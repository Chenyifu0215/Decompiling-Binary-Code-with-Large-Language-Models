#!/usr/bin/env python3
"""
Ghidra batch decompilation script (PyGhidra headless mode).

Supports single-file and batch (directory/glob) decompilation with features
including parallel processing, resume, dry-run, config files, and metadata export.

Usage:
    python decompile_binary.py <binary_path> [options]
    python decompile_binary.py <input_dir> [options]
    python decompile_binary.py "*.exe" "*.dll" [options]

Examples:
    python decompile_binary.py malware.exe
    python decompile_binary.py malware.exe -o ./output --lang "x86:LE:64:default"
    python decompile_binary.py ./input_dir -o ./output --parallel 4
    python decompile_binary.py "*.dll" -o ./decomp --meta --recursive
    python decompile_binary.py sample.exe --functions 0x401000 main --no-analyze
    python decompile_binary.py malware.dll --single-file -O all_decomp.c
    python decompile_binary.py ./binaries -o ./out --dry-run --timeout 600
    python decompile_binary.py ./targets -o ./out --config decompile_config.json

Requirements:
    - Ghidra installation (GHIDRA_INSTALL_DIR env var or --ghidra-dir)
    - pyghidra package (installed from Ghidra's PyGhidra feature)
"""

import argparse
import concurrent.futures
import hashlib
import json
import logging
import multiprocessing
import os
import signal
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from queue import Empty
from typing import Dict, List, Optional, Tuple, Union

SCRIPT_VERSION = "2.0.0"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

BINARY_MAGIC_SIGNATURES = {
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"\xca\xfe\xba\xbe": "Mach-O (Fat)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit)",
    b"\xce\xfa\xed\xfe": "Mach-O (32-bit)",
    b"\xfe\xed\xfa\xce": "Mach-O (32-bit LE)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64-bit LE)",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ocx", ".drv", ".cpl", ".scr",
    ".elf", ".so", ".o", ".a", ".out", ".ko",
    ".macho", ".dylib", ".bundle",
    ".bin", ".rom", ".firmware", ".img",
    ".wasm",
}

SKIP_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".py", ".js", ".ts", ".c", ".h", ".cpp", ".hpp", ".rs", ".go",
    ".md", ".rst", ".pdf", ".doc", ".docx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
}


class DecompileStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_files = 0
        self.processed_files = 0
        self.success_files = 0
        self.failed_files = 0
        self.skipped_files = 0
        self.total_functions = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.failures: List[Tuple[str, str]] = []

    def add_skipped(self):
        with self.lock:
            self.skipped_files += 1

    def add_success(self, num_funcs: int, num_bytes: int):
        with self.lock:
            self.processed_files += 1
            self.success_files += 1
            self.total_functions += num_funcs
            self.total_bytes += num_bytes

    def add_failure(self, filename: str, error: str):
        with self.lock:
            self.processed_files += 1
            self.failed_files += 1
            self.failures.append((filename, error))

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> str:
        elapsed = self.elapsed()
        rate = self.processed_files / elapsed if elapsed > 0 else 0
        return (
            f"\n{'=' * 60}\n"
            f"  Total files:     {self.total_files}\n"
            f"  Processed:       {self.processed_files}\n"
            f"  Successful:      {self.success_files}\n"
            f"  Failed:          {self.failed_files}\n"
            f"  Skipped:         {self.skipped_files}\n"
            f"  Total functions: {self.total_functions}\n"
            f"  Total output:    {self._fmt_bytes(self.total_bytes)}\n"
            f"  Elapsed:         {elapsed:.1f}s ({rate:.2f} files/s)\n"
            f"{'=' * 60}\n"
        )

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / (1024 * 1024):.1f} MB"
        return f"{b / (1024 * 1024 * 1024):.1f} GB"


def detect_binary_type(filepath: Path) -> Optional[str]:
    try:
        with open(filepath, "rb") as f:
            magic = f.read(8)
        for sig, name in BINARY_MAGIC_SIGNATURES.items():
            if magic.startswith(sig):
                return name
    except (IOError, PermissionError):
        pass
    return None


def gather_input_files(
    paths: List[str],
    recursive: bool = False,
    follow_symlinks: bool = False,
    skip_non_binary: bool = False,
) -> List[Path]:
    result = []
    seen = set()

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            logging.warning("Path does not exist, skipping: %s", raw)
            continue

        if p.is_file():
            resolved = p.resolve()
            if resolved not in seen:
                seen.add(resolved)
                result.append(resolved)

        elif p.is_dir():
            pattern = "**/*" if recursive else "*"
            for item in sorted(p.glob(pattern)):
                if not item.is_file():
                    continue
                if not follow_symlinks and item.is_symlink():
                    continue
                resolved = item.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                ext = item.suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    logging.debug("Skipping non-code file: %s", item)
                    continue
                if skip_non_binary and ext not in BINARY_EXTENSIONS:
                    continue
                result.append(resolved)

        else:
            resolved = p.resolve()
            if resolved not in seen:
                seen.add(resolved)
                result.append(resolved)

    return sorted(result, key=lambda x: x.name.lower())


def find_ghidra_install() -> Optional[Path]:
    env = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if env and Path(env).is_dir():
        return Path(env)

    candidates = [
        Path(__file__).resolve().parent,
        Path.home() / "ghidra",
        Path("C:/ghidra") if sys.platform == "win32" else None,
        Path("/opt/ghidra"),
        Path("/usr/local/ghidra"),
    ]
    for c in candidates:
        if c and c.is_dir():
            if (c / "support" / "analyzeHeadless.bat").is_file():
                return c
            if (c / "support" / "analyzeHeadless").is_file():
                return c
    return None


def start_ghidra(
    ghidra_dir: Optional[Path] = None,
    verbose: bool = False,
    max_memory: Optional[str] = None,
):
    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    install_dir = ghidra_dir or find_ghidra_install()
    if install_dir is None:
        logging.error(
            "Ghidra installation not found. Set GHIDRA_INSTALL_DIR or use --ghidra-dir."
        )
        sys.exit(1)

    logging.info("Using Ghidra install: %s", install_dir)

    if not pyghidra.started():
        launcher = HeadlessPyGhidraLauncher(
            verbose=verbose,
            install_dir=install_dir,
        )
        launcher.add_vmargs("-Djava.awt.headless=true")
        if max_memory:
            launcher.add_vmargs(f"-Xmx{max_memory}")
        launcher.start()
        return launcher

    if max_memory:
        logging.warning(
            "--max-memory ignored because the JVM is already running."
        )
    return None


def compute_file_hash(filepath: Path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_state_file(state_path: Path) -> Dict[str, dict]:
    if state_path.is_file():
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logging.warning("Corrupt state file, starting fresh: %s", state_path)
    return {}


def save_state_file(state_path: Path, state: Dict[str, dict]):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def already_processed(
    filepath: Path,
    output_dir: Path,
    state: Dict[str, dict],
    overwrite: bool,
    single_file_mode: bool,
) -> bool:
    if overwrite:
        return False

    fhash = compute_file_hash(filepath)

    if fhash in state:
        entry = state[fhash]
        if entry.get("status") == "success":
            logging.info("Skipping (already processed): %s", filepath.name)
            return True

    if single_file_mode:
        return False

    stem = filepath.stem
    expected = output_dir / f"{stem}_decomp"
    if expected.is_dir() and any(expected.glob("*.c")):
        logging.info("Skipping (output exists): %s", filepath.name)
        return True

    return False


def get_output_paths(
    filepath: Path,
    output_dir: Path,
    output_file: Optional[str],
    single_file: bool,
    mirror_structure: bool,
    base_input_dir: Optional[Path],
) -> Tuple[Optional[Path], Optional[Path]]:
    per_file_dir = None
    single_output = None

    if single_file and output_file:
        single_output = Path(output_file)
    elif output_file:
        single_output = Path(output_file)

    if output_dir:
        if mirror_structure and base_input_dir:
            try:
                rel = filepath.resolve().relative_to(base_input_dir.resolve())
                per_file_dir = output_dir / rel.parent / f"{filepath.stem}_decomp"
            except ValueError:
                per_file_dir = output_dir / f"{filepath.stem}_decomp"
        else:
            per_file_dir = output_dir / f"{filepath.stem}_decomp"

    return per_file_dir, single_output


LIBC_TYPE_TARGETS = [
    ("stat.h", "stat"), ("stat.h", "stat64"),
    ("dirent.h", "dirent"), ("dirent.h", "DIR"),
    ("termios.h", "termios"), ("termios.h", "winsize"),
    ("socket.h", "sockaddr"), ("socket.h", "sockaddr_storage"),
    ("socket.h", "msghdr"), ("socket.h", "cmsghdr"),
    ("in.h", "in_addr"), ("in.h", "in6_addr"),
    ("in.h", "sockaddr_in"), ("in.h", "sockaddr_in6"),
    ("un.h", "sockaddr_un"),
    ("fcntl.h", "flock"),
    ("sigaction.h", "sigaction"), ("signal.h", "sighandler_t"),
    ("time.h", "timespec"), ("time.h", "timeval"),
    ("time.h", "timezone"), ("time.h", "itimerval"), ("time.h", "itimerspec"),
    ("utsname.h", "utsname"),
    ("poll.h", "pollfd"),
    ("regex.h", "regex_t"),
    ("resource.h", "rusage"), ("resource.h", "rlimit"),
    ("netdb.h", "hostent"), ("netdb.h", "servent"), ("netdb.h", "protoent"),
    ("netdb.h", "addrinfo"),
    ("ifaddrs.h", "ifaddrs"),
    ("uio.h", "iovec"),
    ("sched.h", "sched_param"),
]


def _import_libc_signatures(program, adtm) -> int:
    """Import libc function signatures from the archive into same-named
    functions in the program (statically-linked libc copies)."""
    try:
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.symbol import SourceType
    except Exception as e:
        logging.debug("signature import unavailable: %s", e)
        return 0

    func_mgr = program.getFunctionManager()
    func_by_name = {}
    for f in func_mgr.getFunctions(True):
        n = f.getName()
        if n not in func_by_name:
            func_by_name[n] = f

    parser = FunctionSignatureParser(program.getDataTypeManager(), None)
    sig_count = 0
    tx = program.startTransaction("import libc signatures")
    try:
        for dt in adtm.getAllDataTypes():
            if dt.getClass().getSimpleName() != "FunctionDefinitionDB":
                continue
            name = dt.getName()
            func = func_by_name.get(name)
            if func is None:
                continue
            proto = dt.getPrototypeString()
            if not proto:
                continue
            try:
                parsed = parser.parse(None, proto)
                if parsed is None:
                    continue
                cmd = ApplyFunctionSignatureCmd(
                    func.getEntryPoint(), parsed,
                    SourceType.USER_DEFINED, False, True,
                )
                if cmd.applyTo(program):
                    sig_count += 1
            except Exception:
                continue
    finally:
        program.endTransaction(tx, True)
    return sig_count


def import_libc_types(program) -> int:
    """Import common POSIX/C-lib struct types from Ghidra's generic_clib_64
    archive so the decompiler emits `struct X` (with real member access)
    instead of opaque byte arrays.

    Returns the number of types imported.
    """
    try:
        from ghidra.program.model.data import (
            FileDataTypeManager, DataTypeConflictHandler,
        )
        from java.io import File as JFile
    except Exception as e:
        logging.debug("libc type import unavailable: %s", e)
        return 0

    install = find_ghidra_install()
    if install is None:
        logging.debug("no Ghidra install; skipping libc type import")
        return 0

    archive = (
        Path(install) / "Ghidra" / "Features" / "Base" / "data"
        / "typeinfo" / "generic" / "generic_clib_64.gdt"
    )
    if not archive.is_file():
        logging.debug("libc type archive not found: %s", archive)
        return 0

    adtm = FileDataTypeManager.openFileArchive(JFile(str(archive)), False)
    pdtm = program.getDataTypeManager()
    imported = 0
    try:
        tx = program.startTransaction("import libc types")
        try:
            for header, name in LIBC_TYPE_TARGETS:
                dt = adtm.getDataType("/%s/%s" % (header, name))
                if dt is None:
                    continue
                pdtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
                imported += 1
        finally:
            program.endTransaction(tx, True)
        sig_count = _import_libc_signatures(program, adtm)
    finally:
        adtm.close()

    logging.info(
        "Imported %d libc type(s), %d libc signature(s) from generic_clib_64.gdt.",
        imported, sig_count,
    )
    return imported


def load_binary(
    binary_path: str,
    project_dir: Optional[str] = None,
    project_name: Optional[str] = None,
    lang_id: Optional[str] = None,
    compiler_id: Optional[str] = None,
    analyze: bool = True,
):
    import pyghidra

    binary = Path(binary_path).resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"Binary not found: {binary}")

    proj_dir = Path(project_dir or binary.parent)
    proj_name = project_name or f"{binary.name}_ghidra_decomp"
    proj_dir.mkdir(parents=True, exist_ok=True)

    logging.info("Opening project: %s", proj_dir / proj_name)

    project = pyghidra.open_project(str(proj_dir), proj_name, create=True)

    loader = pyghidra.program_loader()
    loader.name(binary.name)
    loader.source(str(binary))

    if lang_id:
        loader.language(lang_id)
        if compiler_id:
            loader.compiler(compiler_id)

    logging.info("Importing: %s", binary)

    load_results = loader.load()
    primary = load_results.getPrimary()
    program = primary.getDomainObject()
    if program is None:
        raise RuntimeError(f"Failed to import {binary}")

    logging.info("Program loaded: %s", program.getName())
    logging.info("  Language:   %s", program.getLanguageID().getIdAsString())
    logging.info(
        "  Compiler:   %s",
        program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
    )
    logging.info("  MD5:        %s", program.getExecutableMD5())
    logging.info("  Image base: %s", program.getImageBase())

    if analyze:
        logging.info("Running Ghidra auto-analysis...")
        log = pyghidra.analyze(program)
        if log:
            logging.debug(log)
        logging.info("Analysis complete.")

    import_libc_types(program)

    return project, program, primary


def decompile_function(program, func, decompiler) -> Optional[str]:
    result = decompiler.decompileFunction(func, 30, None)
    if result is None:
        return None
    if not result.decompileCompleted():
        err = result.getErrorMessage()
        return f"/* Decompilation error: {err} */\n"
    return result.getDecompiledFunction().getC()


def decompile_all_functions(
    program,
    output_dir: Optional[str] = None,
    output_file: Optional[str] = None,
    single_file: bool = False,
    function_list: Optional[list] = None,
) -> Tuple[int, int]:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    decompiler = DecompInterface()
    options = DecompileOptions()
    decompiler.setOptions(options)
    decompiler.toggleSyntaxTree(False)

    if not decompiler.openProgram(program):
        err = decompiler.getLastMessage()
        raise RuntimeError(f"Failed to open program in decompiler: {err}")

    try:
        func_mgr = program.getFunctionManager()
        functions = list(func_mgr.getFunctions(True))
        total = len(functions)
        logging.info("Found %d functions in %s", total, program.getName())

        if function_list:
            filtered = []
            for spec in function_list:
                func = None
                try:
                    addr = program.getAddressFactory().getAddress(spec)
                    func = func_mgr.getFunctionAt(addr)
                except Exception:
                    pass
                if func is None:
                    fiter = func_mgr.getFunctions(True)
                    while True:
                        try:
                            f = fiter.next()
                        except StopIteration:
                            break
                        if f.getName() == spec:
                            func = f
                            break
                if func:
                    filtered.append(func)
                else:
                    logging.warning("Function not found: %s", spec)
            functions = filtered

        out_handle = None
        if output_file and single_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            out_handle = open(output_file, "w", encoding="utf-8")

        per_func_dir = None
        if not single_file:
            if output_dir:
                per_func_dir = Path(output_dir)
            elif output_file:
                of = Path(output_file)
                per_func_dir = of if of.is_dir() else of.parent

        count = 0
        total_bytes = 0
        # 统计同名函数（不同模块的 static 同名函数），输出时加地址后缀避免覆盖
        name_counts = {}
        for f in functions:
            name_counts[f.getName()] = name_counts.get(f.getName(), 0) + 1

        for func in functions:
            addr = func.getEntryPoint()
            name = func.getName()
            c_code = decompile_function(program, func, decompiler)

            if c_code is None:
                logging.warning("Failed to decompile: %s @ %s", name, addr)
                continue

            count += 1
            total_bytes += len(c_code)
            logging.debug("[%4d/%d] %s @ %s", count, total, name, addr)

            if per_func_dir is not None:
                safe_name = "".join(
                    c if c.isalnum() or c in "._-" else "_" for c in name
                )
                if name_counts.get(name, 0) > 1:
                    safe_name = "%s_%s" % (safe_name, str(addr))
                func_file = per_func_dir / f"{safe_name}.c"
                func_file.parent.mkdir(parents=True, exist_ok=True)
                with open(func_file, "w", encoding="utf-8") as f:
                    f.write(f"// Function: {name}\n")
                    f.write(f"// Address:  {addr}\n")
                    f.write(f"// Type:     {func.getSignature()}\n")
                    f.write("// " + "=" * 60 + "\n")
                    f.write(c_code)

            if out_handle:
                out_handle.write(f"// ===== {name} @ {addr} =====\n")
                out_handle.write(f"// {func.getSignature()}\n\n")
                out_handle.write(c_code)
                out_handle.write("\n\n")

        if out_handle:
            out_handle.close()

        logging.info(
            "Successfully decompiled %d/%d functions.", count, len(functions)
        )
        return count, total_bytes

    finally:
        decompiler.closeProgram()
        decompiler.dispose()


def export_program_metadata(program, output_file: str):
    meta = {
        "name": program.getName(),
        "language": program.getLanguageID().getIdAsString(),
        "compiler": program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
        "image_base": str(program.getImageBase()),
        "md5": program.getExecutableMD5(),
        "sha256": program.getExecutableSHA256(),
        "min_address": str(program.getMinAddress()),
        "max_address": str(program.getMaxAddress()),
        "memory_blocks": [],
        "sections": [],
        "imports": [],
        "exports": [],
        "functions": [],
    }

    for block in program.getMemory().getBlocks():
        meta["memory_blocks"].append(
            {
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute(),
            }
        )

    sym_table = program.getSymbolTable()
    for sym in sym_table.getExternalSymbols():
        namespace = sym.getParentNamespace()
        meta["imports"].append(
            {
                "name": sym.getName(),
                "address": str(sym.getAddress()) if sym.getAddress() else None,
                "library": namespace.getName() if namespace else None,
            }
        )

    for sym in sym_table.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            meta["exports"].append(
                {"name": sym.getName(), "address": str(sym.getAddress())}
            )

    func_mgr = program.getFunctionManager()
    for func in func_mgr.getFunctions(True):
        meta["functions"].append(
            {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "body_size": func.getBody().getNumAddresses(),
            }
        )

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    logging.info("Metadata exported to: %s", output_file)


def decompile_single_file(
    filepath: Path,
    ghidra_dir: Optional[Path],
    args,
    stats: DecompileStats,
    state: Dict[str, dict],
    base_input_dir: Optional[Path],
) -> bool:
    filename = filepath.name
    logging.info("=" * 60)
    logging.info("Processing: %s", filename)
    logging.info("  Type: %s", detect_binary_type(filepath) or "unknown")

    per_file_dir, single_output = get_output_paths(
        filepath,
        args.output_dir,
        args.output_file,
        args.single_file,
        args.mirror,
        base_input_dir,
    )

    try:
        project, program, primary_loaded = load_binary(
            str(filepath),
            project_dir=args.project_dir,
            project_name=args.project_name,
            lang_id=args.lang,
            compiler_id=args.compiler,
            analyze=not args.no_analyze,
        )
    except Exception as e:
        logging.error("Failed to load binary %s: %s", filename, e)
        stats.add_failure(filename, str(e))
        return False

    try:
        if args.list_functions:
            lines = []
            for func in program.getFunctionManager().getFunctions(True):
                lines.append(
                    f"  {func.getEntryPoint()}  {func.getName()}()  -> {func.getSignature()}"
                )
            output = "\n".join(
                [f"Function List for {filename}:", "-" * 60] + lines
            )
            if args.output_dir:
                list_file = Path(args.output_dir) / f"{filepath.stem}_functions.txt"
                list_file.parent.mkdir(parents=True, exist_ok=True)
                list_file.write_text(output, encoding="utf-8")
            else:
                print(output)
            stats.add_success(0, 0)
            return True

        if args.meta:
            meta_output = per_file_dir.parent / f"{filepath.stem}_meta.json" if per_file_dir else Path(f"{filepath.stem}_meta.json")
            export_program_metadata(program, str(meta_output))

        output_dir_str = str(per_file_dir) if per_file_dir else None
        output_file_str = str(single_output) if single_output else None

        num_funcs, num_bytes = decompile_all_functions(
            program,
            output_dir=output_dir_str,
            output_file=output_file_str,
            single_file=args.single_file,
            function_list=args.functions,
        )
        stats.add_success(num_funcs, num_bytes)

        if state is not None:
            fhash = compute_file_hash(filepath)
            state[fhash] = {
                "file": str(filepath),
                "status": "success",
                "functions": num_funcs,
                "bytes": num_bytes,
                "timestamp": datetime.now().isoformat(),
            }

        return True

    except Exception as e:
        logging.error("Error decompiling %s: %s", filename, e)
        logging.debug(traceback.format_exc())
        stats.add_failure(filename, str(e))
        return False

    finally:
        try:
            primary_loaded.close() if primary_loaded is not None else None
            project.close() if project is not None else None
        except Exception:
            pass


def _worker_init():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _worker_entry(
    filepath: Path,
    ghidra_dir: Optional[Path],
    args_dict: dict,
    base_input_dir: Optional[Path],
    result_queue,
):
    try:
        result = _worker_decompile(
            filepath,
            ghidra_dir,
            args_dict,
            base_input_dir,
        )
        result_queue.put(result)
    except Exception as e:
        result_queue.put((filepath.name, False, str(e), 0, 0))


def _worker_decompile(
    filepath: Path,
    ghidra_dir: Optional[Path],
    args_dict: dict,
    base_input_dir: Optional[Path],
) -> Tuple[str, bool, Optional[str], int, int]:
    import pyghidra

    class Args:
        pass

    a = Args()
    for k, v in args_dict.items():
        setattr(a, k, v)

    if not pyghidra.started():
        start_ghidra(
            ghidra_dir,
            verbose=a.verbose,
            max_memory=a.max_memory,
        )

    filename = filepath.name

    try:
        per_file_dir, single_output = get_output_paths(
            filepath,
            a.output_dir,
            a.output_file,
            a.single_file,
            a.mirror,
            base_input_dir,
        )

        project, program, primary_loaded = load_binary(
            str(filepath),
            project_dir=a.project_dir,
            project_name=a.project_name,
            lang_id=a.lang,
            compiler_id=a.compiler,
            analyze=not a.no_analyze,
        )

        try:
            if a.list_functions:
                output = "\n".join(
                    f"{func.getEntryPoint()}  {func.getName()}()"
                    for func in program.getFunctionManager().getFunctions(True)
                )
                if a.output_dir:
                    list_file = Path(a.output_dir) / f"{filepath.stem}_functions.txt"
                    list_file.parent.mkdir(parents=True, exist_ok=True)
                    list_file.write_text(output, encoding="utf-8")
                return (filename, True, None, 0, 0)

            if a.meta:
                meta_output = per_file_dir.parent / f"{filepath.stem}_meta.json" if per_file_dir else Path(f"{filepath.stem}_meta.json")
                export_program_metadata(program, str(meta_output))

            output_dir_str = str(per_file_dir) if per_file_dir else None
            output_file_str = str(single_output) if single_output else None

            num_funcs, num_bytes = decompile_all_functions(
                program,
                output_dir=output_dir_str,
                output_file=output_file_str,
                single_file=a.single_file,
                function_list=a.functions,
            )
            return (filename, True, None, num_funcs, num_bytes)

        finally:
            try:
                primary_loaded.close() if primary_loaded is not None else None
                project.close() if project is not None else None
            except Exception:
                pass

    except Exception as e:
        return (filename, False, str(e), 0, 0)


def _run_worker_once(
    filepath: Path,
    ghidra_dir: Optional[Path],
    args,
    base_input_dir: Optional[Path],
    timeout: Optional[int],
) -> Tuple[str, bool, Optional[str], int, int]:
    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue()
    args_dict = {
        k: v
        for k, v in vars(args).items()
        if k in (
            "output_dir",
            "output_file",
            "single_file",
            "mirror",
            "project_dir",
            "project_name",
            "lang",
            "compiler",
            "no_analyze",
            "list_functions",
            "meta",
            "functions",
            "verbose",
            "max_memory",
        )
    }

    process = ctx.Process(
        target=_worker_entry,
        args=(filepath, ghidra_dir, args_dict, base_input_dir, result_queue),
    )
    process.start()

    if timeout and timeout > 0:
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join()
            return (
                filepath.name,
                False,
                f"Timed out after {timeout} seconds",
                0,
                0,
            )
    else:
        process.join()

    try:
        return result_queue.get_nowait()
    except Empty:
        return (
            filepath.name,
            False,
            f"Worker exited with code {process.exitcode}",
            0,
            0,
        )


def _record_worker_result(
    stats: DecompileStats,
    state: Dict[str, dict],
    filepath: Path,
    result: Tuple[str, bool, Optional[str], int, int],
):
    fname, ok, err, num_funcs, num_bytes = result
    if ok:
        stats.add_success(num_funcs, num_bytes)
        if state is not None:
            file_hash = compute_file_hash(filepath)
            state[file_hash] = {
                "file": str(filepath),
                "status": "success",
                "functions": num_funcs,
                "bytes": num_bytes,
                "timestamp": datetime.now().isoformat(),
            }
    else:
        stats.add_failure(fname, err or "unknown error")


def run_parallel(
    files: List[Path],
    ghidra_dir: Optional[Path],
    args,
    stats: DecompileStats,
    state: Dict[str, dict],
    base_input_dir: Optional[Path],
):
    stats.total_files = len(files)

    files_to_process = []
    for fp in files:
        if not args.overwrite and args.output_dir:
            if already_processed(
                fp,
                args.output_dir,
                state,
                args.overwrite,
                args.single_file,
            ):
                stats.add_skipped()
                continue
        files_to_process.append(fp)

    if not files_to_process:
        return

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.parallel,
    ) as executor:
        future_map = {
            executor.submit(
                _run_worker_once,
                fp,
                ghidra_dir,
                args,
                base_input_dir,
                args.timeout,
            ): fp
            for fp in files_to_process
        }

        try:
            for future in concurrent.futures.as_completed(future_map):
                fp = future_map[future]
                try:
                    result = future.result()
                    _record_worker_result(stats, state, fp, result)
                    fname, ok, err, nf, _ = result
                    if ok:
                        logging.info(
                            "[%d/%d] OK: %s (%d funcs)",
                            stats.processed_files,
                            stats.total_files,
                            fname,
                            nf,
                        )
                    else:
                        logging.error(
                            "[%d/%d] FAIL: %s - %s",
                            stats.processed_files,
                            stats.total_files,
                            fname,
                            err,
                        )
                except Exception as e:
                    stats.add_failure(fp.name, str(e))
                    logging.error("Exception in worker for %s: %s", fp.name, e)
        except KeyboardInterrupt:
            logging.warning("Interrupted. Shutting down workers...")
            for future in future_map:
                future.cancel()
            raise


def run_sequential(
    files: List[Path],
    ghidra_dir: Optional[Path],
    args,
    stats: DecompileStats,
    state: Dict[str, dict],
    base_input_dir: Optional[Path],
):
    stats.total_files = len(files)

    for idx, fp in enumerate(files, 1):
        if args.overwrite:
            logging.info("[%d/%d] Processing: %s", idx, len(files), fp.name)

        if not args.overwrite and args.output_dir:
            if already_processed(
                fp, args.output_dir, state, args.overwrite, args.single_file
            ):
                stats.add_skipped()
                continue

        if args.timeout and args.timeout > 0:
            result = _run_worker_once(
                fp,
                ghidra_dir,
                args,
                base_input_dir,
                args.timeout,
            )
            _record_worker_result(stats, state, fp, result)
        else:
            try:
                decompile_single_file(
                    fp,
                    ghidra_dir,
                    args,
                    stats,
                    state,
                    base_input_dir,
                )
            except KeyboardInterrupt:
                logging.warning(
                    "Interrupted at file %d/%d: %s",
                    idx,
                    len(files),
                    fp.name,
                )
                raise

        memory_cleanup()

    if args.resume and state is not None:
        save_state_file(Path(args.resume), state)


def memory_cleanup():
    import gc
    gc.collect()


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.endswith(".json"):
            return json.load(f)
        elif config_path.endswith((".yaml", ".yml")):
            try:
                import yaml
                return yaml.safe_load(f)
            except ImportError:
                logging.error(
                    "PyYAML required for YAML config files. Install with: pip install pyyaml"
                )
                sys.exit(1)
        else:
            logging.error("Unsupported config format: %s", config_path)
            sys.exit(1)


def apply_config(args: argparse.Namespace, config: dict) -> argparse.Namespace:
    mapping = {
        "output_dir": "output_dir",
        "output_file": "output_file",
        "project_dir": "project_dir",
        "project_name": "project_name",
        "lang": "lang",
        "compiler": "compiler",
        "ghidra_dir": "ghidra_dir",
        "parallel": "parallel",
        "timeout": "timeout",
        "max_memory": "max_memory",
        "resume": "resume",
        "log_file": "log_file",
    }
    bool_mapping = {
        "single_file": "single_file",
        "no_analyze": "no_analyze",
        "overwrite": "overwrite",
        "recursive": "recursive",
        "mirror": "mirror",
        "meta": "meta",
        "list_functions": "list_functions",
        "dry_run": "dry_run",
        "verbose": "verbose",
        "follow_symlinks": "follow_symlinks",
        "skip_non_binary": "skip_non_binary",
    }

    for cfg_key, arg_key in mapping.items():
        if cfg_key in config:
            setattr(args, arg_key, config[cfg_key])
    for cfg_key, arg_key in bool_mapping.items():
        if cfg_key in config:
            setattr(args, arg_key, bool(config[cfg_key]))
    if "functions" in config:
        setattr(args, "functions", config["functions"])

    return args


def main():
    parser = argparse.ArgumentParser(
        description=f"Ghidra batch decompilation script v{SCRIPT_VERSION} (PyGhidra headless mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python decompile_binary.py sample.exe
  python decompile_binary.py sample.exe -o ./decomp --lang "x86:LE:64:default"
  python decompile_binary.py ./input_dir -o ./output --parallel 4 --recursive
  python decompile_binary.py "*.dll" -o ./decomp --meta --mirror
  python decompile_binary.py malware.dll --single-file -O all_decomp.c
  python decompile_binary.py ./bins -o ./out --dry-run
  python decompile_binary.py ./targets -o ./out --config cfg.json --resume state.json
  python decompile_binary.py binary.exe --functions 0x401000 main --no-analyze
  python decompile_binary.py binary.exe --list-functions
        """,
    )

    io_group = parser.add_argument_group("Input/Output")
    io_group.add_argument(
        "inputs", nargs="+", help="Binary file(s), directory, or glob pattern(s)"
    )
    io_group.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write decompiled output",
    )
    io_group.add_argument(
        "-O",
        "--output-file",
        type=Path,
        default=None,
        help="Single output file path",
    )
    io_group.add_argument(
        "--single-file",
        action="store_true",
        help="Write all functions into a single file (requires -O)",
    )
    io_group.add_argument(
        "--mirror",
        action="store_true",
        help="Mirror input directory structure in output",
    )

    proc_group = parser.add_argument_group("Processing")
    proc_group.add_argument(
        "--parallel",
        type=int,
        default=0,
        help="Number of parallel workers (0 = sequential, -1 = CPU count)",
    )
    proc_group.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Per-file timeout in seconds (0 = no limit)",
    )
    proc_group.add_argument(
        "--no-analyze",
        action="store_true",
        help="Skip Ghidra auto-analysis",
    )
    proc_group.add_argument(
        "--lang",
        help="Ghidra Language ID (e.g. x86:LE:64:default)",
    )
    proc_group.add_argument(
        "--compiler",
        help="Ghidra CompilerSpec ID (e.g. gcc, windows)",
    )
    proc_group.add_argument(
        "-f",
        "--functions",
        nargs="*",
        help="Specific functions to decompile (by address e.g. 0x401000 or name)",
    )
    proc_group.add_argument(
        "--max-memory",
        default=None,
        help="Max JVM heap size (e.g. 4G, 8192M)",
    )
    proc_group.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan input directories",
    )
    proc_group.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links when scanning directories",
    )
    proc_group.add_argument(
        "--skip-non-binary",
        action="store_true",
        help="Only process files with known binary extensions",
    )

    mgmt_group = parser.add_argument_group("Management")
    mgmt_group.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing output files",
    )
    mgmt_group.add_argument(
        "--resume",
        type=Path,
        default=None,
        help="State file for resuming interrupted runs",
    )
    mgmt_group.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be processed without decompiling",
    )
    mgmt_group.add_argument(
        "--config",
        type=Path,
        default=None,
        help="JSON or YAML config file with default options",
    )
    mgmt_group.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Write log output to a file",
    )

    meta_group = parser.add_argument_group("Metadata / Info")
    meta_group.add_argument(
        "--meta",
        action="store_true",
        help="Export program metadata to JSON",
    )
    meta_group.add_argument(
        "--list-functions",
        action="store_true",
        help="Only list function names and addresses",
    )

    ghidra_group = parser.add_argument_group("Ghidra")
    ghidra_group.add_argument(
        "--ghidra-dir",
        type=Path,
        default=None,
        help="Path to Ghidra installation directory",
    )
    ghidra_group.add_argument(
        "--project-dir",
        help="Directory for Ghidra projects (default: temp or binary directory)",
    )
    ghidra_group.add_argument(
        "--project-name",
        help="Name for Ghidra project (default: derived from binary name)",
    )

    debug_group = parser.add_argument_group("Debug")
    debug_group.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    debug_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output"
    )
    debug_group.add_argument(
        "--version", action="version", version=f"%(prog)s v{SCRIPT_VERSION}"
    )

    args = parser.parse_args()

    if args.config:
        config = load_config(str(args.config))
        args = apply_config(args, config)

    if args.single_file and not args.output_file:
        parser.error("--single-file requires -O/--output-file")

    if (
        args.output_dir is None
        and args.output_file is None
        and not args.list_functions
    ):
        args.output_dir = Path("decompiled_output")
        logging.info(
            "No output path specified; using default output directory: %s",
            args.output_dir,
        )

    if args.parallel == -1:
        args.parallel = os.cpu_count() or 4

    log_level = logging.WARNING
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(args.log_file), encoding="utf-8"))

    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
    )

    ghidra_dir = Path(args.ghidra_dir) if args.ghidra_dir else None

    input_files = gather_input_files(
        args.inputs,
        recursive=args.recursive,
        follow_symlinks=args.follow_symlinks,
        skip_non_binary=args.skip_non_binary,
    )

    if not input_files:
        logging.error("No input files found.")
        sys.exit(1)

    logging.info("Found %d file(s) to process.", len(input_files))

    if args.dry_run:
        print("\nDry run - would process the following files:\n")
        for i, fp in enumerate(input_files, 1):
            ftype = detect_binary_type(fp) or "unknown"
            fsize = fp.stat().st_size
            print(f"  [{i:4d}] {fp}  ({ftype}, {fsize:,} bytes)")
        print(f"\nTotal: {len(input_files)} file(s)\n")
        return

    stats = DecompileStats()
    state: Dict[str, dict] = {}
    if args.resume:
        state = load_state_file(Path(args.resume))

    base_input_dir: Optional[Path] = None
    if args.mirror:
        common = Path(args.inputs[0]).resolve()
        if common.is_file():
            base_input_dir = common.parent
        elif common.is_dir():
            base_input_dir = common
        else:
            base_input_dir = common.parent

    try:
        use_parallel = args.parallel > 0 and len(input_files) > 1
        use_timeout_worker = bool(args.timeout and args.timeout > 0)

        if use_parallel or use_timeout_worker:
            if use_parallel:
                logging.info(
                    "Starting parallel processing with %d workers.",
                    args.parallel,
                )
                run_parallel(
                    input_files,
                    ghidra_dir,
                    args,
                    stats,
                    state,
                    base_input_dir,
                )
            else:
                run_sequential(
                    input_files,
                    ghidra_dir,
                    args,
                    stats,
                    state,
                    base_input_dir,
                )
        else:
            start_ghidra(
                ghidra_dir,
                verbose=args.verbose,
                max_memory=args.max_memory,
            )
            logging.info(
                "Starting sequential processing."
            )
            run_sequential(
                input_files, ghidra_dir, args, stats, state, base_input_dir
            )
    except KeyboardInterrupt:
        logging.warning("Interrupted by user.")
        if args.resume:
            save_state_file(Path(args.resume), state)
            logging.info("Progress saved to: %s", args.resume)
        sys.exit(130)

    sys.stderr.write(stats.summary())

    if args.resume:
        save_state_file(Path(args.resume), state)
        logging.info("State saved to: %s", args.resume)

    if stats.failures:
        sys.stderr.write("\nFailures:\n")
        for fname, err in stats.failures:
            sys.stderr.write(f"  {fname}: {err}\n")

    if stats.failed_files > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
