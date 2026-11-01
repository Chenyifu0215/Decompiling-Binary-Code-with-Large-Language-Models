#!/usr/bin/env python3
"""fix_types_llm.py - 用 LLM 从证据推断并修复函数体内部的类型错误。

流程：编译收集「array type / 指针被当整数 / 位运算类型不匹配」等类型错误，
对每个报错函数导出「伪代码 + 汇编 + 调用点」证据，喂 LLM 生成补丁修 .c 文件。

用法：
    python fix_types_llm.py <binary> <decomp_dir> --build-dir <build_dir> [--max N]
"""

import argparse
import concurrent.futures
import logging
import platform
import subprocess
import sys
from pathlib import Path

import decompile_binary as db
from llm import LLMProposer
from orchestrator import parse_errors, to_wsl
from patch import apply_patch_list
from fix_signatures_llm import export_evidence

LOG = logging.getLogger("fix_types")

TYPE_ERROR_PATTERNS = (
    "assignment to expression with array type",
    "invalid type argument of unary",
    "invalid operands to binary",
    "request for member",
    "invalid use of void expression",
    "called object",        # 变量被当函数调用（声明类型错）
    "subscripted value",    # 标量被下标（声明应为数组/指针）
)


def prescreen_type_errors(build_dir):
    """编译 build，收集类型错误（file/line/message）。"""
    make_cmd = (
        ["wsl", "make", "-C", to_wsl(build_dir), "-k"]
        if platform.system() == "Windows"
        else ["make", "-C", str(build_dir), "-k"]
    )
    proc = subprocess.run(make_cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    errs = []
    for e in parse_errors(output):
        if any(p in e.get("message", "") for p in TYPE_ERROR_PATTERNS):
            errs.append(e)
    return errs


def parse_func_header(c_path):
    """从 decomp 目录的 .c 文件解析函数名 + 地址。"""
    name = addr = None
    try:
        for line in c_path.read_text(encoding="utf-8", errors="replace").splitlines()[:6]:
            if line.startswith("// Function:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("// Address:"):
                addr = line.split(":", 1)[1].strip()
    except OSError:
        pass
    return name, addr


def _compile_error_count(build_dir):
    """make -k 编译，返回错误总数（用于验证回退）。"""
    import platform
    from orchestrator import parse_errors, to_wsl
    make_cmd = (
        ["wsl", "make", "-C", to_wsl(build_dir), "-k", "-j"]
        if platform.system() == "Windows"
        else ["make", "-C", str(build_dir), "-k", "-j"]
    )
    proc = subprocess.run(make_cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return sum(1 for e in parse_errors(output) if e.get("kind") == "error")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("decomp_dir", help="反编译 .c 目录")
    ap.add_argument("--build-dir", required=True, help="build 目录")
    ap.add_argument("--max-functions", type=int, default=0)
    ap.add_argument("--llm-workers", type=int, default=4,
                    help="Concurrent LLM requests while keeping Ghidra access serial")
    ap.add_argument("--verify", action="store_true",
                    help="修复后编译验证，错误总数增加则整体回退")
    ap.add_argument("--model", default=None)
    ap.add_argument("--slow-model", default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--ghidra-dir", type=Path, default=None)
    ap.add_argument("--project-dir", default=None,
                    help="Ghidra project directory (default: binary directory)")
    ap.add_argument("--project-name", default=None,
                    help="Ghidra project name (default: <binary>_ghidra_decomp)")
    ap.add_argument("--no-analyze", action="store_true")
    ap.add_argument("--no-reuse", action="store_true",
                    help="Force re-import and re-analysis instead of reusing the project")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    llm = LLMProposer(base_url=args.base_url, api_key=args.api_key, model=args.model)
    slow_llm = None
    if args.slow_model:
        slow_llm = LLMProposer(base_url=args.base_url, api_key=args.api_key,
                               model=args.slow_model)
    if not llm._available():
        LOG.error("需要 LLM_API_KEY")
        sys.exit(1)

    db.start_ghidra(args.ghidra_dir, verbose=False)
    project, program, primary = db.load_binary(
        args.binary,
        project_dir=args.project_dir,
        project_name=args.project_name,
        analyze=not args.no_analyze,
        reuse=not args.no_reuse,
    )

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    decompiler = DecompInterface()
    decompiler.setOptions(DecompileOptions())
    decompiler.toggleSyntaxTree(False)
    decompiler.openProgram(program)

    listing = program.getListing()
    fm = program.getFunctionManager()

    errs = prescreen_type_errors(args.build_dir)
    LOG.info("类型错误总数: %d", len(errs))

    # 按 file 分组，每个 file 只处理一次
    by_file = {}
    for e in errs:
        by_file.setdefault(e.get("file"), []).append(e)

    decomp_dir = Path(args.decomp_dir)
    build_dir = Path(args.build_dir)

    baseline = _compile_error_count(build_dir) if args.verify else None
    if baseline is not None:
        LOG.info("修复前错误数: %d", baseline)
    backup = {}

    def infer_patches(task):
        fname, name, c_code, asm, xrefs, file_errs = task
        patches = llm.infer_type_fixes(name, c_code, asm, xrefs, file_errs)
        if patches is None and slow_llm is not None:
            patches = slow_llm.infer_type_fixes(name, c_code, asm, xrefs, file_errs)
        return patches

    # 第一阶段：串行访问 Ghidra，准备每个文件的证据包。
    tasks = []
    processed = 0
    for fname, file_errs in sorted(by_file.items()):
        if args.max_functions and processed >= args.max_functions:
            break
        processed += 1

        # 从 decomp 目录找同名 .c，解析函数名 + 地址
        c_path = decomp_dir / fname
        name, addr = parse_func_header(c_path)
        if not name:
            LOG.warning("无法解析函数名: %s", fname)
            continue

        # 从 Ghidra 找函数
        func = None
        if addr:
            try:
                a = program.getAddressFactory().getAddress(addr)
                func = fm.getFunctionAt(a)
            except Exception:
                func = None
        if func is None:
            func = next((f for f in fm.getFunctions(True) if f.getName() == name), None)
        if func is None:
            LOG.warning("未找到函数: %s", name)
            continue

        try:
            # 汇编/调用点从 Ghidra 导出，仅作语义辅助证据。
            _, asm, xrefs = export_evidence(program, func, decompiler, listing)
        except Exception as e:
            LOG.warning("%s: 证据导出失败 %s", name, e)
            continue

        # 伪代码必须用 build 目录里「已处理」的 .c（decompile_helper 已改写过
        # slice/struct/全局名），否则 LLM 基于 Ghidra 原始反编译生成的补丁 old
        # 文本与补丁应用目标不一致，导致大量 "replace target not found"。
        build_c_path = build_dir / fname
        if build_c_path.exists():
            c_code = build_c_path.read_text(encoding="utf-8", errors="replace")
        else:
            c_code = export_evidence(program, func, decompiler, listing)[0]

        tasks.append((fname, name, c_code, asm, xrefs, file_errs))

    # 第二阶段：LLM 请求并发执行；Ghidra 和文件补丁仍在主线程串行。
    results = []
    workers = max(1, args.llm_workers)
    if workers == 1:
        for task in tasks:
            try:
                results.append((task, infer_patches(task)))
            except Exception as e:
                LOG.warning("%s: LLM 调用失败 %s", task[1], e)
                results.append((task, None))
    else:
        LOG.info("LLM 并发请求数: %d", workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(infer_patches, task): task for task in tasks
            }
            for future in concurrent.futures.as_completed(future_map):
                task = future_map[future]
                try:
                    results.append((task, future.result()))
                except Exception as e:
                    LOG.warning("%s: LLM 调用失败 %s", task[1], e)
                    results.append((task, None))

    # 第三阶段：串行应用补丁。
    fixed = 0
    failed = 0
    for idx, (task, patches) in enumerate(results, 1):
        fname, name, c_code, asm, xrefs, file_errs = task
        if not patches:
            failed += 1
            LOG.warning("%s: LLM 无补丁", name)
            continue

        # 强制补丁落到「报错的那个文件」，避免 LLM 用函数名生成不带地址后缀
        # 的 file（同名函数）导致补丁找错文件。
        for p in patches:
            if isinstance(p, dict):
                p["file"] = fname
        if args.verify:
            for p in patches:
                fp = build_dir / (p.get("file") or fname)
                if str(fp) not in backup and fp.exists():
                    backup[str(fp)] = fp.read_text(encoding="utf-8", errors="replace")
        applied, app_errs = apply_patch_list(str(build_dir), patches)
        if applied:
            fixed += 1
            LOG.info("[%d/%d] %s: 应用 %d 个补丁", idx, len(results), name, applied)
        else:
            failed += 1
            LOG.warning("%s: 补丁应用失败 %s", name, app_errs)

    LOG.info("类型修复完成：修复 %d，失败/跳过 %d（共处理 %d）",
             fixed, failed, processed)

    if args.verify and baseline is not None and backup:
        after = _compile_error_count(build_dir)
        if after > baseline:
            for fp_str, content in backup.items():
                Path(fp_str).write_text(content, encoding="utf-8")
            LOG.error("验证不通过：错误 %d -> %d，已回退 %d 个文件",
                      baseline, after, len(backup))
        else:
            LOG.info("验证通过：错误 %d -> %d", baseline, after)

    decompiler.closeProgram()
    decompiler.dispose()
    primary.close()
    project.close()


if __name__ == "__main__":
    main()
