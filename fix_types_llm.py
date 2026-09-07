#!/usr/bin/env python3
"""fix_types_llm.py - 用 LLM 从证据推断并修复函数体内部的类型错误。

流程：编译收集「array type / 指针被当整数 / 位运算类型不匹配」等类型错误，
对每个报错函数导出「伪代码 + 汇编 + 调用点」证据，喂 LLM 生成补丁修 .c 文件。

用法：
    python fix_types_llm.py <binary> <decomp_dir> --build-dir <build_dir> [--max N]
"""

import argparse
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("decomp_dir", help="反编译 .c 目录")
    ap.add_argument("--build-dir", required=True, help="build 目录")
    ap.add_argument("--max-functions", type=int, default=0)
    ap.add_argument("--model", default=None)
    ap.add_argument("--slow-model", default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--ghidra-dir", type=Path, default=None)
    ap.add_argument("--no-analyze", action="store_true")
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
    project, program, primary = db.load_binary(args.binary, analyze=not args.no_analyze)

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

    fixed = 0
    failed = 0
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
            c_code, asm, xrefs = export_evidence(program, func, decompiler, listing)
        except Exception as e:
            LOG.warning("%s: 证据导出失败 %s", name, e)
            continue

        patches = llm.infer_type_fixes(name, c_code, asm, xrefs, file_errs)
        if patches is None and slow_llm is not None:
            patches = slow_llm.infer_type_fixes(name, c_code, asm, xrefs, file_errs)
        if not patches:
            failed += 1
            LOG.warning("%s: LLM 无补丁", name)
            continue

        applied, app_errs = apply_patch_list(str(build_dir), patches)
        if applied:
            fixed += 1
            LOG.info("[%d/%d] %s: 应用 %d 个补丁", processed, len(by_file), name, applied)
        else:
            failed += 1
            LOG.warning("%s: 补丁应用失败 %s", name, app_errs)

    LOG.info("类型修复完成：修复 %d，失败/跳过 %d（共处理 %d）",
             fixed, failed, processed)

    decompiler.closeProgram()
    decompiler.dispose()
    primary.close()
    project.close()


if __name__ == "__main__":
    main()
