#!/usr/bin/env python3
"""fix_signatures_llm.py - 用 LLM 从 Ghidra 证据推断并回灌函数签名。

流程：对每个函数导出「伪代码 + 汇编 + 调用点交叉引用」证据包，喂给 LLM
推断精确 C 签名，再用 ApplyFunctionSignatureCmd 回灌 Ghidra，最后重新反编译。

用法：
    python fix_signatures_llm.py <binary> [-o out_dir] [--max-functions N]
    python fix_signatures_llm.py <binary> --functions bb_strtou bb_strtoull

依赖 LLM_API_KEY（可选 LLM_BASE_URL / LLM_MODEL，默认 DeepSeek）。
"""

import argparse
import logging
import re
import sys
from pathlib import Path

import decompile_binary as db
from llm import LLMProposer
from orchestrator import parse_errors, to_wsl

LOG = logging.getLogger("fix_sig")


def export_evidence(program, func, decompiler, listing, max_asm=40, max_xrefs=5):
    """导出函数证据：返回 (伪代码, 汇编文本, 调用点文本)。"""
    r = decompiler.decompileFunction(func, 60, None)
    c_code = r.getDecompiledFunction().getC() if r and r.decompileCompleted() else ""

    asm_lines = []
    it = listing.getInstructions(func.getEntryPoint(), True)
    n = 0
    while it.hasNext() and n < max_asm:
        ins = it.next()
        if not func.getBody().contains(ins.getAddress()):
            break
        asm_lines.append("%s: %s" % (ins.getAddress(), ins))
        n += 1

    rm = program.getReferenceManager()
    xrefs = []
    for ref in rm.getReferencesTo(func.getEntryPoint()):
        if not ref.getReferenceType().isCall():
            continue
        fr = ref.getFromAddress()
        before = []
        addr = fr
        for _ in range(6):
            prev = listing.getInstructionBefore(addr)
            if prev is None:
                break
            before.append(str(prev))
            addr = prev.getAddress()
        xrefs.append("call at %s; preceding:\n  %s" % (fr, "\n  ".join(reversed(before))))
        if len(xrefs) >= max_xrefs:
            break

    return c_code, "\n".join(asm_lines), "\n".join(xrefs)


_FUZZY_TYPES = {
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
    "undefined5", "undefined6", "undefined7", "undefined8", "byte", "word",
    "dword", "qword", "void",
}


def collect_anchors(program):
    """收集「参数类型精确」的函数（libc 已注入签名等），作为类型传播锚点。"""
    fm = program.getFunctionManager()
    anchors = {}
    for f in fm.getFunctions(True):
        ps = f.getParameters()
        if not ps:
            continue
        types = []
        precise = True
        for p in ps:
            n = p.getDataType().getName()
            if n in _FUZZY_TYPES:
                precise = False
                break
            types.append(n)
        if precise:
            anchors[f.getName()] = types
    return anchors


def export_callee_anchors(program, func, listing, anchors):
    """找 func 内部调用的锚点函数，返回文本「名字: 签名」列表。"""
    fm = program.getFunctionManager()
    body = func.getBody()
    seen = set()
    lines = []
    it = listing.getInstructions(func.getEntryPoint(), True)
    while it.hasNext():
        ins = it.next()
        if not body.contains(ins.getAddress()):
            break
        if not ins.getFlowType().isCall():
            continue
        for ref in ins.getReferencesFrom():
            if not ref.getReferenceType().isCall():
                continue
            callee = fm.getFunctionAt(ref.getToAddress())
            if callee is None:
                continue
            name = callee.getName()
            if name in anchors and name not in seen:
                seen.add(name)
                lines.append("  %s(%s)" % (name, ", ".join(anchors[name])))
    return "\n".join(lines)


# LLM 输出的非标准类型名 → 合法类型名（Ghidra C parser 能解析的）
_TYPE_NAME_MAP = {
    "longlong": "long long",
    "uchar": "unsigned char",
    "schar": "signed char",
    "uint64": "uint64_t",
    "int64": "int64_t",
    "uint32": "uint32_t",
    "int32": "int32_t",
    "uint16": "uint16_t",
    "int16": "int16_t",
    "uint8": "uint8_t",
    "int8": "int8_t",
}


def _normalize_type(s):
    """把类型串里的非标准类型名翻译成合法类型名。"""
    for k, v in _TYPE_NAME_MAP.items():
        s = re.sub(r"\b%s\b" % re.escape(k), v, s)
    return s


def apply_signature(program, func, ret, params):
    """回灌签名；返回 (ok, err_msg)。"""
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.symbol import SourceType

    ret = _normalize_type(ret.replace("const ", ""))
    params_str = ", ".join(_normalize_type(p.replace("const ", "")) for p in params)
    sig_str = "%s %s(%s)" % (ret, func.getName(), params_str)

    parser = FunctionSignatureParser(program.getDataTypeManager(), None)
    try:
        parsed = parser.parse(None, sig_str)
    except Exception as e:
        return False, "parse 失败(%s): %s" % (sig_str, e)
    if parsed is None:
        return False, "parser returned null for: %s" % sig_str

    tx = program.startTransaction("apply inferred signature")
    try:
        cmd = ApplyFunctionSignatureCmd(
            func.getEntryPoint(), parsed, SourceType.USER_DEFINED, False, True
        )
        ok = cmd.applyTo(program)
    except Exception as e:
        ok = False
    finally:
        program.endTransaction(tx, True)
    return bool(ok), None


def collect_functions(program, only_names=None, max_funcs=0):
    funcs = list(program.getFunctionManager().getFunctions(True))
    if only_names:
        funcs = [f for f in funcs if f.getName() in set(only_names)]
    if max_funcs and max_funcs > 0:
        funcs = funcs[:max_funcs]
    return funcs


def _skip_name(name):
    """排除 libc 内部（_ 开头）、GCC 冷路径/变体、匿名函数等噪声。"""
    if name.startswith("_"):
        return True
    if name.startswith("FUN_"):
        return True
    if ".cold" in name or ".isra" in name or ".constprop" in name or ".part" in name:
        return True
    return False


def prescreen_errors(build_dir):
    """用 make -k 编译 build 目录，收集所有 too few/many arguments 报错的函数名。"""
    import platform
    import subprocess

    LOG.info("make -k 编译 build 目录以预筛签名错误...")
    make_cmd = (
        ["wsl", "make", "-C", to_wsl(build_dir), "-k"]
        if platform.system() == "Windows"
        else ["make", "-C", str(build_dir), "-k"]
    )
    proc = subprocess.run(make_cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    names = set()
    for e in parse_errors(output):
        msg = e.get("message", "")
        if "too few arguments" in msg or "too many arguments" in msg:
            m = re.search(r"function\s+[‘’'`\"]?(\w+)", msg)
            if m:
                names.add(m.group(1))
    LOG.info("预筛出 %d 个 too few/many arguments 报错函数", len(names))
    return names


def sort_by_call_reference_count(program, funcs):
    """Sort *funcs* by call-site count (descending).

    A single high-frequency callee with a wrong signature cascades into tens of
    "too few/many arguments" errors at its call sites. Fixing those first
    converges fastest, and also ensures --max-functions spends its budget on the
    highest-impact functions.
    """
    rm = program.getReferenceManager()

    def refcount(f):
        return sum(
            1 for r in rm.getReferencesTo(f.getEntryPoint())
            if r.getReferenceType().isCall()
        )

    return sorted(funcs, key=refcount, reverse=True)


def param_type_names(params):
    """Extract bare type names from LLM-inferred param strings.

    ``["char *arg", "int base"]`` -> ``["char *", "int"]``. Used to feed a
    fixed function back into the anchor set for multi-level type propagation.
    Handles C's ``char *arg`` style (star glued to the arg name).
    """
    out = []
    for p in params:
        p = p.strip()
        m = re.match(r"^(.*?)(\*+)?\s*([A-Za-z_]\w*)$", p)
        if m and m.group(3) and m.group(1).strip():
            typ = m.group(1).strip()
            if m.group(2):
                typ += " " + m.group(2)
            out.append(typ)
        else:
            out.append(p)
    return out


def redecompile_selected(program, funcs, output_dir, decompiler):
    """只重新反编译指定的函数集合，写到 output_dir（一函数一文件）。"""
    count = 0
    for func in funcs:
        r = decompiler.decompileFunction(func, 30, None)
        if r is None or not r.decompileCompleted():
            continue
        c_code = r.getDecompiledFunction().getC()
        safe_name = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in func.getName()
        )
        path = Path(output_dir) / (safe_name + ".c")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("// Function: %s\n" % func.getName())
            f.write("// Address:  %s\n" % func.getEntryPoint())
            f.write("// Type:     %s\n" % func.getSignature())
            f.write("// " + "=" * 60 + "\n")
            f.write(c_code)
        count += 1
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("-o", "--output-dir", default=None,
                    help="重新反编译输出目录")
    ap.add_argument("--functions", nargs="*", default=None,
                    help="只处理这些函数名")
    ap.add_argument("--prescreen", action="store_true",
                    help="编译 build 目录，只对 too few/many arguments 报错的函数调 LLM")
    ap.add_argument("--build-dir", default=None,
                    help="prescreen 用的 build 目录（--prescreen 时必需）")
    ap.add_argument("--max-functions", type=int, default=0,
                    help="最多处理 N 个函数（0=全部）")
    ap.add_argument("--no-sort", action="store_true",
                    help="不按被调次数排序（默认优先修高频被调函数）")
    ap.add_argument("--model", default=None,
                    help="快模型（默认 deepseek-chat）")
    ap.add_argument("--slow-model", default=None,
                    help="慢模型兜底（如 deepseek-v4-pro），对快模型失败的函数重试")
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
        LOG.error("需要 LLM_API_KEY（可选 LLM_BASE_URL / LLM_MODEL）")
        sys.exit(1)

    db.start_ghidra(args.ghidra_dir, verbose=False)
    project, program, primary = db.load_binary(args.binary, analyze=not args.no_analyze)

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    decompiler = DecompInterface()
    decompiler.setOptions(DecompileOptions())
    decompiler.toggleSyntaxTree(False)
    if not decompiler.openProgram(program):
        LOG.error("decompiler openProgram failed")
        sys.exit(1)

    listing = program.getListing()
    anchors = collect_anchors(program)
    # 先收集全部，过滤掉锚点（已精确签名）和 libc 内部/冷路径噪声
    funcs = collect_functions(program, args.functions, 0)
    funcs = [f for f in funcs
             if f.getName() not in anchors and not _skip_name(f.getName())]

    if args.prescreen:
        if not args.build_dir:
            LOG.error("--prescreen 需要 --build-dir")
            sys.exit(1)
        suspicious = prescreen_errors(args.build_dir)
        funcs = [f for f in funcs if f.getName() in suspicious]

    if not args.no_sort:
        funcs = sort_by_call_reference_count(program, funcs)

    if args.max_functions and args.max_functions > 0:
        funcs = funcs[:args.max_functions]
    LOG.info("待处理函数数: %d（锚点数 %d）", len(funcs), len(anchors))

    ok_count = 0
    fail_count = 0
    skip_count = 0
    changed = []
    try:
        for i, func in enumerate(funcs, 1):
            name = func.getName()
            current_sig = str(func.getSignature())
            try:
                c_code, asm, xrefs = export_evidence(program, func, decompiler, listing)
                callee_ctx = export_callee_anchors(program, func, listing, anchors)
            except Exception as e:
                LOG.warning("[%d/%d] %s: 证据导出失败 %s", i, len(funcs), name, e)
                skip_count += 1
                continue

            inferred = llm.infer_signature(name, current_sig, c_code, asm, xrefs,
                                           callee_ctx=callee_ctx or None)
            if inferred is None and slow_llm is not None:
                LOG.info("[%d/%d] %s: 快模型无结果，慢模型重试", i, len(funcs), name)
                inferred = slow_llm.infer_signature(name, current_sig, c_code, asm,
                                                    xrefs, callee_ctx=callee_ctx or None)
            if inferred is None:
                LOG.warning("[%d/%d] %s: LLM 推断失败/无结果", i, len(funcs), name)
                skip_count += 1
                continue

            ret, params = inferred
            ok, err = apply_signature(program, func, ret, params)
            if ok:
                ok_count += 1
                changed.append(func)
                # 锚点回流：修好的函数加入 anchors，后续函数调用它时可做
                # 多层类型传播（第一轮只有 libc 锚点，这里逐层扩充）。
                anchors[func.getName()] = param_type_names(params)
                LOG.info("[%d/%d] %s: %s -> %s %s(%s)",
                         i, len(funcs), name, current_sig, ret, name, ", ".join(params))
            else:
                fail_count += 1
                LOG.warning("[%d/%d] %s: 回灌失败 %s", i, len(funcs), name, err)
    finally:
        pass

    LOG.info("签名回灌完成：成功 %d，失败 %d，跳过 %d", ok_count, fail_count, skip_count)

    if args.output_dir and changed:
        # 用交叉引用找出「被改函数」的所有调用者，只重编受影响函数
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        to_redecompile = set(changed)
        for func in changed:
            for ref in rm.getReferencesTo(func.getEntryPoint()):
                if ref.getReferenceType().isCall():
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller is not None:
                        to_redecompile.add(caller)
        LOG.info("重新反编译 %d 个函数（被改 %d + 调用者）",
                 len(to_redecompile), len(changed))
        count = redecompile_selected(program, to_redecompile, args.output_dir, decompiler)
        LOG.info("已重新反编译 %d 个函数 -> %s", count, args.output_dir)

    decompiler.closeProgram()
    decompiler.dispose()
    primary.close()
    project.close()


if __name__ == "__main__":
    main()
