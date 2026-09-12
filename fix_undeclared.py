#!/usr/bin/env python3
"""fix_undeclared.py - 错误驱动补全未声明的符号（函数/数据）。

只处理「编译 log 里真正报 undeclared」的名字（不会像全量符号表反查那样
把系统函数也生成出来导致冲突）：

  * 名字在二进制符号表里是 FUNC   -> 追加 `extern undefined8 name();`
  * 名字在二进制符号表里是 OBJECT -> 追加数据定义到 data_defs.c
  * 查不到                        -> 追加 `extern undefined8 name;`（兜底）

用法：
    python fix_undeclared.py <binary> <build_dir> [--log LOG] [--map MAP]
"""

import argparse
import logging
import re
import subprocess
import sys
from pathlib import Path

import decompile_helper as dh

LOG = logging.getLogger("fix_und")

_UND_RE = re.compile(r"error: .([A-Za-z_]\w*). undeclared")
# 明显属于 libc 内部/编译器内建的，跳过（避免和系统头冲突）
_SKIP_PREFIX = ("__", "_IO_", "_nl_")


def collect_undeclared(log_text):
    """从编译 log 提取未声明的标识符（保持出现顺序去重）。"""
    names = []
    seen = set()
    for m in _UND_RE.finditer(log_text):
        n = m.group(1)
        if n in seen:
            continue
        seen.add(n)
        names.append(n)
    return names


def compile_and_get_errors(build_dir):
    """make -k 编译，返回 (错误数, 输出文本)。"""
    import platform
    from orchestrator import to_wsl
    make_cmd = (
        ["wsl", "make", "-C", to_wsl(build_dir), "-k", "-j"]
        if platform.system() == "Windows"
        else ["make", "-C", str(build_dir), "-k", "-j"]
    )
    proc = subprocess.run(make_cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    from orchestrator import parse_errors
    errs = [e for e in parse_errors(output) if e.get("kind") == "error"]
    return len(errs), output


def append_decl(path, decl):
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    if decl in text:
        return False
    path.write_text(text.rstrip("\n") + "\n" + decl + "\n", encoding="utf-8")
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("build_dir")
    ap.add_argument("--log", default=None, help="已有的编译 log（缺省则现编译）")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    build_dir = Path(args.build_dir)
    binary = dh.parse_elf(Path(args.binary)) or dh.parse_pe(Path(args.binary))
    if binary is None:
        sys.exit("Unsupported binary: %s" % args.binary)

    if args.log:
        output = Path(args.log).read_text(encoding="utf-8", errors="replace")
        before = -1
    else:
        before, output = compile_and_get_errors(build_dir)
        LOG.info("编译错误数（修复前）: %d", before)

    names = collect_undeclared(output)
    LOG.info("undeclared 名字: %d 个", len(names))

    func_syms = binary.get("func_syms", set())
    norm_syms = binary.get("norm_syms", {})
    proto_path = build_dir / "function_prototypes.h"
    defs_path = build_dir / "data_defs.c"

    n_func = n_data = n_skip = n_fallback = 0
    for name in names:
        if name.startswith(_SKIP_PREFIX):
            n_skip += 1
            continue
        if name in func_syms:
            if append_decl(proto_path, "extern undefined8 %s();" % name):
                n_func += 1
        elif name in norm_syms:
            size = norm_syms[name][1] or 16
            if append_decl(defs_path, "char %s[0x%x];" % (name, size)):
                n_data += 1
        else:
            if append_decl(proto_path, "extern undefined8 %s;" % name):
                n_fallback += 1

    LOG.info("补声明: 函数 %d, 数据 %d, 兜底 %d, 跳过 %d",
             n_func, n_data, n_fallback, n_skip)


if __name__ == "__main__":
    main()
