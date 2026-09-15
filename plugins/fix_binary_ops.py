#!/usr/bin/env python3
"""fix_binary_ops.py - 修复「指针/向量参与位运算」（invalid operands to binary）。

GCC 报 `invalid operands to binary >> (have 'unsigned char *' and 'int')`：
Ghidra 把 SIMD 向量/整数反编译成了指针类型，位运算报错。
把位运算左操作数 cast 成整数：`ptr >> n` -> `(unsigned long)ptr >> n`。

只处理「编译真正报错的行」，避免误伤。

用法：
    python fix_binary_ops.py <build_dir> [--dry-run]
"""

import argparse
import logging
import re
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger("fix_binop")

_ERR_RE = re.compile(
    r"^([A-Za-z0-9_./-]+\.c):(\d+):(\d+): error: invalid operands to binary")
# 行内位运算：标识符 + 运算符（只 cast 简单标识符左操作数）
_OP_RE = re.compile(r"\b([A-Za-z_]\w*)(\s*(?:>>|<<|&|\||\^)\s*)")


def compile_output(build_dir):
    import platform
    from orchestrator import to_wsl
    make_cmd = (
        ["wsl", "make", "-C", to_wsl(build_dir), "-k", "-j"]
        if platform.system() == "Windows"
        else ["make", "-C", str(build_dir), "-k", "-j"]
    )
    proc = subprocess.run(make_cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("build_dir")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    build_dir = Path(args.build_dir)
    out = compile_output(build_dir)

    # 收集 (file, line)
    targets = {}
    for line in out.splitlines():
        m = _ERR_RE.match(line.strip())
        if m:
            targets.setdefault(m.group(1), set()).add(int(m.group(2)))
    total = sum(len(v) for v in targets.values())
    LOG.info("invalid operands 错误行: %d（%d 个文件）", total, len(targets))

    if args.dry_run:
        for f, lines in sorted(targets.items())[:5]:
            LOG.info("  %s: %d 行", f, len(lines))
        return

    # 对每个错误行，给位运算左操作数加 (unsigned long) cast
    changed_files = 0
    changed_lines = 0
    for fname, lines in targets.items():
        p = build_dir / fname
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        rows = text.splitlines()
        for ln in sorted(lines):
            if ln - 1 >= len(rows):
                continue
            src = rows[ln - 1]
            new = _OP_RE.sub(r"(unsigned long)\1\2", src)
            if new != src:
                rows[ln - 1] = new
                changed_lines += 1
        if rows != text.splitlines():
            p.write_text("\n".join(rows) + "\n", encoding="utf-8")
            changed_files += 1
    LOG.info("已改写 %d 行（%d 个文件）", changed_lines, changed_files)


if __name__ == "__main__":
    main()
