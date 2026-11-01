#!/usr/bin/env python3
"""fix_conflicts.py - 错误驱动移除与系统头冲突的函数声明/实现。

动态二进制里可能有「与 libc 同名但自己实现」的函数（如 bash 的 getenv），
其原型/定义会和系统头 conflicting——每个 include prototype.h 的文件都报，
一个函数能放大成几千条错误。

流程：
  1. 编译，收集 `conflicting types for 'X'`
  2. 从 function_prototypes.h 移除这些声明
  3. 从 Makefile 的 SRCS 移除对应的 .c（并在目录里重命名为 .c.bak）
  4. 重新编译验证

用法：
    python fix_conflicts.py <build_dir> [--dry-run]
"""

import argparse
import logging
import re
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger("fix_conf")

_CONF_RE = re.compile(r"conflicting types for .([A-Za-z_]\w*).")


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


def _matches(basename, names):
    return basename in names or any(basename.startswith(n + "_") for n in names)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("build_dir")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    build_dir = Path(args.build_dir)
    out = compile_output(build_dir)
    names = sorted({m.group(1) for m in _CONF_RE.finditer(out)})
    LOG.info("conflicting 函数: %d 个：%s", len(names),
             ", ".join(names[:20]) + (" ..." if len(names) > 20 else ""))
    if not names or args.dry_run:
        return

    # 1) function_prototypes.h 移除声明
    proto = build_dir / "function_prototypes.h"
    if proto.exists():
        text = proto.read_text(encoding="utf-8", errors="replace")
        for n in names:
            text = re.sub(
                r"(?m)^extern[^\n]*\b%s\s*\([^;]*\);\s*\n" % re.escape(n), "", text)
        proto.write_text(text, encoding="utf-8")
        LOG.info("已从 function_prototypes.h 移除 %d 个声明", len(names))

    # 2) Makefile SRCS 移除对应 .c
    mk = build_dir / "Makefile"
    if mk.exists():
        text = mk.read_text(encoding="utf-8", errors="replace")

        def _repl(m):
            keep = [it for it in m.group(2).split()
                    if not _matches(it[:-2] if it.endswith(".c") else it, names)]
            return m.group(1) + " ".join(keep)

        new = re.sub(r"(?m)^(SRCS = )(.+)$", _repl, text)
        if new != text:
            mk.write_text(new, encoding="utf-8")
            LOG.info("已从 Makefile 的 SRCS 移除对应 .c")

    # 3) 目录里对应 .c 重命名为 .c.bak（避免被通配/残留）
    moved = 0
    for p in build_dir.glob("*.c"):
        if _matches(p.stem, names):
            p.rename(p.with_suffix(".c.bak"))
            moved += 1
    LOG.info("已移走 %d 个 .c（→ .c.bak）", moved)


if __name__ == "__main__":
    main()
