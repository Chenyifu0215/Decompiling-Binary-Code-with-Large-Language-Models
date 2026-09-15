#!/usr/bin/env python3
"""fix_argcount.py - 从调用点推断正确参数数，修正函数声明/定义。

GCC 报 too few/many arguments 说明「被调函数声明的参数数」与「调用点实际
参数数」不一致。若某函数的多数调用点都传 N 个参数，则声明应为 N。

流程：
  1. make -k 收集 too few/many 报错的被调函数名。
  2. 扫描 build 的 .c，统计这些函数在所有调用点的参数数（取众数 N）。
  3. 把 function_prototypes.h 和 .c 里的函数定义改成 N 个 undefined8 参数。

用法：
    python fix_argcount.py <build_dir> [--min-votes N]
"""

import argparse
import collections
import logging
import re
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger("fix_argc")

_ARG_ERR_RE = re.compile(
    r"too (?:few|many) arguments to function .([A-Za-z_]\w*)")


def compile_errors(build_dir):
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
    errs = [e for e in parse_errors(output) if e.get("kind") == "error"]
    return len(errs), [e.get("message", "") for e in errs]


def count_args_at(text, pos):
    """从 text[pos] == '(' 开始，返回该调用的参数个数。"""
    depth = 1
    commas = 0
    j = pos + 1
    in_str = None
    while j < len(text):
        c = text[j]
        if in_str:
            if c == "\\":
                j += 2
                continue
            if c == in_str:
                in_str = None
        elif c in "\"'":
            in_str = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1:
            commas += 1
        j += 1
    body = text[pos + 1:j].strip()
    return 0 if not body else commas + 1


def collect_arg_votes(build_dir, names):
    """统计 names 里每个函数在各调用点的参数数分布 {name: Counter}。"""
    votes = collections.defaultdict(collections.Counter)
    pats = {n: re.compile(r"\b" + re.escape(n) + r"\s*\(") for n in names}
    # 定义/声明行：行首（可选 extern）返回类型 + 函数名 + (
    def_re = {n: re.compile(r"(?m)^(?:extern\s+)?[A-Za-z_][\w \*]*?\b"
                            + re.escape(n) + r"\s*\(") for n in names}
    for p in build_dir.glob("*.c"):
        text = p.read_text(encoding="utf-8", errors="replace")
        for n in names:
            skip_spans = {m.start() for m in def_re[n].finditer(text)}
            for m in pats[n].finditer(text):
                if m.start() in skip_spans:
                    continue
                votes[n][count_args_at(text, m.end() - 1)] += 1
    return votes


def _strip_param_name(p):
    """从 'long *param_1' 提取类型 'long *'；无参数名则原样返回。"""
    p = p.strip()
    m = re.match(r"^(.*?)\s*\b([A-Za-z_]\w*)\s*$", p)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return p


def rewrite_params(text, name, nargs):
    """只把「定义/声明行」里 name(...) 调成 nargs 个参数。

    保留已有参数的类型（只改个数），不足的补 undefined8——这样函数体里对
    参数指针的索引/解引用不会因为类型被换成整数而报错。
    """
    pat = re.compile(
        r"(?m)^((?:extern\s+)?[A-Za-z_][\w \*]*?\b" + re.escape(name) + r"\s*)"
        r"\(([^();]*)\)")

    def repl(m):
        prefix, params_str = m.group(1), m.group(2)
        old_types = [_strip_param_name(p) for p in params_str.split(",") if p.strip()]
        if old_types == ["void"]:
            old_types = []
        if nargs <= len(old_types):
            types = old_types[:nargs]
        else:
            types = old_types + ["undefined8"] * (nargs - len(old_types))
        if types:
            new_params = ", ".join("%s param_%d" % (t, i + 1)
                                   for i, t in enumerate(types))
        else:
            new_params = "void"
        return prefix + "(" + new_params + ")"

    return pat.sub(repl, text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("build_dir")
    ap.add_argument("--min-votes", type=int, default=2,
                    help="众数至少出现 N 次才采纳（默认 2）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只分析/报告，不修改文件")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    build_dir = Path(args.build_dir)
    before, msgs = compile_errors(build_dir)
    names = sorted({m.group(1) for m in
                    (_ARG_ERR_RE.search(x) for x in msgs) if m})
    LOG.info("编译错误 %d；too few/many 被调函数 %d 个", before, len(names))

    votes = collect_arg_votes(build_dir, names)
    fixed = []
    for n in names:
        c = votes.get(n)
        if not c:
            continue
        argn, cnt = c.most_common(1)[0]
        total = sum(c.values())
        # 众数要占绝对多数（否则可能是变参函数或调用点不一致，改固定参数
        # 会把 too few 变成 too many）
        if cnt < args.min_votes or cnt / total < 0.9:
            continue
        fixed.append((n, argn, cnt, dict(c)))
    LOG.info("可修正参数数的函数: %d", len(fixed))
    for n, argn, cnt, dist in fixed[:20]:
        LOG.info("  %-28s -> %d 参 (票数 %d, 分布 %s)", n, argn, cnt, dist)

    if args.dry_run:
        LOG.info("dry-run：不修改文件")
        return

    # 应用于 prototypes.h + .c 定义
    proto = build_dir / "function_prototypes.h"
    if proto.exists() and fixed:
        text = proto.read_text(encoding="utf-8", errors="replace")
        for n, argn, _, _ in fixed:
            text = rewrite_params(text, n, argn)
        proto.write_text(text, encoding="utf-8")
    changed_files = 0
    for p in build_dir.glob("*.c"):
        if p.name == "data_defs.c":
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        new = text
        for n, argn, _, _ in fixed:
            new = rewrite_params(new, n, argn)
        if new != text:
            p.write_text(new, encoding="utf-8")
            changed_files += 1
    LOG.info("已改写 prototypes.h + %d 个 .c 文件", changed_files)


if __name__ == "__main__":
    main()
