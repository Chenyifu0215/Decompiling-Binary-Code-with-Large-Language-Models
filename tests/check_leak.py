#!/usr/bin/env python3
"""check_leak.py - 评估公正性检查：确认修复流程没有偷用未 strip 孪生的信息。

思路：语料目录已按 target/ 与 ground_truth/ 物理分离。修复流程只应接触
target/sample（stripped）；本工具校验这一点，并在反编译/构建产物里搜索
ground_truth/symbols.json 中的真实函数名——命中即说明发生了信息泄漏。

用法：

    python tests/check_leak.py --sample-dir <corpus>/<job>/<config> \
        --dirs <反编译目录> [<构建目录> ...]

    # 也可以直接指定
    python tests/check_leak.py --target <stripped样本> --symbols <symbols.json> \
        --dirs <decomp_dir> <build_dir>

检查内容：
  1. target 确实是 stripped（无 .symtab）；
  2. 真实函数名集合 = symbols.json 中的 T/t/W/w，扣除动态导入（libc）与
     下划线开头的 CRT/编译器符号（Ghidra 依约定俗成识别它们不算泄漏）；
  3. 在 --dirs 下的文本产物（*.c/*.h/*.txt/*.json/*.log/Makefile/*.map 等）
     里按单词边界搜索这些名字，命中即报 leak 并返回非零。

不覆盖：Ghidra 项目 .rep 二进制库。严格评估建议在容器里跑修复流程，只挂载
target/，ground_truth/ 不进入容器；本工具作为常规回归检查。
"""

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from build_corpus import ROOT, capture, run_shell, to_wsl

# Ghidra 能通过分析/库签名合法识别的运行时符号，不算泄漏
_RUNTIME_PREFIXES = ("_", )
_RUNTIME_NAMES = {"main"}
_MAX_FILE_BYTES = 5 * 1024 * 1024


def is_stripped(binary):
    out = capture("readelf -S '%s' 2>/dev/null | grep -c '\\.symtab'" % to_wsl(binary))
    try:
        return int(out.strip() or "0") == 0
    except ValueError:
        return False


def dynamic_imports(binary):
    names = set()
    text = capture("readelf --dyn-syms '%s' 2>/dev/null" % to_wsl(binary))
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[6] == "UND":
            name = parts[7].split("@")[0]
            if name:
                names.add(name)
    return names


def real_names(symbols_path, imports):
    symbols = json.loads(Path(symbols_path).read_text(encoding="utf-8"))
    names = set()
    for s in symbols:
        if s.get("type") not in ("T", "t", "W", "w"):
            continue
        name = s.get("name", "")
        if not name or "@" in name:
            continue
        if name in imports or name in _RUNTIME_NAMES:
            continue
        if name.startswith(_RUNTIME_PREFIXES):
            continue
        if len(name) < 3:
            continue
        names.add(name)
    return names


def iter_text_files(dirs):
    for d in dirs:
        base = Path(d)
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.stat().st_size > _MAX_FILE_BYTES:
                continue
            try:
                head = p.read_bytes()[:4096]
            except OSError:
                continue
            if b"\x00" in head:
                continue
            yield p


def scan(dirs, names):
    hits = []
    patterns = {n: re.compile(r"\b%s\b" % re.escape(n)) for n in sorted(names)}
    for p in iter_text_files(dirs):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for n, pat in patterns.items():
                if pat.search(line):
                    hits.append((str(p), line_no, n))
                    break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample-dir", help="语料目录（含 target/ 与 ground_truth/）")
    ap.add_argument("--target", help="stripped 样本路径")
    ap.add_argument("--symbols", help="ground_truth/symbols.json")
    ap.add_argument("--dirs", nargs="+", required=True,
                    help="要检查的产物目录（反编译目录、构建目录等）")
    args = ap.parse_args()

    if args.sample_dir:
        sample_dir = Path(args.sample_dir)
        target = sample_dir / "target" / "sample"
        symbols = sample_dir / "ground_truth" / "symbols.json"
    else:
        if not (args.target and args.symbols):
            ap.error("需要 --sample-dir 或同时给出 --target 与 --symbols")
        target, symbols = Path(args.target), Path(args.symbols)

    if not target.exists():
        print("ERR: 找不到 target: %s" % target)
        return 2
    if not symbols.exists():
        print("ERR: 找不到 symbols: %s" % symbols)
        return 2

    if not is_stripped(target):
        print("LEAK? target 带有 .symtab（不是 stripped）：%s" % target)
        return 1
    imports = dynamic_imports(target)
    names = real_names(symbols, imports)
    if not names:
        print("真实函数名集合为空，跳过文本扫描")
        return 0

    hits = scan(args.dirs, names)
    print("检查 target=%s" % target)
    print("真实函数名 %d 个（已排除动态导入 %d 个与 CRT 符号）；扫描目录 %d 个"
          % (len(names), len(imports), len(args.dirs)))
    if hits:
        print("发现泄漏 %d 处：" % len(hits))
        for path, line, name in hits[:50]:
            print("  %s:%d: %s" % (path, line, name))
        return 1
    print("未发现泄漏：产物中不含未 strip 孪生的函数名")
    return 0


if __name__ == "__main__":
    sys.exit(main())
