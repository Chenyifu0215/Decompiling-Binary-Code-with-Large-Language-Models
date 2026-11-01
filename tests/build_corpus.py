#!/usr/bin/env python3
"""build_corpus.py - 从源码批量构建「动态/静态 × stripped/未stripped」样本。

方案 2 工具：源码来自 GitHub 仓库、release 包或本地文件，自己编译并 strip，
保证每个样本都有对应的源码与编译参数（ground truth），便于比对和功能验证。
每个 (job, config) 目录同时保留：

  sample             目标样本（按配置 strip --strip-all）
  sample.unstripped  同源同参数的未 strip 版本（代码布局一致，符号表可用来
                     把反编译结果里的 FUN_xxx 对回真实函数名）
  symbols.json       从 sample.unstripped 导出的 name/address/size 映射
  sample.map         链接 map（动态链接时）
  build.sh           可复现的构建命令
  manifest.json      分类结果（file/readelf：动态/静态、架构、NEEDED、函数数）

用法（Windows 自动经 WSL 执行 gcc/readelf/nm）：

    python tests/build_corpus.py --config tests/corpus_example.json
    python tests/build_corpus.py --config tests/corpus_example.json --only stress_t1

配置文件格式见 tests/corpus_example.json。configs 是全局编译矩阵；
recipe 类型（真实 GitHub 项目）使用各自的 build 命令，编译矩阵由项目自身决定。
"""

import argparse
import hashlib
import json
import platform
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WINDOWS = platform.system() == "Windows"


def to_wsl(path):
    """Windows 路径 -> WSL 路径；非 Windows 原样返回。"""
    p = str(Path(path).resolve())
    if not WINDOWS:
        return p
    if len(p) >= 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def run_shell(script, cwd=None, capture=False):
    """在 bash 中执行命令（Windows 经 WSL）。"""
    if WINDOWS:
        full = "cd '%s' && %s" % (to_wsl(cwd), script) if cwd else script
        cmd = ["wsl", "bash", "-lc", full]
        return subprocess.run(cmd, capture_output=capture, text=True,
                              encoding="utf-8", errors="replace")
    cwd_s = str(cwd) if cwd else None
    return subprocess.run(["bash", "-lc", script], cwd=cwd_s,
                          capture_output=capture, text=True,
                          encoding="utf-8", errors="replace")


def capture(script, cwd=None):
    r = run_shell(script, cwd=cwd, capture=True)
    return (r.stdout or "") + (r.stderr or "")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def classify(binary, unstripped):
    """用 file/readelf/nm 判定动态/静态、架构、NEEDED、函数数。"""
    info = capture("file -b '%s'" % to_wsl(binary)).strip()
    arch = ""
    m = re.search(r"x86-64|aarch64|ARM|i386|RISC-V", info)
    if m:
        arch = m.group(0)
    is_elf = "ELF" in info
    dynamic = "dynamically linked" in info
    static = "statically linked" in info
    sections = capture("readelf -S '%s' 2>/dev/null | grep -c '\\.symtab'" % to_wsl(binary))
    stripped = int((sections or "0").strip() or "0") == 0
    needed = re.findall(r"NEEDED.*?\[(.*?)\]",
                        capture("readelf -d '%s' 2>/dev/null" % to_wsl(binary)))
    funcs = 0
    if unstripped and Path(unstripped).exists():
        out = capture("nm --defined-only '%s' 2>/dev/null | grep -c ' [TtWw] '" % to_wsl(unstripped))
        try:
            funcs = int(out.strip() or 0)
        except ValueError:
            funcs = 0
    return {
        "elf": is_elf, "arch": arch, "dynamic": dynamic, "static": static,
        "stripped": stripped, "needed": needed, "functions": funcs,
        "file": info,
    }


def write_symbols(unstripped, dst):
    text = capture("nm -S --defined-only '%s' 2>/dev/null" % to_wsl(unstripped))
    symbols = []
    for line in text.splitlines():
        parts = line.split()
        try:
            if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]+", parts[1]):
                addr, size, typ = int(parts[0], 16), int(parts[1], 16), parts[2]
                name = " ".join(parts[3:])
            elif len(parts) >= 3:
                addr, size, typ = int(parts[0], 16), 0, parts[1]
                name = " ".join(parts[2:])
            else:
                continue
        except ValueError:
            continue
        symbols.append({"name": name, "addr": addr, "size": size, "type": typ})
    dst.write_text(json.dumps(symbols, indent=1), encoding="utf-8")
    return len(symbols)


def make_stripped(unstripped, stripped):
    import shutil
    shutil.copyfile(unstripped, stripped)
    r = run_shell("strip --strip-all '%s'" % to_wsl(stripped), capture=True)
    if r.returncode != 0:
        raise RuntimeError("strip failed: %s" % ((r.stdout or "") + (r.stderr or "")))


def _prepare_outdir(outdir):
    """每个 (job, config) 目录重建，并在物理上分离：

        target/        只交给反编译/修复流程（stripped 样本）
        ground_truth/  仅用于事后评分（未 strip 孪生、符号表、map）
    """
    import shutil
    if outdir.exists():
        shutil.rmtree(outdir)
    target_dir = outdir / "target"
    gt_dir = outdir / "ground_truth"
    target_dir.mkdir(parents=True)
    gt_dir.mkdir(parents=True)
    return target_dir, gt_dir


def build_single_file(job, cfg, out_root):
    outdir = out_root / job["name"] / cfg["name"]
    target_dir, gt_dir = _prepare_outdir(outdir)
    flags = list(cfg.get("cflags", [])) + list(job.get("cflags", []))
    if cfg.get("static"):
        flags.append("-static")
    cc = job.get("cc", "gcc")
    sources = job.get("sources", [])
    if not sources:
        raise ValueError("single_file job 需要 sources")
    unstripped = gt_dir / "sample.unstripped"
    parts = [cc] + flags + [shlex.quote(to_wsl(ROOT / s)) for s in sources]
    parts += ["-o", shlex.quote(to_wsl(unstripped))]
    if not cfg.get("static"):
        parts.append("-Wl,-Map=" + shlex.quote(to_wsl(gt_dir / "sample.map")))
    script = " ".join(parts)
    (outdir / "build.sh").write_text("#!/bin/sh\n%s\n" % script, encoding="utf-8")
    r = run_shell(script, capture=True)
    if r.returncode != 0:
        raise RuntimeError("gcc failed:\n%s" % ((r.stdout or "") + (r.stderr or "")))
    make_stripped(unstripped, target_dir / "sample")
    return outdir, unstripped


def git_checkout(job, src_dir):
    if (src_dir / ".git").exists():
        return
    cmd = ["git", "clone", "--depth", "1"]
    if job.get("rev"):
        cmd += ["--branch", job["rev"]]
    cmd += [job["git"], str(src_dir)]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError("git clone failed:\n%s" % (r.stdout or "") + (r.stderr or ""))


def find_artifacts(base, names):
    """在 base 下查找名字匹配的文件（glob 由 find 展开）。"""
    expr = " -o ".join("-name %s" % shlex.quote(n) for n in names)
    text = capture("find . -type f \\( %s \\)" % expr, cwd=base)
    return [base / line.strip().lstrip("./")
            for line in text.splitlines() if line.strip()]


def build_recipe(job, cfg, out_root):
    outdir = out_root / job["name"] / (cfg["name"] or "default")
    target_dir, gt_dir = _prepare_outdir(outdir)
    src_dir = out_root / "_sources" / job["name"]
    git_checkout(job, src_dir)
    for cmd in job.get("build", []):
        r = run_shell(cmd, cwd=src_dir, capture=True)
        if r.returncode != 0:
            raise RuntimeError("build 失败 (%s):\n%s" % (cmd, (r.stdout or "") + (r.stderr or "")))
    arts = find_artifacts(src_dir, job.get("artifacts", []))
    if not arts:
        raise RuntimeError("未找到构建产物: %s" % job.get("artifacts"))
    unstripped = gt_dir / "sample.unstripped"
    import shutil
    shutil.copyfile(arts[0], unstripped)
    make_stripped(unstripped, target_dir / "sample")
    return outdir, unstripped


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="语料构建配置（JSON）")
    ap.add_argument("--only", action="append", default=None,
                    help="只构建指定 job（可重复）")
    args = ap.parse_args()

    spec = json.loads(Path(args.config).read_text(encoding="utf-8"))
    out_root = ROOT / spec.get("out_dir", "ignore/generated/corpus")
    configs = spec.get("configs", [{"name": "default"}])
    jobs = spec.get("jobs", [])
    if args.only:
        jobs = [j for j in jobs if j["name"] in set(args.only)]

    manifest_path = out_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) \
        if manifest_path.exists() else {"entries": []}
    manifest["entries"] = [e for e in manifest["entries"]
                           if e.get("job") not in {j["name"] for j in jobs}]

    ok = fail = 0
    for job in jobs:
        job_configs = configs if job.get("type") != "recipe" else [{"name": "default"}]
        for cfg in job_configs:
            tag = "%s/%s" % (job["name"], cfg["name"])
            try:
                if job.get("type", "single_file") == "single_file":
                    outdir, unstripped = build_single_file(job, cfg, out_root)
                else:
                    outdir, unstripped = build_recipe(job, cfg, out_root)
                target = outdir / "target" / "sample"
                entry = {
                    "job": job["name"], "config": cfg["name"],
                    "dir": str(outdir.relative_to(ROOT)).replace("\\", "/"),
                    "target": "target/sample",
                    "ground_truth": {
                        "unstripped": "ground_truth/sample.unstripped",
                        "symbols": "ground_truth/symbols.json",
                        "map": "ground_truth/sample.map",
                    },
                    "source": {"git": job.get("git"), "rev": job.get("rev"),
                               "sources": job.get("sources")},
                    "cflags": cfg.get("cflags", []) + job.get("cflags", []),
                    "static": bool(cfg.get("static")),
                }
                for label, p in (("stripped", target), ("unstripped", unstripped)):
                    entry[label] = {"sha256": sha256(p), "size": p.stat().st_size}
                entry.update(classify(target, unstripped))
                nsym = write_symbols(unstripped, outdir / "ground_truth" / "symbols.json")
                entry["symbol_count"] = nsym
                manifest["entries"].append(entry)
                ok += 1
                print("[OK] %s: %s | type=%s static=%s stripped=%s funcs=%d symbols=%d"
                      % (tag, entry["file"].split(", ")[0],
                         "dyn" if entry["dynamic"] else "static",
                         entry["static"], entry["stripped"],
                         entry["functions"], nsym))
            except Exception as e:
                fail += 1
                print("[FAIL] %s: %s" % (tag, e))
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("完成: %d 成功, %d 失败; manifest -> %s"
          % (ok, fail, manifest_path))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
