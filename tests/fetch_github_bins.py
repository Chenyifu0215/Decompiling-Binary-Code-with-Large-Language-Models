#!/usr/bin/env python3
"""fetch_github_bins.py - 从 GitHub Release 抓取动态+stripped 二进制样本。

为什么这样抓：GitHub 上大多是源码；但不少项目在 Release 里附了 Linux x86_64
二进制，其中 Rust/C 项目的 .deb（Debian 构建）与官方 tar/txz 包通常就是
「动态链接 + 已 strip」。本工具按配置下载指定资产，解包后逐个判定 ELF：

  * 只保留 ELF64 x86-64 动态可执行文件（可选保留 .so）；
  * 上游已 strip 的直接作为 target 样本；
  * 上游未 strip 的，原始文件存入 ground_truth/（可作为对照答案），
    再 strip 一份到 target/（自 strip 的样本会标注 stripped_upstream=False）。

输出采用与 build_corpus 相同的思想，便于修复流程与评分隔离：

    <out_dir>/target/<name>            只交给反编译/修复流程
    <out_dir>/ground_truth/<name>      上游未 strip 原件（若有）
    <out_dir>/ground_truth/<name>.symbols.json
    <out_dir>/manifest.json            来源 URL、sha256、ELF 分类等

用法：

    python tests/fetch_github_bins.py --config tests/github_bins_example.json

配置见 tests/github_bins_example.json：repos 里写 repo/tag/assets（资产名精确
匹配，可从 GitHub Release 页面或 API 查）。默认下载完成后删除压缩包与解包树。
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from build_corpus import run_shell, to_wsl, write_symbols

WINDOWS = platform.system() == "Windows"
EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
ARCH_MACHINES = {
    "i386": {EM_386},
    "arm": {EM_ARM},
    "x86_64": {EM_X86_64},
    "aarch64": {EM_AARCH64},
}
MAX_SINGLE_MB = 64


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def elf_info(path):
    """轻量 ELF 判定（支持 ELF32/64 与大小端）：动态/是否 strip（有无 .symtab）。"""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 52 or h[:4] != b"\x7fELF" or h[4] not in (1, 2):
                return None
            is64 = h[4] == 2
            end = "little" if h[5] == 1 else "big"
            rd = lambda b: int.from_bytes(b, end)
            e_machine = rd(h[18:20])
            if is64:
                e_phoff = rd(h[32:40]); e_shoff = rd(h[40:48])
                e_phentsize = rd(h[54:56]); e_phnum = rd(h[56:58])
                e_shentsize = rd(h[58:60]); e_shnum = rd(h[60:62])
                e_shstrndx = rd(h[62:64])
            else:
                e_phoff = rd(h[28:32]); e_shoff = rd(h[32:36])
                e_phentsize = rd(h[42:44]); e_phnum = rd(h[44:46])
                e_shentsize = rd(h[46:48]); e_shnum = rd(h[48:50])
                e_shstrndx = rd(h[50:52])
            has_interp = has_dynamic = False
            interp = None
            if is64:
                poff_bytes, pfilesz_bytes = slice(8, 16), slice(32, 40)
            else:
                poff_bytes, pfilesz_bytes = slice(4, 8), slice(16, 20)
            for i in range(min(e_phnum, 64)):
                f.seek(e_phoff + i * e_phentsize)
                ph = f.read(e_phentsize)
                if len(ph) < (56 if is64 else 32):
                    break
                p_type = rd(ph[:4])
                if p_type == 3:
                    has_interp = True
                    p_offset = rd(ph[poff_bytes])
                    p_filesz = rd(ph[pfilesz_bytes])
                    f.seek(p_offset)
                    interp = (f.read(min(p_filesz, 256)).split(b"\x00")[0]
                              .decode(errors="replace"))
                elif p_type == 2:
                    has_dynamic = True
            names_off = None
            if e_shoff and e_shnum and e_shstrndx < e_shnum:
                f.seek(e_shoff + e_shstrndx * e_shentsize)
                sh = f.read(e_shentsize)
                names_off = rd(sh[(24 if is64 else 16):(32 if is64 else 20)])
            has_symtab = False
            for i in range(min(e_shnum, 4096)):
                f.seek(e_shoff + i * e_shentsize)
                sh = f.read(e_shentsize)
                if len(sh) < (64 if is64 else 40) or names_off is None:
                    continue
                name_off = rd(sh[:4])
                f.seek(names_off + name_off)
                if f.read(64).split(b"\x00")[0] == b".symtab":
                    has_symtab = True
                    break
            return {"type": rd(h[16:18]), "machine": e_machine, "interp": interp,
                    "has_interp": has_interp, "has_dynamic": has_dynamic,
                    "is64": is64,
                    "stripped": not has_symtab}
    except (OSError, ValueError):
        return None


def download(url, dst, retries=3):
    if dst.exists() and dst.stat().st_size > 0:
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    last_err = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "opencode-corpus"})
            with urllib.request.urlopen(req, timeout=180) as r, open(dst, "wb") as f:
                expected = int(r.headers.get("Content-Length") or 0)
                shutil.copyfileobj(r, f, 1 << 20)
            if expected and dst.stat().st_size != expected:
                raise RuntimeError("下载不完整: %d/%d 字节" % (dst.stat().st_size, expected))
            return dst
        except Exception as e:  # 网络抖动/截断，删除后重试
            last_err = e
            dst.unlink(missing_ok=True)
    raise RuntimeError("下载失败 %s: %s" % (url, last_err))


def extract(archive, dest):
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith(".deb"):
        r = run_shell("dpkg-deb -x '%s' '%s'" % (to_wsl(archive), to_wsl(dest)),
                      capture=True)
        if r.returncode != 0:
            raise RuntimeError("dpkg-deb 解包失败: %s" % ((r.stdout or "") + (r.stderr or "")))
    elif name.endswith((".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tar")):
        with tarfile.open(archive, "r:*") as tf:
            tf.extractall(dest, filter="data")
    elif name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            base = os.path.realpath(dest)
            for member in zf.infolist():
                target = os.path.realpath(os.path.join(dest, member.filename))
                if not target.startswith(base + os.sep):
                    continue
                zf.extract(member, dest)
    else:
        shutil.copyfile(archive, dest / archive.name)


def collect_elfs(tree, include_shared, include_static, machines):
    out = []
    for root, _dirs, files in os.walk(tree):
        for fn in files:
            p = Path(root) / fn
            try:
                # 悬空符号链接（dpkg-deb 生成的绝对链接）在 Windows 上会抛 OSError
                if p.is_symlink() or not p.is_file():
                    continue
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_SINGLE_MB * 1024 * 1024 or size == 0:
                continue
            info = elf_info(p)
            if not info or info["machine"] not in machines:
                continue
            if info["has_interp"]:
                info["link"] = "dynamic"
            elif info["has_dynamic"]:
                info["link"] = "shared" if include_shared else "skip"
            elif include_static:
                info["link"] = "static"
            else:
                info["link"] = "skip"
            if info["link"] != "skip":
                info["source"] = str(p)
                out.append((p, info))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="抓取配置（JSON）")
    ap.add_argument("--only", action="append", default=None, help="只处理指定 repo")
    args = ap.parse_args()

    spec = json.loads(Path(args.config).read_text(encoding="utf-8"))
    out_dir = ROOT / spec.get("out_dir", "ignore/generated/github_bins")
    target_dir = out_dir / "target"
    gt_dir = out_dir / "ground_truth"
    max_total = spec.get("max_total_mb", 100) * 1024 * 1024
    max_file = spec.get("max_file_mb", 32) * 1024 * 1024
    include_shared = spec.get("include_shared_libs", False)
    machines = set()
    for a in spec.get("arches", ["x86_64"]):
        machines |= ARCH_MACHINES.get(a, set())
    if not machines:
        print("配置中没有有效的 arches: %s" % spec.get("arches"))
        return 2
    include_static = spec.get("include_static", False)
    strip_if_needed = spec.get("strip_if_needed", True)
    keep_downloads = spec.get("keep_downloads", False)
    target_dir.mkdir(parents=True, exist_ok=True)
    gt_dir.mkdir(parents=True, exist_ok=True)
    static_dir = out_dir / "target_static"

    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) \
        if manifest_path.exists() else {"entries": []}
    seen_hashes = {e["sha256"] for e in manifest["entries"]}
    total = sum(e["size"] for e in manifest["entries"])

    repos = spec.get("repos", [])
    if args.only:
        repos = [r for r in repos if r["repo"] in set(args.only)]

    for job in repos:
        repo, tag = job["repo"], job["tag"]
        for asset in job.get("assets", []):
            if total >= max_total:
                print("[SKIP] 预算已满（%.1f MB）: %s/%s" % (total / 1048576, repo, asset))
                continue
            url = "https://github.com/%s/releases/download/%s/%s" % (repo, tag, asset)
            archive = out_dir / "_downloads" / repo.replace("/", "__") / asset
            tree = out_dir / "_extract" / repo.replace("/", "__") / asset
            kept = kept_static = skipped = 0
            try:
                download(url, archive)
                extract(archive, tree)
                cands = collect_elfs(tree, include_shared, include_static, machines)
                try:  # 小文件优先，保证预算用在尽量多的样本上
                    cands.sort(key=lambda t: t[0].stat().st_size)
                except OSError:
                    pass
                for path, info in cands:
                    try:
                        digest = sha256(path)
                        size = path.stat().st_size
                    except OSError:
                        skipped += 1
                        continue
                    if digest in seen_hashes:
                        continue
                    if size > max_file:
                        skipped += 1
                        continue
                    if total + size > max_total:
                        continue
                    dest_dir = static_dir if info["link"] == "static" else target_dir
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    name = path.name
                    if (dest_dir / name).exists():
                        name = "%s_%s" % (path.name, digest[:8])
                    entry = {
                        "repo": repo, "tag": tag, "asset": asset, "url": url,
                        "source_path": info["source"].split(os.sep + "_extract" + os.sep)[-1],
                        "name": name, "link": info["link"],
                        "machine": info["machine"], "is64": info.get("is64", True),
                        "sha256": digest, "size": size,
                        "stripped_upstream": info["stripped"],
                        "interp": info["interp"],
                        "has_ground_truth": False,
                    }
                    try:
                        if info["stripped"]:
                            shutil.copyfile(path, dest_dir / name)
                        elif strip_if_needed:
                            gt = gt_dir / name
                            shutil.copyfile(path, gt)
                            shutil.copyfile(path, dest_dir / name)
                            r = run_shell(
                                "strip --strip-all '%s'" % to_wsl(dest_dir / name),
                                capture=True)
                            if r.returncode != 0:
                                (dest_dir / name).unlink(missing_ok=True)
                                skipped += 1
                                continue
                            write_symbols(gt, gt_dir / (name + ".symbols.json"))
                            entry["stripped"] = True
                            entry["has_ground_truth"] = True
                            # strip 后文件变小，按实际大小记账
                            entry["size"] = (dest_dir / name).stat().st_size
                        else:
                            skipped += 1
                            continue
                    except OSError:
                        skipped += 1
                        continue
                    entry.setdefault("stripped", True)
                    seen_hashes.add(digest)
                    total += entry["size"]
                    if info["link"] == "static":
                        kept_static += 1
                    manifest["entries"].append(entry)
                    kept += 1
                print("[OK] %s/%s: 采用 %d（静态 %d），跳过 %d，累计 %.1f MB"
                      % (repo, asset, kept, kept_static, skipped, total / 1048576))
            except Exception as e:
                print("[FAIL] %s/%s: %s" % (repo, asset, e))
            finally:
                shutil.rmtree(tree, ignore_errors=True)
                if not keep_downloads:
                    shutil.rmtree(out_dir / "_downloads", ignore_errors=True)

    if not keep_downloads:
        shutil.rmtree(out_dir / "_extract", ignore_errors=True)
    manifest_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("完成：target %d 个（%.1f MB），manifest -> %s"
          % (len(manifest["entries"]), total / 1048576, manifest_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
