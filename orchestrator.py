#!/usr/bin/env python3
"""orchestrator.py - Closed-loop *static* repair: iterate until gcc compiles.

Convergence criterion is compile success only (no runtime oracle). The loop:

    prepare (regenerate a clean build via decompile_helper.py)
      -> apply persistent patch list
      -> compile
      -> if OK: done
      -> else: proposer (fallback rules or LLM) emits new patches
      -> append + persist, repeat

Patch state lives in a JSON file and is replayed from the clean base each
iteration, so every run is deterministic and reversible (delete the patch file
to roll back).

Usage:
    python orchestrator.py <binary> <decomp_dir> [options]

Examples:
    python orchestrator.py test_complex.o ./test_out/test_complex_decomp
    python orchestrator.py test_complex.o ./test_out_fixed --proposer llm
    python orchestrator.py test_complex.o ./test_out_fixed --no-prepare --build-dir demo_broken
"""

import argparse
import logging
import platform
import re
import shlex
import subprocess
import sys
from pathlib import Path

from patch import apply_patch_list, load_patches, save_patches
from llm import make_proposer

LOG = logging.getLogger("orchestrator")

_ERROR_RE = re.compile(
    r"^([^:\n]+):(\d+):(\d+):\s*(error|warning):\s*(.*)$"
)

# 链接错误：/usr/bin/ld: foo.c:(.text+0xd): undefined reference to `bar'
_UNDEF_RE = re.compile(r"undefined reference to [`']([^`']+)[`']")
_UNDEF_FILE_RE = re.compile(r"([A-Za-z0-9_.\-]+\.(?:c|h)):\(")


def to_wsl(path):
    p = str(Path(path).resolve())
    if platform.system() != "Windows":
        return p
    if len(p) >= 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def compile_build(build_dir, make_cmd=None):
    """Run make in build_dir; return (ok, errors). Streams output in real time."""
    if make_cmd is None:
        make_cmd = (
            ["wsl", "make", "-C", to_wsl(build_dir), "-j"]
            if platform.system() == "Windows"
            else ["make", "-C", str(build_dir), "-j"]
        )
    proc = subprocess.Popen(
        make_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    chunks = []
    for line in proc.stdout:
        chunks.append(line)
        sys.stderr.write(line)
        sys.stderr.flush()
    proc.wait()
    output = "".join(chunks)
    return proc.returncode == 0, parse_errors(output)


def parse_errors(output):
    errors = []
    for line in output.splitlines():
        m = _ERROR_RE.match(line.strip())
        if m:
            errors.append(
                {
                    "file": m.group(1),
                    "line": int(m.group(2)),
                    "col": int(m.group(3)),
                    "kind": m.group(4),
                    "message": m.group(5),
                }
            )
            continue
        u = _UNDEF_RE.search(line)
        if u:
            fm = _UNDEF_FILE_RE.search(line)
            errors.append(
                {
                    "file": fm.group(1) if fm else "",
                    "line": 0,
                    "col": 0,
                    "kind": "error",
                    "message": "undefined reference to '%s'" % u.group(1),
                }
            )
    return errors


def prepare_build(binary, decomp_dir, build_dir, map_path=None):
    """Regenerate a clean build dir via decompile_helper.py `all`."""
    cmd = [
        sys.executable, "decompile_helper.py", "all",
        binary, decomp_dir, "-o", build_dir,
    ]
    if map_path:
        cmd += ["--map", map_path]
    # 不捕获输出，让 decompile_helper 的日志实时透传到上层（GUI）
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        raise RuntimeError("decompile_helper failed (exit %d)" % proc.returncode)
    return build_dir


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("decomp_dir", help="directory of Ghidra .c output")
    ap.add_argument("-o", "--build-dir", default=None,
                    help="build dir (default: ./static_build)")
    ap.add_argument("--patches", default=None,
                    help="patch state file (default: <build-dir>/patches.json)")
    ap.add_argument("--proposer", choices=["fallback", "llm"], default="fallback")
    ap.add_argument("--rules-file", default=None,
                    help="custom fallback rules (JSON list)")
    ap.add_argument("--model", default=None,
                    help="LLM model id (default: $LLM_MODEL or deepseek-v4-pro)")
    ap.add_argument("--base-url", default=None,
                    help="API base URL (default: $LLM_BASE_URL or DeepSeek)")
    ap.add_argument("--api-key", default=None,
                    help="API key (default: $LLM_API_KEY)")
    ap.add_argument("--max-iter", type=int, default=10)
    ap.add_argument("--map", default=None,
                    help="GNU ld map file; filter out statically-linked libc code")
    ap.add_argument("--no-prepare", action="store_true",
                    help="skip decompile_helper; use existing build dir")
    ap.add_argument("--make-cmd", default=None,
                    help="override the make command (shell-style quotes allowed; include -C <dir> yourself)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    build_dir = args.build_dir or "static_build"
    patch_file = args.patches or str(Path(build_dir) / "patches.json")
    make_cmd = shlex.split(args.make_cmd) if args.make_cmd else None

    proposer = make_proposer(
        args.proposer,
        rules_file=args.rules_file,
        base_url=args.base_url,
        api_key=args.api_key,
        model=args.model,
    )

    patches = load_patches(patch_file)

    for it in range(args.max_iter):
        LOG.info("=== iteration %d ===", it)

        if not args.no_prepare:
            prepare_build(args.binary, args.decomp_dir, build_dir, args.map)

        applied, app_errs = apply_patch_list(build_dir, patches)
        if app_errs:
            LOG.warning("patch application issues: %s", app_errs)

        ok, errors = compile_build(build_dir, make_cmd)
        errs = [e for e in errors if e["kind"] == "error"]

        if ok:
            LOG.info("compile OK after %d iteration(s); %d patch(es) applied.",
                     it, len(patches))
            return 0

        if not errs:
            LOG.error("compile failed but no parseable errors found; giving up.")
            return 1

        for e in errs:
            LOG.info("  error: %(file)s:%(line)s: %(message)s", e)

        new = proposer.propose(errs, build_dir)
        if not new:
            LOG.error("proposer returned no patches for %d error(s); giving up.",
                      len(errs))
            return 1

        LOG.info("proposer suggested %d patch(es).", len(new))
        patches.extend(new)
        save_patches(patch_file, patches)

    LOG.error("reached max iterations (%d) without a clean compile.", args.max_iter)
    return 1


if __name__ == "__main__":
    sys.exit(main())
