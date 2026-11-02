#!/usr/bin/env python3
"""Offline, explicitly synthetic demonstration with a rejected and accepted patch."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins"))


def prepare(destination):
    shutil.copytree(ROOT / "tests" / "dynamic_cases", destination)
    subprocess.run(["gcc", "-O1", str(destination / "reference.c"), "-o", str(destination / "reference")], check=True)
    return destination / "config.yaml"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="new directory; existing paths are never overwritten")
    args = parser.parse_args()
    directory = args.output_dir or ROOT / "ignore" / "dynamic-demo" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:6])
    config = prepare(directory.resolve())
    print("合成缺陷演示（不计作真实 Ghidra 修复率）；配置：" + str(config), flush=True)
    return subprocess.call([sys.executable, str(ROOT / "plugins" / "dynamic_repair.py"),
                            "--config", str(config), "--evaluation-manifest", str(config.parent / "evaluation.json")])


if __name__ == "__main__":
    raise SystemExit(main())
