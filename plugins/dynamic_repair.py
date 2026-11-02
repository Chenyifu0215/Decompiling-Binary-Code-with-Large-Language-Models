#!/usr/bin/env python3
"""CLI for runtime repair. Windows delegates this same entry point to WSL."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def wsl_path(path, distribution=None):
    prefix = ["wsl.exe"] + (["--distribution", distribution] if distribution else [])
    return subprocess.check_output(prefix + ["--exec", "wslpath", "-a", "-u", str(Path(path).resolve())],
                                   text=True, encoding="utf-8").strip()


def validate_result_path(path, config, config_path, evaluation_path):
    if not path:
        return
    target = Path(path).resolve()
    source = Path(config["target"]["source_dir"])
    protected = [config_path, evaluation_path, config["target"]["reference_binary"],
                 config["tests"]["repair_manifest"], config["repair"]["replay_file"]]
    if target == source or source in target.parents or any(target == Path(p).resolve() for p in protected if p):
        raise ValueError("result-file must not overwrite source, configuration or test inputs")
    if not target.parent.is_dir() or target.is_dir():
        raise ValueError("result-file must name a file in an existing directory")


def main(argv=None):
    parser = argparse.ArgumentParser(description="动态修复：独立构建、运行、回归门禁、证据报告")
    parser.add_argument("--config", required=True)
    parser.add_argument("--evaluation-manifest", help="修复结束后才运行的独立测试清单")
    parser.add_argument("--result-file", help="向 GUI/调用者写入最终结果 JSON")
    parser.add_argument("--wsl-distribution", help="Windows 下使用的 WSL 发行版")
    parser.add_argument("--wsl-python", default="python3", help="WSL 中已装 PyYAML 的 Python 路径")
    args = parser.parse_args(argv)
    if os.name == "nt":
        try:
            prefix = ["wsl.exe"] + (["--distribution", args.wsl_distribution] if args.wsl_distribution else [])
            command = prefix + ["--exec", args.wsl_python, wsl_path(__file__, args.wsl_distribution),
                                "--config", wsl_path(args.config, args.wsl_distribution)]
            for flag, value in (("--evaluation-manifest", args.evaluation_manifest), ("--result-file", args.result_file)):
                if value:
                    command += [flag, wsl_path(value, args.wsl_distribution)]
            return subprocess.call(command)
        except (OSError, subprocess.SubprocessError) as exc:
            print("WSL 启动失败: " + str(exc), file=sys.stderr)
            return 2
    from dynamic.config import load_config
    from dynamic.controller import run

    def cancelled(signum, frame):
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, cancelled)
    try:
        config = load_config(args.config)
        validate_result_path(args.result_file, config, args.config, args.evaluation_manifest)
        result = run(config, args.evaluation_manifest, progress=lambda s: print(s, flush=True))
    except (ValueError, OSError) as exc:
        print("配置错误: " + str(exc), file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    if args.result_file:
        try:
            from dynamic.workspace import write_json
            write_json(args.result_file, result)
        except OSError as exc:
            print("无法写入结果文件: " + str(exc), file=sys.stderr)
            return 2
    return 0 if result["status"] in ("TEST_VALIDATED", "REPAIR_TESTS_PASSED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
