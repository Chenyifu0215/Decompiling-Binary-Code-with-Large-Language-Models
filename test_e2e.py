"""test_e2e.py - 端到端测试：decompile_helper all 生成工程 → make 编译通过。

用已反编译好的 test_out_fixed（44 个 .c）作为输入，不依赖 Ghidra JVM，
但依赖 gcc（Linux）或 WSL make（Windows）。
"""

import os
import platform
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(HERE, "test_complex.o")
DECOMP_DIR = os.path.join(HERE, "test_out_fixed")


def _to_wsl(path):
    p = os.path.abspath(path)
    if platform.system() != "Windows":
        return p
    if len(p) >= 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def _make_available():
    """检测 make 是否可用（Windows 用 wsl）。"""
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["wsl", "make", "--version"], capture_output=True)
            return r.returncode == 0
        r = subprocess.run(["make", "--version"], capture_output=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _make_available(), reason="make/wsl 不可用")
class TestEndToEnd:
    def test_decompile_helper_all_and_make(self, tmp_path):
        build_dir = str(tmp_path / "build")

        # 1. decompile_helper all 生成工程
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "decompile_helper.py"), "all",
             BINARY, DECOMP_DIR, "-o", build_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        assert r.returncode == 0, r.stderr
        assert os.path.isfile(os.path.join(build_dir, "Makefile"))
        assert os.path.isfile(os.path.join(build_dir, "ghidra_types.h"))

        # 2. make 编译
        if platform.system() == "Windows":
            make_cmd = ["wsl", "make", "-C", _to_wsl(build_dir)]
        else:
            make_cmd = ["make", "-C", build_dir]
        r2 = subprocess.run(make_cmd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        assert r2.returncode == 0, "make 失败:\n" + r2.stdout[-2000:]
        assert os.path.isfile(os.path.join(build_dir, "rebuilt.exe"))

    def test_generated_headers_contain_expected_types(self, tmp_path):
        """生成的头文件应包含补全的 longlong/uchar typedef。"""
        build_dir = str(tmp_path / "build")
        subprocess.run(
            [sys.executable, os.path.join(HERE, "decompile_helper.py"), "all",
             BINARY, DECOMP_DIR, "-o", build_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        text = open(os.path.join(build_dir, "ghidra_types.h"),
                    encoding="utf-8").read()
        assert "typedef long long          longlong;" in text
        assert "typedef unsigned char      uchar;" in text
