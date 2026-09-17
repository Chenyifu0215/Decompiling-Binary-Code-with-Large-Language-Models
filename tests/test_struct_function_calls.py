"""Compile repaired declarations alongside same-named libc function calls."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_64_bit_stat_family_calls_remain_callable(tmp_path):
    source = """int main(void)
{
    stat64 stat_buf;
    statfs64 statfs_buf;
    statvfs64 statvfs_buf;
    if (stat64(".", &stat_buf) != 0) return 1;
    if (statfs64(".", &statfs_buf) != 0) return 2;
    if (statvfs64(".", &statvfs_buf) != 0) return 3;
    return 0;
}
"""
    src = tmp_path / "input.c"
    repaired = tmp_path / "output.c"
    src.write_text(source, encoding="utf-8")
    dh.repair_source_file(src, repaired, value_used=set(), global_names=set())
    repaired_text = repaired.read_text(encoding="utf-8")
    assert "struct stat64 stat_buf;" in repaired_text
    assert "struct statfs64 statfs_buf;" in repaired_text
    assert "struct statvfs64 statvfs_buf;" in repaired_text
    assert 'stat64(".", &stat_buf)' in repaired_text
    assert 'statfs64(".", &statfs_buf)' in repaired_text
    assert 'statvfs64(".", &statvfs_buf)' in repaired_text

    executable = tmp_path / "stat_test"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         "-D_LARGEFILE64_SOURCE", "-include", "sys/stat.h",
         "-include", "sys/vfs.h", "-include", "sys/statvfs.h",
         str(repaired), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
