"""Compile repaired code and verify that C literals retain their contents."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_repaired_program_prints_original_literal(tmp_path):
    expected = "stat /* literal */ (sigaction *) _g_seed au._0_4_ stack0x10"
    source = """#include <stdio.h>
int main(void)
{
    puts("stat /* literal */ (sigaction *) _g_seed au._0_4_ stack0x10");
    return 0;
}
"""
    src = tmp_path / "input.c"
    repaired = tmp_path / "output.c"
    src.write_text(source, encoding="utf-8")
    dh.repair_source_file(
        src, repaired, value_used=set(), global_names={"g_seed"},
    )

    executable = tmp_path / "literal_test"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         str(repaired), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == expected + "\n"
