"""Compile rewritten signatures to ensure function-body names remain valid."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import fix_argcount as fa


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_added_parameter_does_not_rename_existing_parameters(tmp_path):
    source = """typedef unsigned long long undefined8;
int add(int a, int b)
{
    return a + b;
}
int main(void)
{
    return add(2, 3, 99) == 5 ? 0 : 1;
}
"""
    repaired = fa.rewrite_params(source, "add", 3)
    assert "int add(int a, int b, undefined8 param_3)" in repaired
    assert "return a + b;" in repaired

    src = tmp_path / "argcount_test.c"
    executable = tmp_path / "argcount_test"
    src.write_text(repaired, encoding="utf-8")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", str(src),
         "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
