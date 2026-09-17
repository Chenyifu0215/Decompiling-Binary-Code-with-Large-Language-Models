"""Compile generated globals to verify their binary width and initial value."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_bitwise_global_preserves_object_width_and_initializer(tmp_path):
    binary = dh.parse_elf(ROOT / "tests" / "test_complex.o")
    source = tmp_path / "main.c"
    source.write_text(
        "int main(void)\n"
        "{\n"
        "    return sizeof(g_seed) != 4 || (g_seed >> 16) != 0x1234;\n"
        "}\n",
        encoding="utf-8",
    )

    dh.write_types(tmp_path / "ghidra_types.h")
    dh.write_globals(binary, tmp_path, tmp_path / "globals.h", [source])
    dh.write_data_defs(binary, tmp_path, tmp_path / "data_defs.c", [source])

    globals_text = (tmp_path / "globals.h").read_text(encoding="utf-8")
    definitions = (tmp_path / "data_defs.c").read_text(encoding="utf-8")
    assert "extern undefined4 g_seed;" in globals_text
    assert "undefined4 g_seed = 0x12345678;" in definitions

    executable = tmp_path / "global_test"
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         "-include", str(tmp_path / "globals.h"), str(source),
         str(tmp_path / "data_defs.c"), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
