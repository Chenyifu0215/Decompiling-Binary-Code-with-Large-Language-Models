"""Verify multiline decompiler signatures produce usable prototypes."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


def test_write_prototypes_collects_multiline_signature(tmp_path):
    source = tmp_path / "callee.c"
    source.write_text(
        "int callee(int a,\n"
        "           int b)\n"
        "{\n"
        "    return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    output = tmp_path / "function_prototypes.h"

    dh.write_prototypes(tmp_path, output, [source])

    assert "extern int callee(int a, int b);" in output.read_text(encoding="utf-8")
