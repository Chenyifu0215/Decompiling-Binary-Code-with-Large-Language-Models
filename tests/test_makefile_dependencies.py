"""Verify generated Makefiles rebuild objects after generated headers change."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("make") is None,
    reason="gcc or make is unavailable",
)
def test_header_change_forces_incremental_recompile(tmp_path):
    for name in ["ghidra_types.h", "compat.h", "function_prototypes.h", "globals.h"]:
        (tmp_path / name).write_text("", encoding="utf-8")
    (tmp_path / "main.c").write_text(
        "int main(void) { return 0; }\n", encoding="utf-8",
    )
    dh.write_makefile(tmp_path, ["main.c"], "rebuilt.exe")

    initial = subprocess.run(
        ["make", "-C", str(tmp_path), "CC=gcc"],
        capture_output=True, text=True, timeout=30,
    )
    assert initial.returncode == 0, initial.stdout + initial.stderr
    dependency_file = tmp_path / "main.d"
    assert dependency_file.is_file()
    assert "globals.h" in dependency_file.read_text(encoding="utf-8")

    (tmp_path / "globals.h").write_text(
        "#error globals header was recompiled\n", encoding="utf-8",
    )
    incremental = subprocess.run(
        ["make", "-C", str(tmp_path), "CC=gcc"],
        capture_output=True, text=True, timeout=30,
    )
    assert incremental.returncode != 0
    assert "globals header was recompiled" in incremental.stderr
