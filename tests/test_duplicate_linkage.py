"""Verify duplicate functions retain one cross-file linkable definition."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_duplicate_function_keeps_one_external_owner(tmp_path):
    sources = {
        "helper_1000.c": "int helper(void)\n{\n  return 7;\n}\n",
        "helper_2000.c": "int helper(void)\n{\n  return 9;\n}\n",
        "caller.c": "int main(void)\n{\n  return helper() == 7 ? 0 : 1;\n}\n",
    }
    paths = []
    for filename, source in sources.items():
        path = tmp_path / filename
        path.write_text(source, encoding="utf-8")
        paths.append(path)

    localized = dh.find_static_duplicate_definitions(tmp_path, paths)
    assert localized == {tmp_path / "helper_2000.c": {"helper"}}

    repaired = []
    for path in paths:
        output = tmp_path / ("fixed_" + path.name)
        dh.repair_source_file(
            path, output, value_used=set(), global_names=set(),
            dup_names=localized.get(path),
        )
        repaired.append(output)

    assert "\nint helper(void)" in "\n" + repaired[0].read_text(encoding="utf-8")
    assert "static int helper(void)" in repaired[1].read_text(encoding="utf-8")
    executable = tmp_path / "duplicates"
    compiled = subprocess.run(
        ["gcc", "-std=gnu11", "-w", *(str(path) for path in repaired),
         "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
