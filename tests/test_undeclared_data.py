"""Verify undeclared object repair emits a visible initialized definition."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh
import fix_undeclared as fu


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_data_symbol_gets_extern_and_binary_initializer(tmp_path):
    original = tmp_path / "original.c"
    original.write_text(
        'unsigned char state[4] __asm__("state.0") = {1, 0, 2, 3};\n',
        encoding="utf-8",
    )
    obj = tmp_path / "original.o"
    compiled = subprocess.run(
        ["gcc", "-c", str(original), "-o", str(obj)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    binary = dh.parse_elf(obj)
    assert "state_0" in binary["norm_syms"]

    (tmp_path / "globals.h").write_text(
        "#ifndef GLOBALS_H\n#define GLOBALS_H\n#endif\n", encoding="utf-8",
    )
    (tmp_path / "data_defs.c").write_text("", encoding="utf-8")
    assert fu.add_data_symbol(binary, tmp_path, "state_0")
    header = (tmp_path / "globals.h").read_text(encoding="utf-8")
    definition = (tmp_path / "data_defs.c").read_text(encoding="utf-8")
    assert "extern unsigned char state_0[0x4];\n#endif" in header
    assert "unsigned char state_0[0x4] = {0x01, 0x00, 0x02, 0x03};" in definition

    main = tmp_path / "main.c"
    main.write_text(
        '#include "globals.h"\n'
        "int main(void) { return state_0[2] == 2 ? 0 : 1; }\n",
        encoding="utf-8",
    )
    executable = tmp_path / "undeclared_data"
    rebuilt = subprocess.run(
        ["gcc", str(main), str(tmp_path / "data_defs.c"), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
