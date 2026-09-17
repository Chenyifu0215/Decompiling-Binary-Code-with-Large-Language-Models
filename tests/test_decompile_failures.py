"""Verify failed Ghidra decompilations are excluded from success output."""

from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_binary as db


class _Decompiler:
    def setOptions(self, value):
        pass

    def toggleSyntaxTree(self, value):
        pass

    def openProgram(self, value):
        return True

    def closeProgram(self):
        pass

    def dispose(self):
        pass

    def decompileFunction(self, *args):
        return SimpleNamespace(
            decompileCompleted=lambda: False,
            getErrorMessage=lambda: "Timeout",
        )


def test_failed_function_is_not_counted_or_written(tmp_path):
    func = SimpleNamespace(
        getName=lambda: "failed_function",
        getEntryPoint=lambda: "00100000",
        getSignature=lambda: "int failed_function(void)",
    )
    manager = SimpleNamespace(getFunctions=lambda forward: [func])
    program = SimpleNamespace(
        getFunctionManager=lambda: manager,
        getName=lambda: "test",
    )
    module = ModuleType("ghidra.app.decompiler")
    module.DecompInterface = _Decompiler
    module.DecompileOptions = lambda: None

    with patch.dict(sys.modules, {"ghidra.app.decompiler": module}):
        count, size = db.decompile_all_functions(program, output_dir=str(tmp_path))

    assert (count, size) == (0, 0)
    assert list(tmp_path.glob("*.c")) == []
