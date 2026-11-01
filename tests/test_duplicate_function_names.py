"""Verify duplicate Ghidra names are made unique before decompilation."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_binary as db


class _Function:
    def __init__(self, name, address):
        self.name = name
        self.address = address

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.address

    def setName(self, name, source_type):
        self.name = name


class _Program:
    def __init__(self):
        self.transactions = []

    def startTransaction(self, name):
        self.transactions.append((name, None))
        return 7

    def endTransaction(self, transaction, commit):
        self.transactions[-1] = (self.transactions[-1][0], commit)


def test_duplicate_names_include_entry_addresses():
    funcs = [
        _Function("helper", "00101000"),
        _Function("helper", "00102000"),
        _Function("caller", "00103000"),
    ]
    program = _Program()

    assert db.uniquify_duplicate_function_names(program, funcs, object()) == 2
    assert [func.getName() for func in funcs] == [
        "helper_00101000", "helper_00102000", "caller",
    ]
    assert program.transactions == [("uniquify duplicate function names", True)]
