#!/usr/bin/env python3
"""fix_signatures.py - Apply function signatures to a binary via PyGhidra.

This is the bridge between an LLM (or manual analysis) and Ghidra: the model
emits a list of {name/address: signature string} entries, and this script
parses + applies them through Ghidra's API, then re-decompiles.

Usage:
    python fix_signatures.py <binary> --signatures sigs.json -o <out_dir>
    python fix_signatures.py <binary> --signatures sigs.json --dump apply_op
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import decompile_binary as db


def find_function(program, spec):
    fm = program.getFunctionManager()
    try:
        addr = program.getAddressFactory().getAddress(spec)
        func = fm.getFunctionAt(addr)
        if func is not None:
            return func
    except Exception:
        pass
    for func in fm.getFunctions(True):
        if func.getName() == spec:
            return func
    return None


def apply_signatures(program, specs):
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.symbol import SourceType

    parser = FunctionSignatureParser(program.getDataTypeManager(), None)
    results = []
    for spec in specs:
        name = spec.get("name") or spec.get("address")
        sig = spec["signature"]
        func = find_function(program, name)
        if func is None:
            logging.error("Function not found: %s", name)
            results.append((name, False, "not found"))
            continue
        try:
            parsed = parser.parse(None, sig)
            if parsed is None:
                raise RuntimeError("parser returned null")
            tx = program.startTransaction("fix_signatures")
            try:
                cmd = ApplyFunctionSignatureCmd(
                    func.getEntryPoint(), parsed,
                    SourceType.USER_DEFINED, False, True,
                )
                ok = cmd.applyTo(program)
            finally:
                program.endTransaction(tx, True)
            if not ok:
                raise RuntimeError("ApplyFunctionSignatureCmd returned False")
            logging.info("Applied %s -> %s", name, sig)
            results.append((name, True, None))
        except Exception as e:
            logging.error("Failed to apply %s: %s", name, e)
            results.append((name, False, str(e)))
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("--signatures", type=Path, required=True,
                    help="JSON list of {name/address, signature}")
    ap.add_argument("-o", "--output-dir", type=Path, default=None,
                    help="Where to write re-decompiled functions")
    ap.add_argument("--dump", nargs="*", default=None,
                    help="Print decompiled C for these function names")
    ap.add_argument("--ghidra-dir", type=Path, default=None)
    ap.add_argument("--no-analyze", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    specs = json.loads(args.signatures.read_text(encoding="utf-8"))
    if not isinstance(specs, list):
        logging.error("--signatures must be a JSON list")
        sys.exit(1)

    db.start_ghidra(args.ghidra_dir, verbose=False)

    project, program, primary = db.load_binary(
        args.binary, analyze=not args.no_analyze)

    try:
        results = apply_signatures(program, specs)

        if args.dump:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
            decomp = DecompInterface()
            decomp.setOptions(DecompileOptions())
            decomp.toggleSyntaxTree(False)
            if not decomp.openProgram(program):
                logging.error("openProgram failed")
            for name in args.dump:
                func = find_function(program, name)
                if func is None:
                    print("\n// %s: NOT FOUND" % name)
                    continue
                r = decomp.decompileFunction(func, 30, None)
                if r is None or not r.decompileCompleted():
                    print("\n// %s: decompile failed" % name)
                    continue
                print("\n// ===== %s =====\n%s" % (name, r.getDecompiledFunction().getC()))
            decomp.closeProgram()
            decomp.dispose()

        if args.output_dir:
            count, nbytes = db.decompile_all_functions(
                program, output_dir=str(args.output_dir))
            logging.info("Re-decompiled %d functions (%d bytes) to %s",
                         count, nbytes, args.output_dir)

        ok = sum(1 for _, s, _ in results if s)
        logging.info("Signatures applied: %d/%d", ok, len(results))
    finally:
        try:
            primary.close()
            project.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
