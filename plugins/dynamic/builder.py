"""Separate normal and ASan+UBSan builds, never run helper generation mid-loop."""
import re
import shlex
from pathlib import Path

from .config import relative_name
from .runner import remaining_timeout, run_process
from .workspace import write_json


def resolve_build(config, inventory):
    build = config["build"]
    sources = build["sources"]
    if sources is None:
        makefile = Path(config["target"]["source_dir"]) / "Makefile"
        if makefile.exists():
            match = re.search(r"^SRCS\s*=\s*(.+)$", makefile.read_text(), re.M)
            if not match or "$" in match[1] or "\\" in match[1]:
                raise ValueError("set build.sources explicitly for this Makefile")
            sources = shlex.split(match[1])
        else:
            sources = sorted(name for name in inventory if name.endswith(".c"))
    includes = build["force_include"]
    if includes is None:
        includes = [name for name in ("ghidra_types.h", "compat.h", "function_prototypes.h", "globals.h") if name in inventory]
    if not sources:
        raise ValueError("no compilation units")
    for name in sources + includes:
        relative_name(name)
        if name not in inventory:
            raise ValueError("build input not present in source snapshot: " + name)
    build["sources"], build["force_include"] = sources, includes


def compile_profiles(source, output, config):
    builds = {}
    build = config["build"]
    for profile in ("normal", "instrumented"):
        directory = output / profile
        directory.mkdir(parents=True)
        binary = directory / "program"
        argv = [build["compiler"], "-std=gnu11", "-O1", "-g", "-I."]
        if profile == "instrumented":
            # Fixed, enabled at compile AND link; non-PIE avoids ASan shadow collisions.
            argv += ["-fno-omit-frame-pointer", "-fsanitize=address,undefined",
                     "-fno-sanitize-recover=all", "-fno-pie", "-no-pie"]
        for header in build["force_include"]:
            argv += ["-include", header]
        argv += ["./" + name for name in build["sources"]] + ["-o", str(binary)] + ["-l" + lib for lib in build["libraries"]]
        result = run_process(argv, source, remaining_timeout(config, build["timeout_seconds"]), 1048576)
        result.update(argv=argv, binary=str(binary))
        result["ok"] = result["state"] == "exited" and result["exit_code"] == 0 and binary.is_file()
        builds[profile] = result
        write_json(directory / "build.json", result)
    return builds
