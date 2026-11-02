"""Versioned configuration and test manifests. Paths are relative to each manifest."""
import json
import re
from pathlib import Path, PurePosixPath

import yaml


def relative_name(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value or value == ".":
        raise ValueError("expected a nonempty portable relative path")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or ":" in value or str(p) != value:
        raise ValueError("unsafe relative path: " + value)
    return value


def positive(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(name + " must be a positive integer")
    return value


def load_config(path):
    path = Path(path).resolve()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError("invalid YAML: " + str(exc)) from exc
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise ValueError("configuration requires schema_version: 1")
    allowed = {"schema_version", "project_id", "target", "build", "execution", "tests", "repair", "artifacts"}
    if set(raw) - allowed:
        raise ValueError("unknown configuration sections: " + str(set(raw) - allowed))
    defaults = {
        "target": {"source_dir": None, "reference_binary": None},
        "build": {"compiler": "gcc", "sources": None, "force_include": None, "libraries": ["m"], "timeout_seconds": 60},
        "execution": {"timeout_seconds": 3, "instrumented_timeout_seconds": 10,
                      "max_output_bytes": 1048576, "reference_repeats": 2,
                      "compare_stderr": False, "environment": {}},
        "tests": {"repair_manifest": None},
        "repair": {"proposer": "none", "replay_file": None, "max_attempts": 10,
                   "max_no_progress": 3, "max_llm_calls": 10, "max_total_tokens": 30000,
                   "max_completion_tokens": 2000, "max_files_per_patch": 3,
                   "max_total_seconds": 600},
        "artifacts": {"output_dir": "runs", "keep_rejected_candidates": False},
    }
    c = {"schema_version": 1, "project_id": str(raw.get("project_id", path.stem))}
    for section, default in defaults.items():
        supplied = raw.get(section, {})
        if not isinstance(supplied, dict) or set(supplied) - set(default):
            raise ValueError("unknown or invalid settings in " + section)
        c[section] = default | supplied
    for section, keys in {"target": ["source_dir", "reference_binary"], "tests": ["repair_manifest"],
                          "repair": ["replay_file"], "artifacts": ["output_dir"]}.items():
        for key in keys:
            value = c[section][key]
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise ValueError(section + "." + key + " must be a path")
                c[section][key] = str((path.parent / value).resolve())
    if not c["target"]["source_dir"]:
        raise ValueError("target.source_dir is required")
    if not c["artifacts"]["output_dir"]:
        raise ValueError("artifacts.output_dir must be a path")
    source, output = Path(c["target"]["source_dir"]), Path(c["artifacts"]["output_dir"])
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("source_dir and output_dir must not overlap")
    if not source.is_dir():
        raise ValueError("source_dir does not exist")
    for key in ("sources", "force_include"):
        values = c["build"][key]
        if values is not None:
            if not isinstance(values, list) or not values:
                # Empty force_include is useful for plain C projects.
                if values != [] or key != "force_include":
                    raise ValueError("build." + key + " must be a nonempty list")
            for value in values:
                relative_name(value)
    if not isinstance(c["build"]["compiler"], str) or not c["build"]["compiler"]:
        raise ValueError("build.compiler must be an executable name/path")
    libs = c["build"]["libraries"]
    if not isinstance(libs, list) or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_+.-]+", v) for v in libs):
        raise ValueError("build.libraries must contain library names")
    for section in ("build", "execution", "repair"):
        for key, value in c[section].items():
            if key.startswith("max_") or key.endswith("seconds") or key == "reference_repeats":
                positive(value, section + "." + key)
    if c["execution"]["reference_repeats"] < 2:
        raise ValueError("reference_repeats must be >= 2")
    for section, key in (("execution", "compare_stderr"), ("artifacts", "keep_rejected_candidates")):
        if not isinstance(c[section][key], bool):
            raise ValueError(section + "." + key + " must be boolean")
    env = c["execution"]["environment"]
    if not isinstance(env, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str) or "=" in k or "\0" in k + v for k, v in env.items()):
        raise ValueError("execution.environment must map names to strings")
    if any(k.startswith(("ASAN_", "UBSAN_", "LSAN_", "LD_")) for k in env):
        raise ValueError("sanitizer and loader overrides are not allowed")
    if c["repair"]["proposer"] not in ("none", "replay", "llm"):
        raise ValueError("repair.proposer must be none, replay or llm")
    if c["repair"]["proposer"] == "replay" and not c["repair"]["replay_file"]:
        raise ValueError("replay requires repair.replay_file")
    return c


def load_cases(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema_version", "cases"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("test manifest requires schema_version: 1 and cases")
    if not isinstance(data["cases"], list) or not data["cases"]:
        raise ValueError("test manifest must contain cases")
    cases, ids = [], set()
    for item in data["cases"]:
        if not isinstance(item, dict) or set(item) - {"id", "args", "stdin", "files", "output_files"}:
            raise ValueError("invalid test case fields")
        case = {"args": [], "stdin": "", "files": {}, "output_files": []} | item
        cid = case.get("id")
        if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", cid) or cid in ids:
            raise ValueError("case IDs must be unique portable identifiers")
        ids.add(cid)
        if not isinstance(case["args"], list) or any(not isinstance(x, str) or "\0" in x for x in case["args"]):
            raise ValueError("args must be strings without NUL")
        if not isinstance(case["stdin"], str) or not isinstance(case["files"], dict) or not isinstance(case["output_files"], list):
            raise ValueError("stdin/files/output_files have invalid types")
        for name, content in case["files"].items():
            relative_name(name)
            if not isinstance(content, str):
                raise ValueError("input files must have UTF-8 text content")
        for name in case["output_files"]:
            relative_name(name)
        cases.append(case)
    return cases
