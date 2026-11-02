"""Reference outputs are collected repeatedly; held-out cases enter only at the end."""
from .diagnostics import behavior, diagnose
from .runner import run_case


def collect_reference(binary, cases, config):
    expected, records = {}, {}
    for case in cases:
        runs = [run_case(binary, case, config) for _ in range(config["execution"]["reference_repeats"])]
        records[case["id"]] = runs
        if any(diagnose(r, instrumented=False) for r in runs):
            raise ValueError("reference failed, timed out or exceeded limits: " + case["id"])
        outputs = [behavior(r, config["execution"]["compare_stderr"]) for r in runs]
        if any(r != outputs[0] for r in outputs[1:]):
            raise ValueError("reference is nondeterministic on case: " + case["id"])
        expected[case["id"]] = outputs[0]
    return expected, records


def evaluate(builds, cases, expected, config):
    results = {}
    for case in cases:
        cid = case["id"]
        row = {}
        for profile in ("normal", "instrumented"):
            result = run_case(builds[profile]["binary"], case, config, profile == "instrumented")
            issues = diagnose(result, instrumented=profile == "instrumented")
            matched = behavior(result, config["execution"]["compare_stderr"]) == expected[cid]
            row[profile] = {"result": result, "issues": issues, "matches_reference": matched}
        row["passed"] = all(r["matches_reference"] and not r["issues"] for r in row.values())
        results[cid] = row
    return results
