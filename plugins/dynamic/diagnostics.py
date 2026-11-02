"""Diagnostic categories, without conflating exit success and behavior agreement."""
import re

from .runner import decode


def diagnose(result, instrumented=True):
    text = decode(result["stderr"]).decode("utf-8", "replace")
    issues = []
    if result["state"] != "exited":
        issues.append(result["state"])
    if result["exit_code"] is not None and result["exit_code"] < 0:
        issues.append("signal:" + str(-result["exit_code"]))
    if not instrumented:
        return sorted(set(issues))
    matches = re.findall(r"(?:ERROR|SUMMARY): (?:AddressSanitizer|LeakSanitizer):\s*([^\s:]+)", text)
    issues.extend("sanitizer:" + m for m in matches)
    if re.search(r"(?m)^.*?:\d+(?::\d+)?: runtime error:", text):
        issues.append("sanitizer:undefined-behavior")
    if "AddressSanitizer:DEADLYSIGNAL" in text:
        issues.append("sanitizer:deadly-signal")
    if (re.search(r"(?:Address|Leak|UndefinedBehavior)Sanitizer:|(?m:^==\d+==.*Sanitizer)", text)
            and not any(s.startswith("sanitizer:") for s in issues)):
        issues.append("sanitizer:runtime-error")
    return sorted(set(issues))


def behavior(result, compare_stderr=False):
    keys = ["state", "exit_code", "stdout", "output_files"]
    if compare_stderr:
        keys.append("stderr")
    return {k: result[k] for k in keys}
