"""Monotone gate over case/profile predicates, not unstable sanitizer log counts."""


def failures(results):
    failed = set()
    for cid, row in results.items():
        for profile in ("normal", "instrumented"):
            current = row[profile]
            if not current["matches_reference"]:
                failed.add((cid, profile, "behavior"))
            for issue in current["issues"]:
                failed.add((cid, profile, issue))
    return failed


def accept_candidate(previous, candidate):
    if set(previous) != set(candidate):
        return False, "case set changed"
    before, after = failures(previous), failures(candidate)
    if after - before:
        return False, "regression: " + repr(sorted(after - before))
    if after == before:
        return False, "no strict improvement"
    return True, "strict improvement without regression"
