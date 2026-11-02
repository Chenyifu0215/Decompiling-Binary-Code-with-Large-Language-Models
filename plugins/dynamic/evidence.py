"""Only repair cases and candidate sources enter proposal context."""
from .runner import decode


def preview(value):
    """Bound test/oracle context too, and make omissions explicit to the model."""
    if isinstance(value, str) and len(value) > 2000:
        return {"preview": value[:2000], "truncated": True, "original_chars": len(value)}
    if isinstance(value, list):
        values = [preview(item) for item in value[:32]]
        return values if len(value) <= 32 else {"preview": values, "truncated": True}
    if isinstance(value, dict):
        values = {key: preview(item) for key, item in list(value.items())[:32]}
        return values if len(value) <= 32 else {"preview": values, "truncated": True}
    return value


def make_evidence(source, inventory, cases, expected, results):
    failed = {cid: row for cid, row in results.items() if not row["passed"]}
    evidence = {"failures": {}, "sources": {}, "allowed_files": sorted(inventory)}
    case_map = {c["id"]: c for c in cases}
    for cid, row in list(failed.items())[:8]:
        evidence["failures"][cid] = {
            "input": preview(case_map[cid]), "expected": preview(expected[cid]),
            "observed": {profile: {"issues": row[profile]["issues"],
                                  "stdout": decode(row[profile]["result"]["stdout"]).decode("utf-8", "replace")[:2000],
                                  "stderr": decode(row[profile]["result"]["stderr"]).decode("utf-8", "replace")[:6000],
                                  "exit_code": row[profile]["result"]["exit_code"]}
                         for profile in ("normal", "instrumented")},
        }
    # Prefer files named by diagnostics before filling remaining source context.
    diagnostic = str(evidence["failures"])
    names = sorted(inventory, key=lambda n: (n not in diagnostic, not n.endswith(".c"), n))
    remaining = 20000
    for name in names:
        if remaining <= 0:
            break
        text = (source / name).read_text(encoding="utf-8", errors="replace")
        snippet = text[:remaining]
        evidence["sources"][name] = {"text": snippet, "truncated": len(text) > len(snippet)}
        remaining -= len(snippet)
    return evidence
