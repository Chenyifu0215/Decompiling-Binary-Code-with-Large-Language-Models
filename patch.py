#!/usr/bin/env python3
"""patch.py - Apply a persistent, replayable list of source patches.

Patch list is a JSON array. Two primitive ops:

    {"op": "replace", "file": "apply_op.c",
     "old": "auVar3._8_8_ = param_3;",
     "new": "*(undefined8 *)((char *)auVar3 + 8) = param_3;"}

    {"op": "regex", "file": "apply_op.c",
     "pattern": "(\\b\\w+)\\._(\\d+)_(\\d+)_",
     "repl": "*(undefined\\3 *)((char *)\\1 + \\2)", "count": 0}

`count` for regex defaults to 0 (= replace all). Patches are applied in order
and persisted so a run can be replayed from a clean base deterministically.
"""

import json
import re
from pathlib import Path


def apply_patch_list(build_dir, patches):
    """Apply `patches` to files under `build_dir`. Returns (applied, errors)."""
    applied = 0
    errors = []
    for patch in patches:
        op = patch.get("op")
        fname = patch.get("file")
        if not op or not fname:
            errors.append("invalid patch (missing op/file): %s" % patch)
            continue

        path = Path(build_dir) / fname
        if not path.is_file():
            errors.append("%s: file not found" % fname)
            continue

        text = path.read_text(encoding="utf-8", errors="replace")

        if op == "replace":
            old, new = patch.get("old", ""), patch.get("new", "")
            if not old:
                errors.append("%s: replace op requires non-empty 'old'" % fname)
                continue
            if old not in text:
                errors.append("%s: replace target not found" % fname)
                continue
            count = patch.get("count", 0)
            text = text.replace(old, new, -1 if count == 0 else count)

        elif op == "regex":
            pattern = patch.get("pattern", "")
            repl = patch.get("repl", "")
            count = patch.get("count", 0)
            new_text, n = re.subn(pattern, repl, text, count=count)
            if n == 0:
                errors.append("%s: regex did not match" % fname)
                continue
            text = new_text

        else:
            errors.append("unknown patch op: %r" % op)
            continue

        path.write_text(text, encoding="utf-8")
        applied += 1

    return applied, errors


def load_patches(path):
    p = Path(path)
    if p.is_file():
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    return []


def save_patches(path, patches):
    Path(path).write_text(
        json.dumps(patches, indent=2, ensure_ascii=False), encoding="utf-8"
    )
