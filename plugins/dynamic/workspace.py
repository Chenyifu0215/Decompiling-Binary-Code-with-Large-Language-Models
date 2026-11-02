"""Snapshot inputs, apply source-only patches, and retain auditable evidence."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .config import relative_name


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, data):
    path = Path(path)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def snapshot(source, destination):
    destination.mkdir(parents=True)
    hashes = {}
    total = 0
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("source symlinks are not supported: " + str(path))
        if not path.is_file() or path.suffix not in (".c", ".h"):
            continue
        relative = path.relative_to(source).as_posix()
        relative_name(relative)
        total += path.stat().st_size
        if total > 8 * 1024 * 1024:
            raise ValueError("source snapshot exceeds V1 8 MiB limit")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        hashes[relative] = digest(target)
    if not hashes:
        raise ValueError("no C sources or headers in source_dir")
    return hashes


def apply_candidate(root, patches, allowed, max_files):
    if not isinstance(patches, list) or not 1 <= len(patches) <= 32:
        raise ValueError("expected 1..32 exact replacement patches")
    changes, originals = {}, {}
    # Validate and calculate every replacement before touching any file.
    for p in patches:
        if not isinstance(p, dict) or set(p) - {"op", "file", "old", "new", "count"}:
            raise ValueError("invalid patch object")
        name = relative_name(p.get("file"))
        if name not in allowed or Path(name).suffix not in (".c", ".h"):
            raise ValueError("patch file is not in source allowlist: " + name)
        path = root / name
        if path.is_symlink() or root.resolve() not in path.resolve().parents:
            raise ValueError("patch target escapes source snapshot")
        if p.get("op") != "replace" or p.get("count", 1) != 1:
            raise ValueError("V1 accepts only unique exact replace patches (count=1)")
        old, new = p.get("old"), p.get("new")
        if not isinstance(old, str) or not old or not isinstance(new, str) or max(len(old), len(new)) > 32000:
            raise ValueError("invalid or oversized replacement")
        original = originals.setdefault(name, path.read_text(encoding="utf-8"))
        text = changes.get(name, original)
        if text.count(old) != 1 or old == new:
            raise ValueError("replace target must occur exactly once and change the source")
        changes[name] = text.replace(old, new, 1)
    if len(changes) > max_files or all(text == originals[name] for name, text in changes.items()):
        raise ValueError("too many files or no effective changes")
    diff = []
    for name, text in changes.items():
        diff.extend(difflib.unified_diff(originals[name].splitlines(True), text.splitlines(True),
                                        fromfile="before/" + name, tofile="after/" + name))
        (root / name).write_text(text, encoding="utf-8")
    return "".join(diff)
