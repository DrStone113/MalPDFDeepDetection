"""Check indexed Git content while preserving reviewed legacy research artifacts.

Legacy Parquet files and four historic nonempty .gitkeep placeholders are
accepted only when their index blob identity is unchanged from a trusted
baseline (HEAD locally, protected PR base in CI). New .gitkeep must be empty. This checker is
not a malware scanner, an SSH command firewall, or a substitute for human review.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
from lab_contract import SENSITIVE_NAMES, private_key_failure, text_failure

MAX_BYTES = 8 * 1024 * 1024
MAX_LEGACY_BYTES = 32 * 1024 * 1024
MAX_LEGACY_PLACEHOLDER_BYTES = 4096
BLOCKED_TOP_LEVEL = {"artifacts", "checkpoints", "data", "datasets", "malware", "samples", ".venv"}
BLOCKED_SUFFIXES = {
    ".pdf", ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar",
    ".npy", ".npz", ".pkl", ".pickle", ".joblib", ".pt", ".pth",
    ".ckpt", ".safetensors", ".parquet", ".arrow", ".feather", ".onnx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".msi",
    ".pem", ".p12", ".pfx", ".key", ".ovpn", ".h5", ".hdf5",
}
BLOCKED_NAMES = {".env", ".gitmodules", "id_rsa", "id_ed25519", "authorized_keys"}
BLOCKED_PREFIXES = (b"%PDF-", b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
LEGACY_GITKEEP = {
    "artifacts/.gitkeep",
    "data/external/.gitkeep",
    "data/processed/.gitkeep",
    "data/raw/.gitkeep",
}
LEGACY_PARQUET = {
    "reports/experiments/selective_ensemble/protocol_g_seed42/test_predictions.parquet",
    "reports/experiments/selective_ensemble/protocol_g_seed42/validation_predictions.parquet",
}


def git(*args: str, input_data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", *args], input=input_data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True,
    ).stdout


def indexed_entries() -> list[tuple[str, str, str]]:
    result = []
    for record in git("ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, object_id, stage = meta.decode("ascii").split()
        name = path.decode("utf-8", "surrogateescape")
        if stage != "0":
            raise ValueError(f"Unmerged index entry: {name}")
        result.append((name, mode, object_id))
    return result


def tree_entries(ref: str) -> dict[str, tuple[str, str]]:
    entries = {}
    for record in git("ls-tree", "-rz", "--full-tree", ref).split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, object_id = meta.decode("ascii").split()
        if kind == "blob":
            entries[path.decode("utf-8", "surrogateescape")] = (mode, object_id)
    return entries


def object_sizes(ids: list[str]) -> dict[str, tuple[str, int]]:
    unique = list(dict.fromkeys(ids))
    if not unique:
        return {}
    output = git("cat-file", "--batch-check", input_data=("\n".join(unique) + "\n").encode("ascii"))
    lines = output.decode("ascii").splitlines()
    if len(lines) != len(unique):
        raise RuntimeError("Unexpected Git object count")
    sizes = {}
    for object_id, line in zip(unique, lines):
        oid, kind, count = line.split()
        if oid != object_id:
            raise RuntimeError("Unexpected Git object identity")
        sizes[object_id] = (kind, int(count))
    return sizes


def kind_for_path(name: str, mode: str, oid: str, baseline: dict[str, tuple[str, str]]) -> tuple[str, str | None]:
    p = PurePosixPath(name.replace("\\", "/"))
    normalized = name.replace("\\", "/").casefold()
    parts = normalized.split("/")
    if mode not in {"100644", "100755"}:
        return "reject", "symlink, submodule, or unsupported Git mode"
    if any(part in {".git", ".ssh", "__pycache__"} for part in parts):
        return "reject", "internal Git/SSH material or bytecode cache"
    if p.name.casefold() in BLOCKED_NAMES or (p.name.casefold().startswith(".env.") and p.name.casefold() != ".env.example"):
        return "reject", "credential or private configuration filename"
    if p.stem.casefold() in SENSITIVE_NAMES:
        return "reject", "credential or secret filename"
    if parts[0] in BLOCKED_TOP_LEVEL:
        if p.name == ".gitkeep" and mode == "100644":
            if name in LEGACY_GITKEEP and baseline.get(name) == (mode, oid):
                return "legacy-placeholder", None
            return "placeholder", None
        return "reject", "blocked top-level data/runtime folder"
    if parts[0].startswith(".venv"):
        return "reject", "virtual environment content"
    if name in LEGACY_PARQUET:
        if baseline.get(name) == (mode, oid):
            return "legacy", None
        return "reject", "legacy Parquet changed or absent from trusted baseline; review separately"
    if p.suffix.casefold() == ".png":
        if normalized.startswith("reports/figures/"):
            return "figure", None
        return "reject", "PNG outside reviewed reports/figures directory"
    if p.suffix.casefold() in BLOCKED_SUFFIXES:
        return "reject", "blocked binary, archive, sample, or data extension"
    return "ordinary", None


def content_failure(blob: bytes, kind: str, path: str = "") -> str | None:
    failure = private_key_failure(blob, path)
    if failure:
        return failure
    if kind == "placeholder":
        return None if not blob else "new or modified nonempty .gitkeep"
    if kind == "legacy-placeholder":
        if (b"\x00" in blob or blob.startswith(BLOCKED_PREFIXES)
                or blob.startswith(PNG_SIGNATURE) or any(byte < 32 and byte not in (9, 10, 13) for byte in blob)):
            return "invalid binary content in legacy .gitkeep"
        try:
            blob.decode("utf-8")
        except UnicodeDecodeError:
            return "invalid text encoding in legacy .gitkeep"
        return None
    if kind == "figure":
        return None if blob.startswith(PNG_SIGNATURE) else "PNG file has invalid magic header"
    if kind == "legacy":
        return None if blob.startswith(b"PAR1") and blob.endswith(b"PAR1") else "legacy Parquet magic header invalid"
    return text_failure(blob, path)


def blob_batches(entries: list[tuple[str, str, str]], sizes: dict[str, tuple[str, int]]):
    batch = []
    budget = 0
    for entry in entries:
        size = sizes[entry[2]][1]
        if batch and (budget + size > 16 * 1024 * 1024 or len(batch) >= 128):
            yield batch
            batch, budget = [], 0
        batch.append(entry)
        budget += size
    if batch:
        yield batch


def read_batch(entries: list[tuple[str, str, str]]):
    raw = git("cat-file", "--batch", input_data=("\n".join(oid for _, _, oid in entries) + "\n").encode("ascii"))
    offset = 0
    for name, mode, oid in entries:
        end = raw.index(b"\n", offset)
        actual, kind, size = raw[offset:end].decode("ascii").split()
        if actual != oid or kind != "blob":
            raise ValueError("Unexpected batch object identity")
        offset = end + 1
        length = int(size)
        blob = raw[offset:offset + length]
        offset += length
        if len(blob) != length or raw[offset:offset + 1] != b"\n":
            raise ValueError("Truncated batch blob")
        offset += 1
        yield name, mode, oid, blob
    if offset != len(raw):
        raise ValueError("Unexpected batch trailing bytes")


def worktree_failures(baseline: dict[str, tuple[str, str]]) -> list[str]:
    changed = git("diff", "--name-only", "-z", "--diff-filter=ACMR").split(b"\0")
    changed += git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    failures = []
    object_format = git("rev-parse", "--show-object-format").decode("ascii").strip()
    for encoded in sorted(set(changed) - {b""}):
        name = encoded.decode("utf-8", "strict")
        path = Path(name)
        if path.is_symlink() or not path.is_file():
            failures.append(f"{name}: symlink or unsupported worktree file")
            continue
        if path.stat().st_size > MAX_LEGACY_BYTES:
            failures.append(f"{name}: oversized worktree file")
            continue
        blob = path.read_bytes()
        oid = hashlib.new(object_format, b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob).hexdigest()
        mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        if sys.platform == "win32":
            mode = baseline.get(name, ("100644", ""))[0]
        kind, reason = kind_for_path(name, mode, oid, baseline)
        cap = MAX_LEGACY_PLACEHOLDER_BYTES if kind in ("legacy-placeholder", "placeholder") else MAX_LEGACY_BYTES if kind == "legacy" else MAX_BYTES
        reason = reason or ("exceeds size limit" if len(blob) > cap else content_failure(blob, kind, name))
        if reason:
            failures.append(f"{name}: {reason}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="HEAD", help="Trusted baseline commit (PR base SHA in CI; HEAD locally)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--revision", help="Validate a committed tree instead of the index")
    group.add_argument("--worktree", action="store_true", help="Also validate modified and untracked nonignored files")
    args = parser.parse_args()
    issues = []
    try:
        baseline = tree_entries(args.baseline_ref)
        if args.revision:
            if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
                raise ValueError("--revision requires a full commit SHA")
            entries = [(name, mode, oid) for name, (mode, oid) in tree_entries(args.revision).items()]
            modes = git("ls-tree", "-rz", args.revision)
            if any(record.startswith((b"120000 ", b"160000 ")) for record in modes.split(b"\0")):
                raise ValueError("Committed tree contains a symlink or submodule")
        else:
            entries = indexed_entries()
        sizes = object_sizes([object_id for _, _, object_id in entries])
        readable = []
        for name, mode, object_id in entries:
            kind, reason = kind_for_path(name, mode, object_id, baseline)
            if reason:
                issues.append(f"{name}: {reason}")
                continue
            object_kind, size = sizes[object_id]
            cap = (MAX_LEGACY_PLACEHOLDER_BYTES if kind in ("legacy-placeholder", "placeholder")
                   else MAX_LEGACY_BYTES if kind == "legacy" else MAX_BYTES)
            if object_kind != "blob":
                issues.append(f"{name}: unsupported Git object type ({object_kind})")
            elif size > cap:
                issues.append(f"{name}: exceeds allowed {cap} bytes")
            else:
                readable.append((name, mode, object_id))
        for batch in blob_batches(readable, sizes):
            for name, mode, object_id, blob in read_batch(batch):
                kind, _ = kind_for_path(name, mode, object_id, baseline)
                failure = content_failure(blob, kind, name)
                if failure:
                    issues.append(f"{name}: {failure}")
        if args.worktree:
            issues.extend(worktree_failures(baseline))
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as exc:
        print(f"Security gate could not complete: {exc}", file=sys.stderr)
        return 2
    if issues:
        print("Rejected indexed repository content:", file=sys.stderr)
        for issue in issues[:60]:
            print(f"  - {issue}", file=sys.stderr)
        if len(issues) > 60:
            print(f"  ... and {len(issues) - 60} more", file=sys.stderr)
        return 1
    scope = "commit " + args.revision if args.revision else "index + worktree" if args.worktree else "tracked index"
    print(f"Repository content gate passed: {len(entries)} {scope} files checked against {args.baseline_ref}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
