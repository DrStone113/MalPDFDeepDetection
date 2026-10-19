"""REMnux-side root-installed, run-as-remnux release verifier and AST smoke check."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile

INBOX = Path("/home/remnux/malpdf-inbox")
RELEASES = Path("/home/remnux/malpdf-releases")
REPORTS = Path("/var/lib/malpdf/reports/approved")
REV = re.compile(r"[0-9a-f]{40}\Z")
PATH = re.compile(r"[A-Za-z0-9_.\-/]+\Z")
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 3000
BLOCK_MAGIC = (b"%PDF-", b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b", b"\x89PNG\r\n\x1a\n")


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def valid_path(name: str) -> bool:
    p = PurePosixPath(name)
    if not PATH.fullmatch(name) or p.is_absolute() or any(part in ("..", ".", "") for part in name.split("/")):
        return False
    if name in ("README.md", "pyproject.toml", "pytest.ini", "setup.cfg", "AGENTS.md"):
        return True
    if not name.startswith(("src/", "scripts/", "tests/", "configs/")):
        return False
    return all(not part.startswith(".") for part in p.parts) and p.suffix.lower() in {".py", ".pyi", ".toml", ".md", ".txt", ".yaml", ".yml", ".json", ".ini", ".cfg", ".sh", ".ps1"}


def install(commit: str) -> None:
    archive = INBOX / f"{commit}.tar"
    manifest = INBOX / f"{commit}.json"
    if not archive.is_file() or not manifest.is_file() or archive.stat().st_size > 40 * 1024 * 1024 or manifest.stat().st_size > 512 * 1024:
        raise ValueError("Missing or oversized upload")
    meta = json.loads(manifest.read_text(encoding="utf-8"))
    if set(meta) != {"schema_version", "commit", "archive_sha256", "files"} or meta["schema_version"] != 1 or meta["commit"] != commit:
        raise ValueError("Invalid release manifest")
    if not isinstance(meta["files"], list) or not 0 < len(meta["files"]) <= MAX_FILES:
        raise ValueError("Invalid file count")
    if digest(archive.read_bytes()) != meta["archive_sha256"]:
        raise ValueError("Archive SHA-256 mismatch")
    expected = {}
    total = 0
    for item in meta["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise ValueError("Invalid file manifest entry")
        name, size, sha = item["path"], item["size"], item["sha256"]
        if not isinstance(name, str) or not valid_path(name) or name in expected:
            raise ValueError("Unsafe or duplicate release file")
        if type(size) is not int or not 0 <= size <= MAX_FILE or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("Invalid file checksum/size")
        expected[name] = (size, sha)
        total += size
    if total > MAX_TOTAL:
        raise ValueError("Release exceeds size limit")
    RELEASES.mkdir(parents=True, exist_ok=True)
    target = RELEASES / commit
    if target.exists() or target.is_symlink():
        raise ValueError("Release already exists; refusing overwrite")
    scratch = Path(tempfile.mkdtemp(prefix="staging-", dir=RELEASES))
    try:
        actual = set()
        with tarfile.open(archive, "r:") as tf:
            members = tf.getmembers()
            if len(members) != len(expected):
                raise ValueError("Unexpected TAR entry count")
            for member in members:
                if not member.isfile() or not valid_path(member.name) or member.name in actual or member.name not in expected:
                    raise ValueError("Unsafe TAR member")
                size, sha = expected[member.name]
                if member.size != size:
                    raise ValueError("TAR member size mismatch")
                stream = tf.extractfile(member)
                if stream is None:
                    raise ValueError("Missing member bytes")
                payload = stream.read(MAX_FILE + 1)
                if len(payload) != size or digest(payload) != sha:
                    raise ValueError("TAR member checksum mismatch")
                if payload.startswith(BLOCK_MAGIC) or b"\x00" in payload[:4096] or b"-----BEGIN OPENSSH PRIVATE KEY" in payload:
                    raise ValueError("Forbidden binary or credential content")
                output = scratch / member.name
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("xb") as f:
                    f.write(payload)
                output.chmod(0o644)
                actual.add(member.name)
        if actual != set(expected):
            raise ValueError("Missing files")
        scratch.rename(target)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
    print(json.dumps({"installed": True, "commit": commit, "file_count": len(expected)}))


def syntax(commit: str) -> None:
    folder = RELEASES / commit
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Unknown release")
    pyfiles = sorted(folder.rglob("*.py"))
    if len(pyfiles) > MAX_FILES:
        raise ValueError("Too many Python files")
    issues = []
    passed = failed = 0
    for p in pyfiles:
        relative = p.relative_to(folder).as_posix()
        if not valid_path(relative):
            raise ValueError("Invalid source path")
        line = 0
        kind = ""
        try:
            if p.is_symlink() or p.stat().st_size > MAX_FILE:
                kind = "Oversize"
            else:
                ast.parse(p.read_text(encoding="utf-8"), filename=relative)
        except SyntaxError as exc:
            kind, line = "SyntaxError", int(exc.lineno or 0)
        except UnicodeError:
            kind = "UnicodeError"
        except OSError:
            kind = "FileError"
        if kind:
            failed += 1
            if len(issues) < 30:
                issues.append({"path": relative, "line": line, "kind": kind})
        else:
            passed += 1
    data = {"schema_version": 1, "commit": commit, "kind": "ast_syntax", "status": "passed" if failed == 0 else "failed", "file_count": passed + failed, "passed": passed, "failed": failed, "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "issues": issues}
    REPORTS.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="result-", suffix=".json", dir=REPORTS)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
            f.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, REPORTS / f"{commit}.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(json.dumps({"report_ready": True, "commit": commit, "kind": "ast_syntax", "status": data["status"], "failed": failed}))


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("install", "syntax") or not REV.fullmatch(sys.argv[2]):
        print("Usage: lab_side.py {install|syntax} <full-commit-sha>", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "install":
            install(sys.argv[2])
        else:
            syntax(sys.argv[2])
        return 0
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f"LAB operation refused: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
