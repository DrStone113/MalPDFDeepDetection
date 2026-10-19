"""Windows-side, opt-in source deployment and sanitized LAB report retrieval."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import re
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 3000
REV_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9_.\-/]+\Z")
SOURCE_PREFIXES = ("src/", "scripts/", "tests/", "configs/")
SOURCE_ROOT = {"README.md", "pyproject.toml", "pytest.ini", "setup.cfg", "AGENTS.md"}
SUFFIXES = {".py", ".pyi", ".toml", ".md", ".txt", ".yaml", ".yml", ".json", ".ini", ".cfg", ".sh", ".ps1"}
BLOCK_MAGIC = (b"%PDF-", b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b", b"\x89PNG\r\n\x1a\n")
REPO = Path(__file__).resolve().parents[2]
OUT = Path(tempfile.gettempdir()) / "malpdf-lab-packages"
REPORT_OUT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "MalPDFDeepDetection" / "lab_reports"
ADMIN = "remnux@192.168.217.10"
READ = "remnux-lab-audit"
SSH_SECURITY = ["-a", "-x", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes", "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no"]
ADMIN_SECURITY = [*SSH_SECURITY, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
SCP_SECURITY = ["-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]


def run(args: list[str], *, check=True, capture=False) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, cwd=REPO, text=False, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)


def git(*args: str) -> bytes:
    return run(["git", *args], capture=True).stdout


def revision() -> str:
    rev = git("rev-parse", "HEAD").decode("ascii").strip()
    if not REV_RE.fullmatch(rev):
        raise ValueError("Expected a 40-character SHA-1 Git object ID; unsupported repository hash format")
    return rev


def clean_repo() -> None:
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Windows worktree is not clean. Review and commit source changes before preparing a release")
    if (REPO / "scripts" / "security" / "check_repo_content.py").is_file():
        run([sys.executable, str(REPO / "scripts/security/check_repo_content.py")])


def safe_path(path: str) -> bool:
    p = PurePosixPath(path)
    if not PATH_RE.fullmatch(path) or p.is_absolute() or any(part in ("..", ".", "") for part in path.split("/")):
        return False
    if path.startswith(SOURCE_PREFIXES):
        return p.suffix.lower() in SUFFIXES and all(not part.startswith(".") for part in p.parts)
    return path in SOURCE_ROOT


def source_files(commit: str) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    total = 0
    records = git("ls-tree", "-r", "-z", commit).split(b"\0")
    for record in records:
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split(" ")
        path = name.decode("utf-8", errors="strict")
        if not safe_path(path):
            continue
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"Unsafe Git object type for {path}")
        payload = git("cat-file", "blob", oid)
        if len(payload) > MAX_FILE or payload.startswith(BLOCK_MAGIC) or b"\x00" in payload[:4096] or b"-----BEGIN OPENSSH PRIVATE KEY" in payload:
            raise ValueError(f"Unsafe blob content/size: {path}")
        total += len(payload)
        if total > MAX_TOTAL or len(result) >= MAX_FILES:
            raise ValueError("Release exceeds total byte/file limit")
        result.append((path, payload))
    if not result:
        raise ValueError("Release contained no approved source files")
    return sorted(result)


def prepare() -> tuple[str, Path, Path]:
    clean_repo()
    commit = revision()
    contents = source_files(commit)
    OUT.mkdir(parents=True, exist_ok=True)
    archive = OUT / f"{commit}.tar"
    manifest_path = OUT / f"{commit}.json"
    with tarfile.open(archive, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, payload in contents:
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            info.mtime = 0
            tf.addfile(info, io.BytesIO(payload))
    listing = [{"path": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()} for name, blob in contents]
    data = {"schema_version": 1, "commit": commit, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "files": listing}
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"commit": commit, "file_count": len(listing), "archive": str(archive), "manifest": str(manifest_path)}, indent=2))
    return commit, archive, manifest_path


def ssh_admin(cmd: str) -> None:
    run(["ssh", *ADMIN_SECURITY, ADMIN, cmd])


def deploy() -> None:
    commit, archive, manifest = prepare()
    print(f"\nDeploy reviewed commit {commit} to NEW release directory on {ADMIN}.")
    print("This operation uploads source-only files and executes only AST syntax checking on LAB.")
    confirm = input(f"Type the entire commit SHA to authorize this single deployment: ").strip()
    if confirm != commit:
        raise ValueError("Deployment was NOT approved")
    inbox = "/home/remnux/malpdf-inbox"
    ssh_admin(f"umask 077; mkdir -p {inbox}")
    for path in (archive, manifest):
        run(["scp", *SCP_SECURITY, str(path), f"{ADMIN}:{inbox}/{path.name}"])
    ssh_admin(f"python3 /usr/local/libexec/malpdf/lab_side.py install {commit}")
    ssh_admin(f"python3 /usr/local/libexec/malpdf/lab_side.py syntax {commit}")
    print("LAB source installed and syntax scan requested. Fetch only the sanitized report using the audit key.")


def validate_report(obj: object, expected_rev: str) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("Report must be JSON object")
    required = {"schema_version", "commit", "kind", "status", "file_count", "passed", "failed", "generated_utc", "issues"}
    if set(obj) != required or obj["schema_version"] != 1 or obj["commit"] != expected_rev:
        raise ValueError("Report schema/revision mismatch")
    if obj["kind"] != "ast_syntax" or obj["status"] not in ("passed", "failed"):
        raise ValueError("Unexpected report kind/status")
    for item in ("file_count", "passed", "failed"):
        if type(obj[item]) is not int or not 0 <= obj[item] <= MAX_FILES:
            raise ValueError("Invalid count")
    if obj["passed"] + obj["failed"] != obj["file_count"]:
        raise ValueError("Inconsistent counts")
    if not isinstance(obj["generated_utc"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", obj["generated_utc"]):
        raise ValueError("Unexpected timestamp")
    issues = obj["issues"]
    if not isinstance(issues, list) or len(issues) > 30:
        raise ValueError("Unexpected issue count")
    for issue in issues:
        if not isinstance(issue, dict) or set(issue) != {"path", "line", "kind"}:
            raise ValueError("Invalid issue schema")
        if not isinstance(issue["path"], str) or not safe_path(issue["path"]):
            raise ValueError("Unexpected issue path")
        if type(issue["line"]) is not int or not 0 <= issue["line"] <= 1000000:
            raise ValueError("Unexpected line")
        if issue["kind"] not in ("SyntaxError", "UnicodeError", "FileError", "Oversize"):
            raise ValueError("Unexpected issue type")
    return obj


def report(commit: str, save: bool) -> None:
    if not REV_RE.fullmatch(commit):
        raise ValueError("Invalid commit SHA")
    proc = run(["ssh", *SSH_SECURITY, "-o", "BatchMode=yes", READ, f"report {commit}"], capture=True)
    if len(proc.stdout) > 16384:
        raise ValueError("Audit response exceeds size limit")
    obj = validate_report(json.loads(proc.stdout), commit)
    serialized = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    print(serialized)
    if save:
        REPORT_OUT.mkdir(parents=True, exist_ok=True)
        target = REPORT_OUT / f"{commit}.json"
        target.write_text(serialized, encoding="utf-8")
        print(f"Saved validated report to {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare", help="Package clean, committed, allowlisted source locally")
    sub.add_parser("deploy", help="Manual approval + administrator password; deploy & AST syntax check")
    sub.add_parser("status", help="Use read-only forced-command SSH key")
    p = sub.add_parser("report", help="Fetch only schema-validated JSON from read-only endpoint")
    p.add_argument("commit", help="Full 40-hex Git commit SHA")
    p.add_argument("--save", action="store_true", help="Save sanitized report under ignored artifacts/lab_reports")
    args = parser.parse_args()
    try:
        if args.cmd == "prepare":
            prepare()
        elif args.cmd == "deploy":
            deploy()
        elif args.cmd == "status":
            run(["ssh", *SSH_SECURITY, "-o", "BatchMode=yes", READ, "status"])
        elif args.cmd == "report":
            report(args.commit, args.save)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as exc:
        print(f"labctl error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
