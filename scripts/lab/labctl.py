"""Windows source packaging and bounded, schema-validated audit inspection."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading

from lab_contract import MAX_FILE, MAX_FILES, MAX_TOTAL, MAX_REPORT, REV_RE, parse_json, safe_path, text_failure, validate_public_key, validate_report, validate_status

REPO = Path(__file__).resolve().parents[2]
OUT = Path(tempfile.gettempdir()) / "malpdf-lab-packages"
REPORT_OUT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "MalPDFDeepDetection" / "lab_reports"
ADMIN = "remnux@192.168.217.10"
READ = "remnux-lab-audit"
PUBLIC_KEY = Path.home() / ".ssh/id_ed25519_malpdf_audit.pub"
BOOTSTRAP_FILES = ("lab_contract.py", "lab_readonly.py", "lab_side.py", "setup_readonly.sh")
SSH = str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/OpenSSH/ssh.exe") if os.name == "nt" else "ssh"
SSH_SECURITY = ["-F", "none", "-a", "-x", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "StrictHostKeyChecking=yes", "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no", "-o", "ControlMaster=no", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1"]
AUDIT_SECURITY = [*SSH_SECURITY, "-o", "HostName=192.168.217.10", "-o", "User=malpdf-audit", "-o", "Port=22", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-i", str(Path.home() / ".ssh/id_ed25519_malpdf_audit")]
ADMIN_SECURITY = [*SSH_SECURITY, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
SCP_SECURITY = ["-F", "none", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "StrictHostKeyChecking=yes", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ConnectTimeout=5", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]


def run(args: list[str], *, check=True, capture=False, input_data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_data, check=check, cwd=REPO, text=False, timeout=120, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)


def git(*args: str, input_data: bytes | None = None) -> bytes:
    return run(["git", *args], capture=True, input_data=input_data).stdout


def revision(ref: str = "HEAD") -> str:
    rev = git("rev-parse", "--verify", ref + "^{commit}").decode("ascii").strip()
    if not REV_RE.fullmatch(rev):
        raise ValueError("Expected a full SHA-1 Git commit")
    return rev


def clean_repo() -> None:
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Windows worktree is not clean. Review and commit changes before preparing HEAD")


def source_files(commit: str) -> list[tuple[str, bytes]]:
    if not REV_RE.fullmatch(commit):
        raise ValueError("Expected full commit SHA")
    result = []
    total = 0
    objects = []
    for record in git("ls-tree", "-r", "-l", "-z", commit).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid, count = meta.decode("ascii").split()
        path = name.decode("utf-8", errors="strict")
        if not safe_path(path):
            continue
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"Unsafe Git object type: {path}")
        size = int(count)
        if size > MAX_FILE or total + size > MAX_TOTAL or len(objects) >= MAX_FILES:
            raise ValueError(f"Release size/count limit: {path}")
        total += size
        objects.append((path, oid, size))
    if not objects:
        raise ValueError("Release contained no approved source files")
    raw = git("cat-file", "--batch", input_data=("\n".join(oid for _, oid, _ in objects) + "\n").encode("ascii"))
    offset = 0
    for path, oid, size in objects:
        end = raw.index(b"\n", offset)
        actual, kind, count = raw[offset:end].decode("ascii").split()
        if actual != oid or kind != "blob" or int(count) != size:
            raise ValueError("Unexpected Git batch object identity/size")
        offset = end + 1
        payload = raw[offset:offset + size]
        offset += size
        if raw[offset:offset + 1] != b"\n":
            raise ValueError("Truncated Git batch object")
        offset += 1
        failure = text_failure(payload, path)
        if len(payload) != size or failure:
            raise ValueError(f"Unsafe blob content/size: {path}: {failure or 'size mismatch'}")
        result.append((path, payload))
    if offset != len(raw):
        raise ValueError("Unexpected Git batch trailing bytes")
    return sorted(result)


def prepare(commit: str | None = None) -> tuple[str, Path, Path]:
    if commit is None:
        clean_repo()
        commit = revision()
    elif not REV_RE.fullmatch(commit) or revision(commit) != commit:
        raise ValueError("--commit requires an existing full commit SHA")
    checker = REPO / "scripts/security/check_repo_content.py"
    if not checker.is_file() or checker.is_symlink():
        raise ValueError("Mandatory repository content guard is missing or symlinked")
    run([sys.executable, str(checker), "--revision", commit], capture=True)
    contents = source_files(commit)
    OUT.mkdir(parents=True, exist_ok=True)
    archive = OUT / f"{commit}.tar"
    manifest_path = OUT / f"{commit}.json"
    with tempfile.TemporaryDirectory(prefix="package-", dir=OUT) as temporary:
        staged = Path(temporary) / "source.tar"
        with tarfile.open(staged, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name, payload in contents:
                info = tarfile.TarInfo(name=name)
                info.size = len(payload)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                info.mtime = 0
                tf.addfile(info, io.BytesIO(payload))
        data = {"schema_version": 1, "commit": commit, "archive_sha256": hashlib.sha256(staged.read_bytes()).hexdigest(), "files": [{"path": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()} for name, blob in contents]}
        serialized = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(serialized) > 512 * 1024 or staged.stat().st_size > 40 * 1024 * 1024:
            raise ValueError("Package exceeds LAB manifest/archive limits")
        for target, payload in ((archive, staged.read_bytes()), (manifest_path, serialized)):
            if target.is_symlink() or (target.exists() and target.read_bytes() != payload):
                raise ValueError("Existing package differs; refusing overwrite")
        for target, payload in ((archive, staged.read_bytes()), (manifest_path, serialized)):
            if not target.exists():
                with target.open("xb") as stream:
                    stream.write(payload)
    print(json.dumps({"commit": commit, "file_count": len(contents), "archive_sha256": data["archive_sha256"], "archive": str(archive), "manifest": str(manifest_path), "source": "git_commit_only", "working_changes_included": False}, indent=2))
    return commit, archive, manifest_path


def ssh_admin(command: str) -> None:
    run([SSH, *ADMIN_SECURITY, ADMIN, command])


def bootstrap(commit: str | None = None) -> Path:
    commit, _, _ = prepare(commit)
    if PUBLIC_KEY.is_symlink() or not PUBLIC_KEY.is_file() or PUBLIC_KEY.stat().st_size > 1024:
        raise ValueError("Missing or invalid audit public key file")
    public = (validate_public_key(PUBLIC_KEY.read_bytes()) + "\n").encode("ascii")
    contents = dict(source_files(commit))
    files = {}
    for name in BOOTSTRAP_FILES:
        source = "scripts/lab/" + name
        if source not in contents:
            raise ValueError("Commit lacks the complete reviewed bootstrap")
        files[name] = contents[source]
    files["id_ed25519_malpdf_audit.pub"] = public
    metadata = {"schema_version": 1, "commit": commit, "files": [{"path": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()} for name, blob in sorted(files.items())]}
    files["manifest.json"] = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
    target = OUT / "bootstrap" / commit
    if target.is_symlink():
        raise ValueError("Refusing symlinked bootstrap directory")
    target.mkdir(parents=True, exist_ok=True)
    if set(path.name for path in target.iterdir()) - set(files):
        raise ValueError("Unexpected existing bootstrap files")
    for name, payload in files.items():
        path = target / name
        if path.is_symlink() or (path.exists() and (path.stat().st_size != len(payload) or path.read_bytes() != payload)):
            raise ValueError("Existing bootstrap differs; refusing overwrite")
    for name, payload in files.items():
        path = target / name
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(payload)
    print(json.dumps({"bootstrap": str(target), "commit": commit, "file_count": len(files), "remote_changes": False}, indent=2))
    return target


def deploy() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("Operator-only deployment requires a supervised interactive terminal")
    commit, archive, manifest = prepare()
    print(f"Deploy reviewed commit {commit} to a NEW release on {ADMIN}.")
    print("Uploads source only; the default LAB check parses AST without executing source.")
    if input("Type the entire commit SHA to approve this deployment: ").strip() != commit:
        raise ValueError("Deployment was not approved")
    inbox = "/home/remnux/malpdf-inbox"
    ssh_admin(f"umask 077; mkdir -p {inbox}")
    for path in (archive, manifest):
        run(["scp", *SCP_SECURITY, str(path), f"{ADMIN}:{inbox}/{path.name}"])
    ssh_admin(f"python3 -Es /usr/local/libexec/malpdf/lab_side.py install {commit}")
    ssh_admin(f"python3 -Es /usr/local/libexec/malpdf/lab_side.py syntax {commit}")
    print("Fetch only the sanitized report using the audit key after transfer approval.")


def audit_request(command: str) -> tuple[int, bytes]:
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    with subprocess.Popen([SSH, *AUDIT_SECURITY, READ, command], cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        def drain(pipe, bucket):
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                if len(bucket) + len(chunk) > MAX_REPORT:
                    exceeded.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                bucket.extend(chunk)
        readers = [threading.Thread(target=drain, args=(pipe, bucket), daemon=True) for pipe, bucket in zip((process.stdout, process.stderr), buffers)]
        for reader in readers:
            reader.start()
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise ValueError("Audit SSH timed out; isolation and networking were not changed") from None
        for reader in readers:
            reader.join(timeout=2)
        if exceeded.is_set() or any(reader.is_alive() for reader in readers):
            raise ValueError("Audit response exceeded resource limits")
    return code, bytes(buffers[0])


def status() -> None:
    code, payload = audit_request("status")
    if code != 0:
        raise ValueError(f"Audit SSH unavailable (exit {code}); no remote stderr displayed")
    print(json.dumps(validate_status(parse_json(payload)), sort_keys=True))


def audit_check() -> None:
    status()
    for label, command in (("non_allowlisted_command", "id"), ("empty_shell_request", "")):
        code, payload = audit_request(command)
        if code != 2 or payload.strip():
            raise ValueError(f"Audit restriction NOT VERIFIED: {label}")
        print(f"PASS: {label} refused with exit 2")
    print("NOT VERIFIED: server forwarding, sudo policy and filesystem permissions require operator checks")


def report(commit: str, save: bool) -> None:
    if not REV_RE.fullmatch(commit):
        raise ValueError("Invalid commit SHA")
    code, payload = audit_request(f"report {commit}")
    if code != 0:
        raise ValueError(f"Audit report unavailable (exit {code}); no remote stderr displayed")
    obj = validate_report(parse_json(payload), commit)
    serialized = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    print(serialized)
    if save:
        REPORT_OUT.mkdir(parents=True, exist_ok=True)
        identity = obj.get("run_id", obj["generated_utc"].replace(":", ""))
        target = REPORT_OUT / f"{commit}_{identity}.json"
        if target.is_symlink() or (target.exists() and target.read_text(encoding="utf-8") != serialized):
            raise ValueError("Refusing to replace a saved report")
        if not target.exists():
            with target.open("x", encoding="utf-8") as stream:
                stream.write(serialized)
        print(f"Saved validated report to {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare", help="Package committed allowlisted source locally; default requires clean HEAD")
    p.add_argument("--commit", help="Explicit immutable full SHA; excludes every working change")
    p = sub.add_parser("bootstrap", help="Prepare reviewed helper files plus the public audit key locally")
    p.add_argument("--commit", help="Explicit full source commit SHA; default requires clean HEAD")
    sub.add_parser("deploy", help="Operator-only: supervised terminal, SHA confirmation and administrator password")
    sub.add_parser("status", help="Read schema-validated fixed audit status")
    sub.add_parser("audit-check", help="Status plus read-only command/shell refusal probes")
    p = sub.add_parser("report", help="Read schema-validated JSON using the restricted audit key")
    p.add_argument("commit", help="Full 40-hex commit SHA")
    p.add_argument("--save", action="store_true", help="Save under LOCALAPPDATA/MalPDFDeepDetection/lab_reports")
    args = parser.parse_args()
    try:
        if args.cmd == "prepare":
            prepare(args.commit)
        elif args.cmd == "bootstrap":
            bootstrap(args.commit)
        elif args.cmd == "deploy":
            deploy()
        elif args.cmd == "status":
            status()
        elif args.cmd == "audit-check":
            audit_check()
        elif args.cmd == "report":
            report(args.commit, args.save)
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError) as exc:
        print(f"labctl error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
