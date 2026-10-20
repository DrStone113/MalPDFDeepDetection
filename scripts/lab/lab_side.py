"""REMnux-side root-installed, run-as-remnux release verifier and AST smoke check."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

from lab_contract import MAX_FILE, MAX_FILES, MAX_TOTAL, REV_RE as REV, parse_json, safe_path, text_failure, validate_report

INBOX = Path("/home/remnux/malpdf-inbox")
RELEASES = Path("/home/remnux/malpdf-releases")
REPORTS = Path("/var/lib/malpdf/reports/approved")


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def bounded_read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Unexpected input type/size")
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Input exceeds byte limit")
    return payload


def valid_path(name: str) -> bool:
    return safe_path(name)


def verify_release(commit: str, manifest_sha256: str) -> dict:
    if not REV.fullmatch(commit):
        raise ValueError('release_mismatch')
    if any(path.is_symlink() for path in (INBOX, *INBOX.parents)):
        raise ValueError('manifest_unavailable')
    try:
        raw = bounded_read(INBOX / f'{commit}.json', 512 * 1024)
    except OSError:
        raise ValueError('manifest_unavailable') from None
    if digest(raw) != manifest_sha256:
        raise ValueError('release_mismatch')
    meta = parse_json(raw)
    if not isinstance(meta, dict) or set(meta) != {'schema_version', 'commit', 'archive_sha256', 'files'} or type(meta['schema_version']) is not int or meta['schema_version'] != 1 or meta['commit'] != commit or not isinstance(meta['files'], list):
        raise ValueError('release_mismatch')
    folder = RELEASES / commit
    if folder.is_symlink() or not folder.is_dir() or not 0 < len(meta['files']) <= MAX_FILES:
        raise ValueError('release_mismatch')
    expected = set()
    total = 0
    for entry in meta['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'size', 'sha256'} or not valid_path(entry['path']) or entry['path'] in expected:
            raise ValueError('release_mismatch')
        path = folder / entry['path']
        if any(part.is_symlink() for part in (path, *path.parents)) or type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE:
            raise ValueError('release_mismatch')
        payload = bounded_read(path, MAX_FILE)
        if len(payload) != entry['size'] or digest(payload) != entry['sha256'] or text_failure(payload, entry['path']):
            raise ValueError('release_mismatch')
        expected.add(entry['path'])
        total += len(payload)
    actual = set()
    for path in folder.rglob('*'):
        if path.is_symlink() or not path.is_file() and not path.is_dir():
            raise ValueError('release_mismatch')
        if path.is_file():
            actual.add(path.relative_to(folder).as_posix())
    if actual != expected or total > MAX_TOTAL:
        raise ValueError('release_mismatch')
    return meta


def install(commit: str) -> None:
    if not REV.fullmatch(commit):
        raise ValueError("Invalid commit")
    archive = INBOX / f"{commit}.tar"
    manifest = INBOX / f"{commit}.json"
    if archive.is_symlink() or manifest.is_symlink() or not archive.is_file() or not manifest.is_file() or archive.stat().st_size > 40 * 1024 * 1024 or manifest.stat().st_size > 512 * 1024:
        raise ValueError("Missing or oversized upload")
    meta = parse_json(bounded_read(manifest, 512 * 1024))
    if not isinstance(meta, dict) or set(meta) != {"schema_version", "commit", "archive_sha256", "files"} or type(meta["schema_version"]) is not int or meta["schema_version"] != 1 or meta["commit"] != commit:
        raise ValueError("Invalid release manifest")
    if not isinstance(meta["files"], list) or not 0 < len(meta["files"]) <= MAX_FILES:
        raise ValueError("Invalid file count")
    archive_bytes = bounded_read(archive, 40 * 1024 * 1024)
    if digest(archive_bytes) != meta["archive_sha256"]:
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
        offset = 0
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as tf:
            for member in tf:
                if len(actual) >= len(expected) or member.type != tarfile.REGTYPE or member.pax_headers or member.linkname or not valid_path(member.name) or member.name in actual or member.name not in expected:
                    raise ValueError("Unsafe TAR member")
                size, sha = expected[member.name]
                if member.size != size:
                    raise ValueError("TAR member size mismatch")
                canonical = tarfile.TarInfo(member.name)
                canonical.size = size
                canonical.mode = 0o644
                if member.offset != offset or member.offset_data != offset + 512 or archive_bytes[offset:offset + 512] != canonical.tobuf(format=tarfile.USTAR_FORMAT):
                    raise ValueError("Noncanonical TAR metadata")
                end = member.offset_data + size
                offset = member.offset_data + ((size + 511) // 512) * 512
                if any(archive_bytes[end:offset]):
                    raise ValueError("Nonzero TAR member padding")
                stream = tf.extractfile(member)
                if stream is None:
                    raise ValueError("Missing member bytes")
                payload = stream.read(MAX_FILE + 1)
                if len(payload) != size or digest(payload) != sha:
                    raise ValueError("TAR member checksum mismatch")
                if text_failure(payload, member.name):
                    raise ValueError("Forbidden binary or credential content")
                output = scratch / member.name
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("xb") as f:
                    f.write(payload)
                output.chmod(0o644)
                actual.add(member.name)
        if len(archive_bytes) % tarfile.RECORDSIZE or len(archive_bytes) - offset < 1024 or any(archive_bytes[offset:]):
            raise ValueError("Noncanonical TAR trailer")
        if actual != set(expected):
            raise ValueError("Missing files")
        scratch.rename(target)
    finally:
        if scratch.exists():
            if scratch.is_symlink() or scratch.parent.resolve() != RELEASES.resolve() or not scratch.name.startswith("staging-"):
                raise ValueError("Unexpected staging cleanup path")
            shutil.rmtree(scratch)
    print(json.dumps({"installed": True, "commit": commit, "file_count": len(expected)}))


def syntax(commit: str) -> dict:
    if not REV.fullmatch(commit):
        raise ValueError("Invalid commit")
    folder = RELEASES / commit
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Unknown release")
    pyfiles = []
    for path in folder.rglob("*.py"):
        pyfiles.append(path)
        if len(pyfiles) > MAX_FILES:
            raise ValueError("Too many Python files")
    if not pyfiles:
        raise ValueError("No Python files")
    pyfiles.sort()
    issues = []
    passed = failed = 0
    for p in pyfiles:
        relative = p.relative_to(folder).as_posix()
        if not valid_path(relative):
            raise ValueError("Invalid source path")
        line = 0
        kind = ""
        try:
            if p.is_symlink():
                kind = "FileError"
            elif p.stat().st_size > MAX_FILE:
                kind = "Oversize"
            else:
                ast.parse(bounded_read(p, MAX_FILE).decode("utf-8-sig"), filename=relative)
        except SyntaxError as exc:
            kind, line = "SyntaxError", int(exc.lineno or 0)
        except UnicodeError:
            kind = "UnicodeError"
        except OSError:
            kind = "FileError"
        except ValueError:
            kind = "Oversize"
        if kind:
            failed += 1
            if len(issues) < 30:
                issues.append({"path": relative, "line": line, "kind": kind})
        else:
            passed += 1
    data = make_report(commit, "ast_syntax", passed, failed, 0, issues)
    save_report(data)
    return data


def synthetic_limits() -> None:
    import resource
    for limit, bound in ((resource.RLIMIT_CPU, 60), (resource.RLIMIT_AS, 256 * 1024 * 1024), (resource.RLIMIT_FSIZE, 2 * 1024 * 1024), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(limit, (bound, bound))


def synthetic(commit: str) -> dict:
    if sys.platform != "linux" or os.geteuid() == 0 or not REV.fullmatch(commit):
        raise ValueError("Synthetic LAB execution requires an approved non-root Linux session")
    folder = RELEASES / commit
    test_file = folder / "scripts/lab/selftest.py"
    if not folder.is_dir() or not test_file.is_file() or any(path.is_symlink() for path in (folder, folder / "scripts", folder / "scripts/lab", test_file)):
        raise ValueError("Missing reviewed synthetic test release")
    with tempfile.TemporaryDirectory(prefix="malpdf-synthetic-") as temporary, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": temporary, "TMPDIR": temporary, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
        with subprocess.Popen(["/usr/bin/python3", "-Es", "-B", str(test_file), "--json"], cwd=folder, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, start_new_session=True, preexec_fn=synthetic_limits) as process:
            timed_out = False
            try:
                code = process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise
        output.seek(0)
        raw = output.read(16_385)
    kind = "Timeout" if timed_out else "TestError"
    counts = {"total": 1, "passed": 0, "failed": 1, "skipped": 0}
    try:
        candidate = parse_json(raw)
        if len(raw) > 16_384 or not isinstance(candidate, dict) or set(candidate) != set(counts):
            raise ValueError("Invalid synthetic summary")
        if any(type(value) is not int or not 0 <= value <= MAX_FILES for value in candidate.values()):
            raise ValueError("Invalid synthetic counts")
        if not candidate["total"] or candidate["passed"] + candidate["failed"] + candidate["skipped"] != candidate["total"] or code != (1 if candidate["failed"] else 0):
            raise ValueError("Inconsistent synthetic result")
        counts = candidate
        kind = "AssertionFailure"
    except (ValueError, RecursionError):
        pass
    issues = [{"path": "scripts/lab/selftest.py", "line": 0, "kind": kind} for _ in range(min(counts["failed"], 30))]
    data = make_report(commit, "synthetic_security", counts["passed"], counts["failed"], counts["skipped"], issues)
    save_report(data)
    return data


def make_report(commit: str, kind: str, passed: int, failed: int, skipped: int, issues: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    data = {"schema_version": 2, "commit": commit, "run_id": now.strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:16], "kind": kind, "status": "failed" if failed else "partial" if skipped else "passed", "file_count": passed + failed + skipped, "passed": passed, "failed": failed, "skipped": skipped, "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "environment": {"system": sys.platform, "python": ".".join(str(v) for v in sys.version_info[:3]), "isolation": "not_verified", "dependencies": "not_checked"}, "issues": issues}
    return validate_report(data, commit)


def save_report(data: dict) -> None:
    commit = data["commit"]
    validate_report(data, commit)
    REPORTS.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="result-", suffix=".json", dir=REPORTS)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
            f.write("\n")
        os.chmod(tmp, 0o640)
        historical = REPORTS / f"{commit}_{data['run_id']}.json"
        with historical.open("xb") as history:
            history.write(Path(tmp).read_bytes())
        historical.chmod(0o640)
        os.replace(tmp, REPORTS / f"{commit}.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(json.dumps({"report_ready": True, "commit": commit, "kind": data["kind"], "status": data["status"], "failed": data["failed"]}))


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("install", "syntax", "synthetic") or not REV.fullmatch(sys.argv[2]):
        print("Usage: lab_side.py {install|syntax|synthetic} <full-commit-sha>", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "install":
            install(sys.argv[2])
        elif sys.argv[1] == "syntax":
            return 1 if syntax(sys.argv[2])["failed"] else 0
        else:
            return 1 if synthetic(sys.argv[2])["failed"] else 0
        return 0
    except (OSError, ValueError, RecursionError, tarfile.TarError, subprocess.SubprocessError) as exc:
        print(f"LAB operation refused: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
