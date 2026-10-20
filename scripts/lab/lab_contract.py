"""Shared, offline source-content and sanitized-report contracts."""
from __future__ import annotations

import ast
import base64
from datetime import datetime
import io
import json
from pathlib import PurePosixPath
import re
import tokenize

MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 3000
MAX_REPORT = 16_384
REV_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9_.\-/]+\Z")
SOURCE_PREFIXES = ("src/", "scripts/", "tests/", "configs/")
SOURCE_ROOT = {"README.md", "pyproject.toml", "pytest.ini", "setup.cfg", "AGENTS.md"}
SUFFIXES = {".py", ".pyi", ".toml", ".md", ".txt", ".yaml", ".yml", ".json", ".ini", ".cfg", ".sh", ".ps1"}
SENSITIVE_NAMES = {"credentials", "secrets", "auth", "service_account", "service-account"}
BLOCK_MAGIC = (b"%PDF-", b"MZ", b"\x7fELF", b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"\x89PNG\r\n\x1a\n", b"PAR1", b"7z\xbc\xaf\x27\x1c", b"Rar!")
KEY_BEGIN = re.compile(rb"-----BEGIN (?:(?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY(?:-----)?")
KEY_END = re.compile(rb"-----END (?:(?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY(?:-----)?")
ISSUE_KINDS = {"SyntaxError", "UnicodeError", "FileError", "Oversize", "AssertionFailure", "TestError", "Timeout"}


def safe_path(path: str) -> bool:
    if not isinstance(path, str) or len(path) > 240 or not PATH_RE.fullmatch(path):
        return False
    p = PurePosixPath(path)
    if p.is_absolute() or any(part in ("..", ".", "") or part.startswith(".") for part in path.split("/")):
        return False
    if p.stem.casefold() in SENSITIVE_NAMES:
        return False
    if path.startswith(SOURCE_PREFIXES):
        return p.suffix.lower() in SUFFIXES
    return path in SOURCE_ROOT


def private_key_failure(blob: bytes, path: str = "") -> str | None:
    matches = list(KEY_BEGIN.finditer(blob))
    if not matches:
        return None
    if KEY_END.search(blob) or PurePosixPath(path).suffix.lower() not in {".py", ".pyi"}:
        return "private key block or header"
    try:
        source = blob.decode("utf-8-sig")
        ast.parse(source)
        lines = source.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line.encode("utf-8")))
        allowed = set()
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.STRING or token.start[0] != token.end[0]:
                continue
            try:
                value = ast.literal_eval(token.string)
            except (ValueError, SyntaxError):
                continue
            if isinstance(value, str):
                value = value.encode("utf-8")
            if not isinstance(value, bytes) or not KEY_BEGIN.fullmatch(value):
                continue
            start = offsets[token.start[0] - 1] + len(lines[token.start[0] - 1][:token.start[1]].encode("utf-8"))
            end = offsets[token.end[0] - 1] + len(lines[token.end[0] - 1][:token.end[1]].encode("utf-8"))
            bom = 3 if blob.startswith(b"\xef\xbb\xbf") else 0
            allowed.update(m.start() for m in matches if start + bom <= m.start() < end + bom)
        if all(m.start() in allowed for m in matches):
            return None
    except (SyntaxError, UnicodeError, ValueError, TypeError, tokenize.TokenError, RecursionError):
        pass
    return "private key block or header"


def text_failure(blob: bytes, path: str) -> str | None:
    if blob.removeprefix(b"\xef\xbb\xbf").lstrip(b" \t\r\n").startswith(BLOCK_MAGIC):
        return "binary/archive magic header"
    if any(byte < 32 and byte not in (9, 10, 13) for byte in blob):
        return "binary control byte"
    try:
        blob.decode("utf-8-sig")
    except UnicodeError:
        return "invalid UTF-8 source"
    headers = list(re.finditer(rb"%PDF-[0-9]\.[0-9]", blob[:1024]))
    if headers:
        if PurePosixPath(path).suffix.lower() not in {".py", ".pyi"}:
            return "embedded PDF header"
        try:
            source = blob.decode("utf-8-sig")
            ast.parse(source)
            lines = source.splitlines(keepends=True)
            offsets = [3 if blob.startswith(b"\xef\xbb\xbf") else 0]
            for line in lines:
                offsets.append(offsets[-1] + len(line.encode("utf-8")))
            covered = set()
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type == tokenize.STRING:
                    start = offsets[token.start[0] - 1] + len(lines[token.start[0] - 1][:token.start[1]].encode("utf-8"))
                    end = offsets[token.end[0] - 1] + len(lines[token.end[0] - 1][:token.end[1]].encode("utf-8"))
                    covered.update(m.start() for m in headers if start <= m.start() < end)
            if any(m.start() not in covered for m in headers):
                return "embedded PDF header"
        except (SyntaxError, ValueError, UnicodeError, tokenize.TokenError, RecursionError):
            return "embedded PDF header"
    return private_key_failure(blob, path)


def validate_report(obj: object, expected_rev: str) -> dict:
    required = {"schema_version", "commit", "kind", "status", "file_count", "passed", "failed", "generated_utc", "issues"}
    if not isinstance(obj, dict) or type(obj.get("schema_version")) is not int:
        raise ValueError("Report must be a versioned JSON object")
    version = obj["schema_version"]
    if version == 2:
        required |= {"run_id", "skipped", "environment"}
    elif version != 1:
        raise ValueError("Unknown report schema")
    if set(obj) != required or not REV_RE.fullmatch(expected_rev) or obj["commit"] != expected_rev:
        raise ValueError("Report schema/revision mismatch")
    if obj["kind"] not in (("ast_syntax", "synthetic_security") if version == 2 else ("ast_syntax",)):
        raise ValueError("Unexpected report kind")
    for key in ("file_count", "passed", "failed", *(["skipped"] if version == 2 else [])):
        if type(obj[key]) is not int or not 0 <= obj[key] <= MAX_FILES:
            raise ValueError("Invalid report count")
    if obj["passed"] + obj["failed"] + obj.get("skipped", 0) != obj["file_count"]:
        raise ValueError("Inconsistent report counts")
    expected_status = "failed" if obj["failed"] else "partial" if obj.get("skipped", 0) else "passed"
    if obj["status"] != expected_status or obj["file_count"] == 0:
        raise ValueError("Inconsistent report status")
    stamp = obj["generated_utc"]
    if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
        raise ValueError("Invalid report time")
    datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    if version == 2:
        if not isinstance(obj["run_id"], str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z_[0-9a-f]{16}", obj["run_id"]):
            raise ValueError("Invalid run identity")
        env = obj["environment"]
        if not isinstance(env, dict) or set(env) != {"system", "python", "isolation", "dependencies"}:
            raise ValueError("Invalid environment schema")
        if env["system"] not in ("linux", "win32", "darwin") or not isinstance(env["python"], str) or not re.fullmatch(r"3\.\d{1,2}\.\d{1,2}", env["python"]):
            raise ValueError("Invalid environment values")
        if env["isolation"] != "not_verified" or env["dependencies"] != "not_checked":
            raise ValueError("Unexpected environment attestation")
    issues = obj["issues"]
    if not isinstance(issues, list) or len(issues) != min(obj["failed"], 30):
        raise ValueError("Inconsistent issue count")
    for issue in issues:
        if not isinstance(issue, dict) or set(issue) != {"path", "line", "kind"}:
            raise ValueError("Invalid issue schema")
        if not safe_path(issue["path"]) or PurePosixPath(issue["path"]).suffix != ".py":
            raise ValueError("Invalid issue path")
        if type(issue["line"]) is not int or not 0 <= issue["line"] <= 1_000_000 or not isinstance(issue["kind"], str) or issue["kind"] not in ISSUE_KINDS:
            raise ValueError("Invalid issue descriptor")
    return obj


def validate_status(obj: object) -> dict:
    expected = {"schema_version": 1, "role": "malpdf-audit", "connection": "read-only-command-gate"}
    if isinstance(obj, dict) and type(obj.get('schema_version')) is int and obj['schema_version'] == 2:
        if set(obj) != {*expected, 'runner'} or obj['role'] != expected['role'] or obj['connection'] != expected['connection']:
            raise ValueError('Invalid runner status')
        runner = obj['runner']
        if not isinstance(runner, dict) or set(runner) != {'api', 'installed', 'host_only_ready', 'offline_guest_ready', 'reason'} or type(runner['api']) is not int or runner['api'] != 1:
            raise ValueError('Invalid runner capability')
        if any(type(runner[name]) is not bool for name in ('installed', 'host_only_ready', 'offline_guest_ready')) or runner['reason'] not in (None, 'network_blocked'):
            raise ValueError('Invalid runner capability')
        return obj
    if not isinstance(obj, dict) or obj != expected or type(obj.get("schema_version")) is not int:
        raise ValueError("Invalid audit status")
    return expected


def parse_json(raw: bytes | str) -> object:
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("Duplicate JSON field")
            obj[key] = value
        return obj
    def constant(value):
        raise ValueError("Non-finite JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def validate_public_key(raw: bytes) -> str:
    if len(raw) > 1024:
        raise ValueError("Oversized public key")
    line = raw.decode("ascii").rstrip("\r\n")
    if not line or any(ord(char) < 32 or ord(char) > 126 for char in line):
        raise ValueError("Public key must be one printable ASCII line")
    parts = line.split(" ", 2)
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("Require an ed25519 public key without key options")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ValueError("Invalid public key encoding") from None
    if len(decoded) != 51 or decoded[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        raise ValueError("Invalid ed25519 public key structure")
    return "ssh-ed25519 " + base64.b64encode(decoded).decode("ascii") + " malpdf-audit-readonly"
