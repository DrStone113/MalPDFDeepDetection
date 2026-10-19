"""Root-owned forced-command SSH endpoint: fixed status and schema-filtered reports."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys

REPORTS = Path("/var/lib/malpdf/reports/approved")
REV_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"(?:src|scripts|tests|configs)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.py\Z")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def check(payload: object, sha: str) -> dict:
    required = {"schema_version", "commit", "kind", "status", "file_count", "passed", "failed", "generated_utc", "issues"}
    if not isinstance(payload, dict) or set(payload) != required or payload["schema_version"] != 1 or payload["commit"] != sha:
        raise ValueError("Invalid report schema")
    if payload["kind"] != "ast_syntax" or payload["status"] not in ("passed", "failed"):
        raise ValueError("Invalid report kind")
    for key in ("file_count", "passed", "failed"):
        if type(payload[key]) is not int or not 0 <= payload[key] <= 3000:
            raise ValueError("Invalid counts")
    if payload["passed"] + payload["failed"] != payload["file_count"]:
        raise ValueError("Inconsistent counts")
    if not isinstance(payload["generated_utc"], str) or not TIMESTAMP_RE.fullmatch(payload["generated_utc"]):
        raise ValueError("Invalid time")
    issues = payload["issues"]
    if not isinstance(issues, list) or len(issues) > 30:
        raise ValueError("Invalid issues")
    for issue in issues:
        if not isinstance(issue, dict) or set(issue) != {"path", "line", "kind"}:
            raise ValueError("Invalid issue")
        if not isinstance(issue["path"], str) or not PATH_RE.fullmatch(issue["path"]):
            raise ValueError("Invalid issue path")
        if type(issue["line"]) is not int or not 0 <= issue["line"] <= 1_000_000:
            raise ValueError("Invalid line")
        if issue["kind"] not in ("SyntaxError", "UnicodeError", "FileError", "Oversize"):
            raise ValueError("Invalid kind")
    return payload


def main() -> int:
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command == "status":
        print(json.dumps({"schema_version": 1, "role": "malpdf-audit", "connection": "read-only-command-gate"}))
        return 0
    if command.startswith("report "):
        sha = command[7:]
        if not REV_RE.fullmatch(sha):
            return 2
        file = REPORTS / f"{sha}.json"
        if not file.is_file() or file.is_symlink() or file.stat().st_size > 16_384:
            return 3
        try:
            obj = check(json.loads(file.read_text(encoding="utf-8")), sha)
        except (OSError, ValueError, json.JSONDecodeError):
            return 4
        print(json.dumps(obj, separators=(",", ":")))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
