"""Root-owned forced-command SSH endpoint: fixed status and schema-filtered reports."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

from lab_contract import parse_json, validate_report

REPORTS = Path("/var/lib/malpdf/reports/approved")
REV_RE = re.compile(r"[0-9a-f]{40}\Z")


def check(payload: object, sha: str) -> dict:
    return validate_report(payload, sha)


def main() -> int:
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command == 'diagnose gateway':
        try:
            from lab_diagnostics import collect, validate_report as validate_diagnostics
            value = validate_diagnostics(collect())
        except (ImportError, OSError, ValueError, KeyError, TypeError, RecursionError):
            return 3
        print(json.dumps(value, separators=(',', ':')))
        return 0
    if command == "status":
        from lab_jobs import probe
        value = {"schema_version": 2, "role": "malpdf-audit", "connection": "read-only-command-gate", 'runner': probe()}
        try:
            from lab_gateway import capability
        except ImportError:
            pass
        else:
            value.update(schema_version=3, gateway=capability())
        print(json.dumps(value))
        return 0
    if command.startswith('report-job '):
        identity = command[len('report-job '):]
        if not re.fullmatch(r'[0-9a-f]{64}', identity):
            return 2
        try:
            from lab_gateway import audit
            value = audit(identity)
        except (ImportError, OSError, ValueError, KeyError, TypeError, RecursionError):
            return 3
        print(json.dumps(value, separators=(',', ':')))
        return 0
    if command.startswith("report "):
        sha = command[7:]
        if not REV_RE.fullmatch(sha):
            return 2
        file = REPORTS / f"{sha}.json"
        if not file.is_file() or file.is_symlink() or file.stat().st_size > 16_384:
            return 3
        try:
            fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return 3
                raw = stream.read(16_385)
            if len(raw) > 16_384:
                return 3
            obj = check(parse_json(raw), sha)
        except (OSError, ValueError, RecursionError):
            return 4
        print(json.dumps(obj, separators=(",", ":")))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
