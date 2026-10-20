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
    if command == "status":
        from lab_jobs import probe
        print(json.dumps({"schema_version": 2, "role": "malpdf-audit", "connection": "read-only-command-gate", 'runner': probe()}))
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
