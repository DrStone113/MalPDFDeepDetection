"""Require explicit operator isolation attestation before live extraction."""

import os
from pathlib import Path


def require_lab_isolation() -> None:
    if os.environ.get('MALPDF_LAB_ISOLATED') != '1':
        raise PermissionError('Live extraction requires MALPDF_LAB_ISOLATED=1 after offline LAB isolation is verified')


def require_live_path_isolation(path: Path) -> None:
    for candidate in (path.absolute(), path.resolve()):
        if any(left == 'data' and right in {'raw', 'external'}
               for left, right in zip(candidate.parts, candidate.parts[1:])):
            require_lab_isolation()
            return
