"""Require explicit operator isolation attestation before live extraction."""

import os
from pathlib import Path
import platform


def require_extraction_platform() -> None:
    if platform.system() != 'Linux':
        raise PermissionError('Path-based PDF extraction requires an approved Linux LAB; Windows DEV supports reviewed synthetic byte tests only')


def require_lab_isolation() -> None:
    require_extraction_platform()
    if os.environ.get('MALPDF_LAB_ISOLATED') != '1':
        raise PermissionError('Live extraction requires MALPDF_LAB_ISOLATED=1 after offline LAB isolation is verified')


def require_live_path_isolation(path: Path) -> None:
    require_extraction_platform()
    for candidate in (path.absolute(), path.resolve()):
        parts = [part.casefold() for part in candidate.parts]
        if any(left == 'data' and right in {'raw', 'external'}
               for left, right in zip(parts, parts[1:])):
            require_lab_isolation()
            return
