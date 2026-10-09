"""Resource limits for inert static PDF inspection."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat


@dataclass(frozen=True)
class StaticInspectionLimits:
    """Bound parsing work before an untrusted PDF is inspected.

    Limits apply to this local, read-only extractor.  A limit produces a
    structured result; it never causes an attempt to bypass the limit.
    """

    max_file_size_bytes: int = 50 * 1024 * 1024
    max_pages: int = 1_000
    max_objects: int = 10_000
    max_recursion_depth: int = 100
    max_warning_length: int = 500

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def read_bounded_bytes(path: Path, *, boundary: Path, max_bytes: int) -> bytes:
    """Read a stable regular file, rejecting symlinks, escapes and oversized input."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    path, boundary = Path(path).absolute(), Path(boundary).absolute()
    if not path.is_relative_to(boundary) or ".." in path.parts:
        raise ValueError("Input escapes the allowed directory")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Symbolic links are not allowed")
    initial = path.stat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
        raise ValueError("Input must be a regular file within the byte cap")

    def opener(name: str, flags: int) -> int:
        return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))

    with open(path, "rb", opener=opener) as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError("Opened input exceeds the regular-file/byte cap")
        if (initial.st_dev, initial.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Input changed before opening")
        # Read the verified size plus one sentinel byte, rather than allocating
        # the entire allowed cap for every small file. Growth still fails the
        # length/identity checks below, even when the file grows beyond this read.
        data = handle.read(before.st_size + 1)
        after = os.fstat(handle.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(data) > max_bytes or len(data) != before.st_size or identity(before) != identity(after):
        raise ValueError("Input changed during reading or exceeded the byte cap")
    return data
