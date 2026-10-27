"""Validated source snapshots without staging or committing unrelated changes."""

import os
from pathlib import Path
import stat
import sys

import labctl as ctl
from lab_contract import MAX_FILE, MAX_FILES, MAX_TOTAL, safe_path, text_failure
from gateway_contract import encoded, sha


def source_contents():
    ctl.run([sys.executable, str(ctl.REPO / 'scripts/security/check_repo_content.py'), '--worktree'], capture=True)
    names = ctl.git('ls-files', '--cached', '--others', '--exclude-standard', '-z').decode('utf-8').split('\0')
    contents = []
    seen = set()
    total = 0
    for name in sorted(set(names) - {''}):
        if not safe_path(name):
            continue
        path = ctl.REPO / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('source_rejected')
        if not path.exists():
            continue
        if name.casefold() in seen:
            raise ValueError('source_rejected')
        seen.add(name.casefold())
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                raise ValueError('source_rejected')
            payload = stream.read(MAX_FILE + 1)
        if len(payload) > MAX_FILE or text_failure(payload, name):
            raise ValueError('source_rejected')
        contents.append((name, payload))
        total += len(payload)
        if len(contents) > MAX_FILES or total > MAX_TOTAL:
            raise ValueError('source_rejected')
    if not contents:
        raise ValueError('source_rejected')
    return contents


def prepare(*, normalize=False):
    commit = ctl.revision()
    contents = source_contents()
    if normalize:
        contents = [(name, payload.replace(b'\r\n', b'\n')) for name, payload in contents]
    identity = sha(encoded({'base_commit': commit, 'files': [(name, sha(payload)) for name, payload in contents]}))
    destination = ctl.OUT / 'snapshots' / identity
    if destination.resolve() != destination.absolute() or any(parent.is_symlink() for parent in (destination, *destination.parents)):
        raise ValueError('source_rejected')
    archive, manifest, metadata = ctl.write_source_package(commit, contents, destination)
    return commit, archive, manifest, metadata
