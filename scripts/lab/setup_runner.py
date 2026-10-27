"""Operator-only offline runner setup that preserves the verified gateway."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
LIB = Path('/usr/local/libexec/malpdf')
ETC = Path('/etc/malpdf')
DATA = Path('/home/remnux/MalPDFDeepDetection')
JOBS = Path('/var/lib/malpdf/jobs')
INBOX = Path('/home/remnux/malpdf-inbox')
RELEASES = Path('/home/remnux/malpdf-releases')
CLI = Path('/usr/local/bin/lab')
DESKTOP = Path('/usr/share/applications/malpdf-lab.desktop')
HELPERS = ('lab_contract.py', 'lab_readonly.py', 'lab_side.py', 'lab_jobs.py',
           'lab_runner.py', 'check_local.py', 'lab_guard.py')
FILES = (*HELPERS, 'setup_readonly.sh', 'setup_runner.py', 'setup_runner.sh',
         'id_ed25519_malpdf_audit.pub')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def safe(path):
    if path.resolve() != path.absolute() or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('symlinked_destination')
    return path


def read(path, maximum, *, root=False):
    safe(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError('unsafe_file')
        if root and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError('unsafe_file')
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError('unsafe_file')
    return payload


def validate_bootstrap(folder):
    raw = read(folder / 'manifest.json', 32768)
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('bootstrap_rejected')
            result[key] = value
        return result
    metadata = json.loads(raw, object_pairs_hook=unique)
    allowed = ({'schema_version', 'commit', 'files'}, {'schema_version', 'commit', 'source_kind', 'files'})
    if not isinstance(metadata, dict) or set(metadata) not in allowed or type(metadata['schema_version']) is not int or metadata['schema_version'] != 1:
        raise ValueError('bootstrap_rejected')
    if not isinstance(metadata['commit'], str) or not re.fullmatch(r'[0-9a-f]{40}', metadata['commit']):
        raise ValueError('bootstrap_rejected')
    if 'source_kind' in metadata and metadata['source_kind'] != 'reviewed_worktree_bootstrap':
        raise ValueError('bootstrap_rejected')
    if 'source_kind' in metadata and folder.name != hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest():
        raise ValueError('bootstrap_rejected')
    items = metadata['files']
    if not isinstance(items, list) or len(items) != len(FILES) or any(not isinstance(item, dict) or set(item) != {'path', 'size', 'sha256'} for item in items):
        raise ValueError('bootstrap_rejected')
    if any(not isinstance(item['path'], str) for item in items) or {item['path'] for item in items} != set(FILES) or {path.name for path in folder.iterdir()} != {*FILES, 'manifest.json'}:
        raise ValueError('bootstrap_rejected')
    payloads = {}
    for item in items:
        if type(item['size']) is not int or not 0 < item['size'] <= 2 * 1024**2 or not isinstance(item['sha256'], str) or not HEX.fullmatch(item['sha256']):
            raise ValueError('bootstrap_rejected')
        payload = read(folder / item['path'], 2 * 1024**2)
        if len(payload) != item['size'] or hashlib.sha256(payload).hexdigest() != item['sha256']:
            raise ValueError('bootstrap_rejected')
        payloads[item['path']] = payload
    return metadata, payloads


def compatible_helpers(payloads, config):
    for name in HELPERS:
        expected = config['policy'].get(name)
        if expected is not None and hashlib.sha256(payloads[name]).hexdigest() != expected:
            raise ValueError('gateway_upgrade_required')


def live_gateway():
    for name in ('lab_gateway.py', 'lab_diagnostics.py', 'gateway_contract.py', *HELPERS):
        if name != 'check_local.py':
            read(LIB / name, 2 * 1024**2, root=True)
    sys.path.insert(0, str(LIB))
    import lab_gateway
    config = lab_gateway.config()
    lab_gateway.verified(config)
    return config


def state_directory(path, account, *, private=False):
    safe(path)
    if path.exists():
        info = path.stat()
        forbidden = 0o077 if private else 0o027
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_gid != account.pw_gid or info.st_mode & forbidden:
            raise ValueError('existing_state_requires_review')


def preflight():
    if sys.platform != 'linux' or os.getuid() != 0:
        raise ValueError('operator_console_root_required')
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        raise ValueError('unsupported_python')
    metadata, payloads = validate_bootstrap(SOURCE)
    config = live_gateway()
    compatible_helpers(payloads, config)
    from lab_contract import parse_json, validate_public_key
    parse_json(read(SOURCE / 'manifest.json', 32768))
    key = validate_public_key(payloads['id_ed25519_malpdf_audit.pub']).split()[:2]
    authorized = read(Path('/home/malpdf-audit/.ssh/authorized_keys'), 16384, root=True).decode('ascii')
    installed = re.findall(r'(?:^|[ \t])(ssh-ed25519) ([A-Za-z0-9+/]+={0,2})(?=[ \t\r\n]|$)', authorized)
    if installed != [tuple(key)]:
        raise ValueError('audit_key_mismatch')
    import pwd
    account = pwd.getpwnam('remnux')
    if account.pw_uid < 1000 or account.pw_dir != '/home/remnux' or not safe(DATA).is_dir():
        raise ValueError('analysis_account_or_data_missing')
    for path in (LIB, ETC):
        safe(path)
        if path.exists():
            info = path.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('destination_permissions')
    for path in (CLI, ETC / 'runner.json', DESKTOP, LIB / 'check_local.py'):
        safe(path)
        if path.exists():
            read(path, 2 * 1024**2, root=True)
    for path in (JOBS, INBOX, RELEASES):
        state_directory(path, account, private=path == JOBS)
    python = DATA / '.venv/bin/python'
    if not python.is_file():
        python = Path('/usr/bin/python3')
    candidate = {'schema_version': 1, 'data_root': str(DATA), 'python': str(python), 'uid': account.pw_uid}
    current = ETC / 'runner.json'
    if current.exists() and parse_json(read(current, 8192, root=True)) != candidate:
        raise ValueError('existing_runner_requires_review')
    return metadata, payloads, config, account, candidate


def write(path, payload, mode):
    safe(path)
    descriptor, name = tempfile.mkstemp(prefix='.malpdf-offline-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def install(payloads, config, account, candidate):
    backup = Path(tempfile.mkdtemp(prefix='malpdf-runner-setup.', dir='/var/tmp'))
    backup.chmod(0o700)
    print('Operator backups: ' + str(backup))
    cli = b'#!/bin/sh\nexec /usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_runner.py "$@"\n'
    desktop = b'[Desktop Entry]\nType=Application\nName=MalPDF LAB Runner\nComment=Run approved offline jobs\nExec=/usr/local/bin/lab menu\nTerminal=true\nIcon=utilities-terminal\nCategories=Development;\n'
    changes = [(LIB / 'check_local.py', payloads['check_local.py'], 0o644),
               (ETC / 'runner.json', json.dumps(candidate, sort_keys=True).encode() + b'\n', 0o644),
               (CLI, cli, 0o755), (DESKTOP, desktop, 0o644)]
    compatible_helpers(payloads, config)
    for index, (path, payload, mode) in enumerate(changes):
        if path.exists():
            shutil.copy2(path, backup / (str(index) + '-' + path.name))
        write(path, payload, mode)
    for path, mode in ((JOBS, 0o700), (INBOX, 0o750), (RELEASES, 0o750)):
        safe(path)
        if not path.exists():
            path.mkdir(parents=True, mode=mode)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
            try:
                if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise ValueError('existing_state_requires_review')
                os.fchown(descriptor, account.pw_uid, account.pw_gid)
                os.fchmod(descriptor, mode)
            finally:
                os.close(descriptor)
        state_directory(path, account, private=path == JOBS)
    if live_gateway() != config:
        raise ValueError('gateway_changed_during_installation')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('--check', '--install'), nargs='?', default='--check')
    values = list(sys.argv[1:] if argv is None else argv)
    action = values.pop(0) if values and values[0] in ('--check', '--install') else '--check'
    parser.parse_args(values)
    try:
        metadata, payloads, config, account, candidate = preflight()
        print('PASS: exact bootstrap, existing verified gateway, matching shared helpers and audit key; no changes.')
        if action == '--install':
            install(payloads, config, account, candidate)
            print('Offline console runner installed; gateway helpers, accounts, keys and SSHD preserved.')
            print('PDF metadata/dependencies, current credentials and isolation must still pass before any PDF is read.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError) as error:
        known = {'operator_console_root_required', 'unsupported_python', 'bootstrap_rejected',
            'symlinked_destination', 'unsafe_file', 'gateway_upgrade_required', 'audit_key_mismatch',
            'analysis_account_or_data_missing', 'destination_permissions', 'existing_state_requires_review',
            'existing_runner_requires_review', 'gateway_changed_during_installation'}
        reason = str(error) if str(error) in known else 'offline_setup_not_ready'
        print('NOT READY: ' + reason + '; preserve operator backups. No PDF was read.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
