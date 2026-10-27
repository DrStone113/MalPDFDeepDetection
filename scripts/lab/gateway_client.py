"""Unattended syntax/approved synthetic jobs through a separate constrained key."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import gateway_contract as contract
import gateway_snapshot as snapshot
import labctl as ctl
import lab_gateway as server
import lab_jobs as jobs
import lab_diagnostics as diagnostics
from lab_vmware import collect as host_metadata
from lab_contract import MAX_REPORT, parse_json, validate_public_key, validate_status

STATE = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'MalPDFDeepDetection/workflow/gateway'
KEY = Path.home() / '.ssh/id_ed25519_malpdf_runner'
ALIAS = 'remnux-lab-runner'


def security():
    return [*ctl.SSH_SECURITY, '-o', 'HostName=192.168.217.10', '-o', 'User=malpdf-runner',
            '-o', 'Port=22', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no', '-i', str(KEY)]


def exchange(command, payload=None, *, subsystem=False, forwarding=False):
    jobs.trusted_path(KEY)
    if not KEY.is_file():
        raise ValueError('setup_required')
    arguments = [*security()]
    if subsystem:
        arguments.append('-s')
    if forwarding:
        arguments += ['-W', '127.0.0.1:22', ALIAS]
    else:
        arguments += [ALIAS, command]
    return ctl.bounded_ssh(arguments, payload=payload, timeout=60 if payload else 10)


def expected_policy():
    contents = {}
    for name in server.HELPERS:
        path = ctl.REPO / ('src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else 'scripts/lab/' + name)
        jobs.trusted_path(path)
        contents[name] = contract.sha(jobs.side.bounded_read(path, 2 * 1024**2).replace(b'\r\n', b'\n'))
    return contract.sha(contract.encoded(contents))


def readiness(*, negative=True):
    code, raw = ctl.audit_request('status')
    if code:
        raise ValueError('ssh_unavailable')
    status = validate_status(parse_json(raw))
    value = status.get('gateway')
    if not value or not value['installed']:
        raise ValueError('setup_required')
    contract.validate_capability(value)
    if not value['verified'] or value['policy_sha256'] != expected_policy():
        raise ValueError('gateway_not_verified')
    code, raw = exchange('probe')
    if code or contract.validate_capability(parse_json(raw)) != value:
        raise ValueError('gateway_not_verified')
    if negative:
        for command, subsystem in [('id', False), ('', False), ('submit-pdf ' + 'a' * 64, False), ('submit-syntax ../escape', False), ('sftp', True)]:
            code, raw = exchange(command, subsystem=subsystem)
            if code != 2 or raw.strip():
                raise ValueError('gateway_not_verified')
        code, raw = exchange('', forwarding=True)
        if code == 0 or raw.strip():
            raise ValueError('gateway_not_verified')
    return value


def remember(job):
    folder = jobs.trusted_path(STATE / job['job_id'])
    folder.mkdir(parents=True, exist_ok=True)
    jobs.immutable(folder / 'job.json', job)
    descriptor, name = tempfile.mkstemp(prefix='last-', suffix='.tmp', dir=STATE)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(contract.encoded({'job_id': job['job_id']}))
    os.replace(name, jobs.trusted_path(STATE / 'last.json'))


def read_job():
    identity = parse_json(jobs.side.bounded_read(jobs.trusted_path(STATE / 'last.json'), MAX_REPORT))['job_id']
    if not isinstance(identity, str) or not contract.HEX.fullmatch(identity):
        raise ValueError('job_mismatch')
    value = contract.validate_job(parse_json(jobs.side.bounded_read(jobs.trusted_path(STATE / identity / 'job.json'), MAX_REPORT)))
    if value['job_id'] != identity:
        raise ValueError('job_mismatch')
    return value


def fetch(job):
    code, raw = ctl.audit_request('report-job ' + job['job_id'])
    if code == 3:
        raise ValueError('report_pending')
    if code:
        raise ValueError('ssh_unavailable')
    value = contract.validate_result(parse_json(raw), job)
    jobs.immutable(STATE / job['job_id'] / (value['status'] + '.json'), value)
    return value


def test(profile):
    if profile not in contract.PROFILES:
        raise ValueError('profile_not_approved')
    capability = readiness()
    if profile not in capability['profiles']:
        raise ValueError('profile_not_approved')
    try:
        ctl.run([sys.executable, '-B', str(ctl.REPO / 'scripts/lab/check_local.py'), '--save'], capture=True)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError('local_checks_failed') from None
    commit, archive, manifest, metadata = snapshot.prepare()
    job = contract.make_job(commit, contract.sha(manifest.read_bytes()), metadata['archive_sha256'], profile, capability['policy_sha256'])
    folder = jobs.trusted_path(STATE / job['job_id'])
    already = (folder / 'job.json').exists()
    if already:
        remember(job)
        return fetch(job)
    pieces = [contract.encoded(job), jobs.side.bounded_read(manifest, 512 * 1024), jobs.side.bounded_read(archive, 40 * 1024**2)]
    if contract.sha(pieces[1]) != job['manifest_sha256'] or contract.sha(pieces[2]) != job['archive_sha256']:
        raise ValueError('source_rejected')
    payload = b''.join(len(piece).to_bytes(4, 'big') + piece for piece in pieces)
    remember(job)
    code, raw = exchange('submit-' + profile + ' ' + job['job_id'], payload)
    if code:
        raise ValueError('ssh_unavailable')
    if parse_json(raw) != {'api': 1, 'job_id': job['job_id'], 'accepted': True}:
        raise ValueError('report_invalid')
    deadline = time.monotonic() + 100
    while True:
        try:
            value = fetch(job)
        except ValueError as error:
            if str(error) != 'report_pending' or time.monotonic() >= deadline:
                raise
        else:
            if value['status'] not in ('queued', 'running') or time.monotonic() >= deadline:
                return value
        time.sleep(2)


def ensure_key():
    if sys.platform != 'win32':
        raise ValueError('setup_required')
    public = KEY.with_suffix('.pub')
    jobs.trusted_path(KEY)
    jobs.trusted_path(public)
    if KEY.exists() != public.exists():
        raise ValueError('setup_required')
    if KEY.exists() and not KEY.is_file():
        raise ValueError('setup_required')
    if not KEY.exists():
        KEY.parent.mkdir(parents=True, exist_ok=True)
        binary = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'System32/OpenSSH/ssh-keygen.exe'
        subprocess.run([str(binary), '-q', '-t', 'ed25519', '-N', '', '-C', 'malpdf-runner-gateway', '-f', str(KEY)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
    return (validate_public_key(jobs.side.bounded_read(public, 1024)).rsplit(' ', 1)[0] + ' malpdf-runner-gateway\n').encode('ascii')


def setup():
    public = ensure_key()
    files = {}
    for name in (*server.HELPERS, 'setup_gateway.py', 'setup_gateway.sh'):
        path = ctl.REPO / ('src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else 'scripts/lab/' + name)
        jobs.trusted_path(path)
        payload = jobs.side.bounded_read(path, 2 * 1024**2).replace(b'\r\n', b'\n')
        from lab_contract import text_failure
        if len(payload) > 2 * 1024**2 or text_failure(payload, 'scripts/lab/' + name):
            raise ValueError('source_rejected')
        files[name] = payload
    files['id_ed25519_malpdf_runner.pub'] = public
    metadata = {'api': 1, 'base_commit': ctl.revision(), 'source_kind': 'reviewed_worktree_bootstrap',
                'files': [{'path': name, 'size': len(payload), 'sha256': contract.sha(payload)} for name, payload in sorted(files.items())]}
    identity = contract.sha(contract.encoded(metadata))
    files['manifest.json'] = contract.encoded(metadata) + b'\n'
    target = jobs.trusted_path(ctl.OUT / 'gateway-bootstrap' / identity)
    target.mkdir(parents=True, exist_ok=True)
    if set(path.name for path in target.iterdir()) - set(files):
        raise ValueError('source_rejected')
    for name, payload in files.items():
        path = jobs.trusted_path(target / name)
        if path.exists():
            if path.read_bytes() != payload:
                raise ValueError('source_rejected')
        else:
            with path.open('xb') as output:
                output.write(payload)
    return {'bootstrap': str(target), 'manifest_id': identity, 'files': len(files), 'remote_changes': False, 'ready': False}


def prepare():
    commit, archive, manifest, metadata = snapshot.prepare()
    return {'base_commit': commit, 'source_kind': 'validated_worktree_snapshot', 'files': len(metadata['files']),
            'archive': str(archive), 'manifest': str(manifest), 'archive_sha256': metadata['archive_sha256'],
            'manifest_sha256': contract.sha(manifest.read_bytes()), 'remote_changes': False}


def doctor(*, offline=False):
    result = {'api': 1, 'status': 'not_ready', 'reason': 'lab_unreachable', 'diagnostics': None,
              'audit_status': None, 'checked_utc': diagnostics.stamp(), 'cache_saved': False, 'host_vmware': None}
    code, raw = None, b''
    if offline:
        result['reason'] = 'offline_result_requires_review'
    else:
        try:
            code, raw = ctl.audit_request('diagnose gateway')
        except (OSError, ValueError, subprocess.SubprocessError):
            code, raw = 255, b''
    if code == 2:
        result['reason'] = 'diagnostics_upgrade_required'
        try:
            status_code, status_raw = ctl.audit_request('status')
            if status_code == 0:
                result['audit_status'] = validate_status(parse_json(status_raw))
        except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
            pass
    elif code not in (None, 0, 255):
        result['reason'] = 'diagnostics_unavailable'
    elif code == 0:
        try:
            value = diagnostics.validate_report(parse_json(raw))
            result['status'], result['reason'] = diagnostics.classify(value)
            result['diagnostics'] = value
            if result['status'] == 'ready':
                try:
                    local_policy = expected_policy()
                except (OSError, ValueError):
                    result.update(status='not_ready', reason='local_policy_unavailable')
                else:
                    if value['gateway']['policy_sha256'] != local_policy:
                        result.update(status='not_ready', reason='local_policy_mismatch')
        except (ValueError, KeyError, TypeError, RecursionError):
            result['reason'] = 'diagnostics_invalid'
    if not offline and result['reason'] == 'lab_unreachable':
        result['host_vmware'] = host_metadata()
    try:
        folder = jobs.trusted_path(STATE / 'doctor')
        folder.mkdir(parents=True, exist_ok=True)
        result['cache_saved'] = True
        identity = contract.sha(contract.encoded(result))
        jobs.immutable(folder / (result['checked_utc'].replace(':', '') + '_' + identity + '.json'), result)
    except (OSError, ValueError):
        result['cache_saved'] = False
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('test', 'report', 'verify', 'setup', 'prepare', 'doctor'))
    parser.add_argument('--profile', choices=tuple(sorted(contract.PROFILES)), default='synthetic')
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            value = doctor(offline=args.offline)
            print(json.dumps(value, sort_keys=True))
            return {'ready': 0, 'pending': 4, 'not_ready': 3, 'failed': 1}[value['status']]
        if args.command == 'test':
            value = test(args.profile)
        elif args.command == 'verify':
            value = readiness()
        elif args.command == 'setup':
            value = setup()
        elif args.command == 'prepare':
            value = prepare()
        else:
            job = read_job()
            if args.refresh:
                value = fetch(job)
            else:
                folder = STATE / job['job_id']
                path = next((folder / (status + '.json') for status in ('passed', 'failed', 'interrupted', 'running', 'queued') if (folder / (status + '.json')).is_file()), None)
                if path is None:
                    raise ValueError('report_pending')
                value = contract.validate_result(parse_json(jobs.side.bounded_read(jobs.trusted_path(path), MAX_REPORT)), job)
        print(json.dumps(value, sort_keys=True))
        if value.get('status') in ('queued', 'running'):
            return 4
        return 1 if value.get('status') in ('failed', 'interrupted') else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RecursionError) as error:
        reason = str(error) if str(error) in contract.REASONS | {'local_checks_failed'} else 'source_rejected'
        action = 'Run the Windows scripts/lab/check_local.py check and inspect its local receipt; no new LAB job was submitted.' if reason == 'local_checks_failed' else 'Use the reviewed one-time gateway setup; no administrative SSH or automatic retry is attempted.'
        print(json.dumps({'status': 'NOT READY', 'reason': reason, 'action': action}))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
