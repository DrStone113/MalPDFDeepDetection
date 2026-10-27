"""One-command Windows interface over the existing LAB packager and receiver."""

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import tempfile

import labctl as ctl
import lab_jobs as jobs
from lab_contract import MAX_REPORT, parse_json, validate_status

STATE = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'MalPDFDeepDetection/workflow'
REMOTE = '/usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_runner.py'
FIXES = {'setup_required': 'Run the reviewed one-time LAB installer from its console.',
    'job_unavailable': 'No local job receipt exists. Prepare and approve a job first; no remote job is guessed.',
    'report_pending': 'This job has no saved result yet. Check it at LAB; refresh is available only for connected jobs, without retrying the task.',
    'source_dirty': 'Review and commit the Windows changes first; the package must come from one clean commit.',
    'source_rejected': 'Run the local source/security check and fix the rejected content; no check is bypassed.',
    'export_requires_review': 'Offline results stay on LAB. Do not reconnect it; use a separately reviewed export/recovery procedure.',
    'credential_present': 'Use the approved credential-free LAB account. Review credential presence at its console; nothing is removed automatically.',
    'resource_unavailable': 'Review available RAM, disk and process/FD budgets at LAB; limits are not raised automatically.',
    'network_blocked': 'Verify the selected network mode, routes and shared mounts at the VM console.',
    'manifest_unavailable': 'Prepare the approved metadata/job before disconnecting; keep existing data unchanged.',
    'release_mismatch': 'Review source/manifest identity; preserve the old release and prepare a new one.',
    'already_claimed': 'Use report to inspect this job; automatic retries are disabled.',
    'dependency_mismatch': 'Review the existing LAB Python/dependency environment; no packages were installed.',
    'approval_required': 'Run test yourself in a separate interactive Windows terminal.',
    'ssh_unavailable': 'Check the approved connection at the console; networking is never changed automatically.',
    'audit_response_invalid': 'The audit response failed schema validation. Preserve the installed helper and review it at the console; no raw response is displayed.'}


def packet(job, archive, manifest):
    pieces = [jobs.encoded(job), manifest.read_bytes(), archive.read_bytes()]
    if any(len(data) > limit for data, limit in zip(pieces, (MAX_REPORT, 512 * 1024, 40 * 1024 * 1024))):
        raise ValueError('release_mismatch')
    if jobs.sha(pieces[1]) != job['manifest_sha256'] or jobs.sha(pieces[2]) != job['archive_sha256']:
        raise ValueError('release_mismatch')
    return b''.join(len(data).to_bytes(4, 'big') + data for data in pieces)


def exchange(command, payload=b''):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('approval_required')
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    environment = os.environ.copy()
    for name in ('SSH_ASKPASS', 'SSH_AUTH_SOCK', 'SSH_ASKPASS_PROMPT'):
        environment.pop(name, None)
    environment['SSH_ASKPASS_REQUIRE'] = 'never'
    with subprocess.Popen([ctl.SSH, *ctl.ADMIN_SECURITY, ctl.ADMIN, command], cwd=ctl.REPO,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment) as process:
        def drain(pipe, bucket, prompt=False):
            while True:
                chunk = pipe.read(1 if prompt else 4096)
                if not chunk:
                    return
                if len(bucket) + len(chunk) > MAX_REPORT:
                    exceeded.set()
                    process.kill()
                    return
                bucket.extend(chunk)
                if prompt and bytes(bucket).endswith(b'password: '):
                    sys.stderr.write('OpenSSH authentication required in this operator terminal.\n')
                    sys.stderr.flush()
        def send():
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        readers = [threading.Thread(target=drain, args=(pipe, bucket, index == 1), daemon=True)
            for index, (pipe, bucket) in enumerate(zip((process.stdout, process.stderr), buffers))]
        writer = threading.Thread(target=send, daemon=True)
        for thread in [*readers, writer]:
            thread.start()
        try:
            code = process.wait(timeout=240)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise ValueError('ssh_unavailable') from None
        for thread in [*readers, writer]:
            thread.join(timeout=2)
        if exceeded.is_set() or any(thread.is_alive() for thread in [*readers, writer]):
            raise ValueError('report_invalid')
        if code != 0:
            try:
                failure = parse_json(bytes(buffers[0]))
                if isinstance(failure, dict) and set(failure) == {'status', 'reason'} and failure['status'] in ('blocked', 'interrupted') and isinstance(failure['reason'], str) and failure['reason'] in jobs.REASONS:
                    raise ValueError(failure['reason'])
            except (json.JSONDecodeError, UnicodeError):
                pass
            raise ValueError('ssh_unavailable')
    return parse_json(bytes(buffers[0]))


def save_pending(job):
    jobs.validate_job(job)
    folder = jobs.trusted_path(STATE / job['job_id'])
    folder.mkdir(parents=True, exist_ok=True)
    jobs.immutable(folder / 'job.json', job)
    pointer = jobs.trusted_path(STATE / 'last.json')
    descriptor, filename = tempfile.mkstemp(prefix='last-', suffix='.tmp', dir=STATE)
    temporary = Path(filename)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(jobs.encoded({'job_id': job['job_id']}))
    os.replace(temporary, pointer)


def local_job(job_id=None):
    if job_id is None:
        try:
            job_id = parse_json(side_read(jobs.trusted_path(STATE / 'last.json')))['job_id']
        except FileNotFoundError:
            raise ValueError('job_unavailable') from None
    if not isinstance(job_id, str) or not jobs.HEX.fullmatch(job_id):
        raise ValueError('job_mismatch')
    return jobs.validate_job(parse_json(side_read(jobs.trusted_path(STATE / job_id / 'job.json'))))


def side_read(path):
    return jobs.side.bounded_read(path, MAX_REPORT)


def save_result(value, job):
    jobs.validate_result(value, job)
    folder = jobs.trusted_path(STATE / job['job_id'])
    jobs.immutable(folder / (value['status'] + '.json'), value)


def test(*, mode, kind):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('approval_required')
    if kind in jobs.PDF_KINDS and mode != 'offline':
        raise ValueError('job_mismatch')
    if mode != 'offline':
        ctl.clean_repo()
    ctl.run([sys.executable, str(ctl.REPO / 'scripts/lab/check_local.py'), '--save'], capture=True)
    with redirect_stdout(io.StringIO()):
        if mode == 'offline':
            from gateway_snapshot import prepare as snapshot_prepare
            commit, archive, manifest, _ = snapshot_prepare(normalize=True)
        else:
            commit, archive, manifest = ctl.prepare()
    print('PASS: local source, security and dependency checks; immutable package verified.')
    code, raw = ctl.audit_request('status')
    if code:
        raise ValueError('ssh_unavailable')
    status = validate_status(parse_json(raw))
    if not status.get('runner', {}).get('installed'):
        raise ValueError('setup_required')
    if not status['runner']['host_only_ready']:
        raise ValueError('network_blocked')
    meta = parse_json(manifest.read_bytes())
    if mode == 'offline':
        from offline_prepare import make_job
        job = make_job(commit, manifest, meta, kind)
    else:
        job = jobs.make_job(commit, meta['archive_sha256'], jobs.sha(manifest.read_bytes()), mode=mode, kind=kind)
    payload = packet(job, archive, manifest)
    print(json.dumps({'job_id': job['job_id'], 'commit': commit, 'files': len(meta['files']),
        'archive_sha256': job['archive_sha256'], 'kind': kind, 'mode': mode, 'limits': job['limits'],
        'actions': ['upload_source', 'verify_release', 'queue_offline_job' if mode == 'offline' else 'syntax_and_reviewed_test', 'return_filtered_json'],
        'pdf_execution_now': False, 'dependencies': 'stdlib for syntax/synthetic; full declared stack rechecked by offline PDF preparation'}))
    print('Approve this source/job and filtered JSON return. Hypervisor settings require your review; no networking is changed.')
    if kind in jobs.PDF_KINDS:
        from offline_prepare import cohort_contract
        print(json.dumps({'separate_pdf_approval': cohort_contract(kind), 'queue_metadata_only': True}, sort_keys=True))
    if input('Approve this batch? [y/N]: ').strip().lower() != 'y':
        raise ValueError('approval_required')
    if mode == 'offline':
        with redirect_stdout(io.StringIO()):
            checked_commit, checked_archive, checked_manifest, _ = snapshot_prepare(normalize=True)
        if checked_commit != commit or jobs.sha(checked_archive.read_bytes()) != job['archive_sha256'] or jobs.sha(checked_manifest.read_bytes()) != job['manifest_sha256']:
            raise ValueError('release_mismatch')
    else:
        ctl.clean_repo()
    if ctl.revision() != commit:
        raise ValueError('release_mismatch')
    save_pending(job)
    value = exchange(f'{REMOTE} receive {job["job_id"]}', payload)
    save_result(value, job)
    print(json.dumps(value, sort_keys=True))
    if value['status'] not in ('passed', 'queued'):
        raise ValueError('worker_failed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('status', 'prepare', 'test', 'report', 'setup', 'verify', 'doctor'))
    parser.add_argument('--mode', choices=('host-only', 'offline', 'syntax', 'synthetic'), default='host-only')
    parser.add_argument('--kind', choices=tuple(sorted(jobs.KINDS)), default='synthetic')
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--job-id')
    parser.add_argument('--gateway', action='store_true')
    parser.add_argument('--operator', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'doctor':
        from gateway_client import main as gateway_main
        return gateway_main(['doctor', *(['--offline'] if args.mode == 'offline' else [])])
    if args.mode in ('syntax', 'synthetic'):
        args.kind, args.mode = args.mode, 'host-only'
    if args.command in ('verify',) or args.command in ('setup', 'prepare') and args.gateway or args.command == 'test' and args.mode != 'offline' and not args.operator:
        from gateway_client import main as gateway_main
        command = 'test' if args.command == 'test' else args.command
        profile = args.mode if args.mode in ('syntax', 'synthetic') else args.kind
        if command == 'test' and profile not in ('syntax', 'synthetic'):
            print(json.dumps({'status': 'NOT READY', 'reason': 'profile_not_approved'}))
            return 3
        return gateway_main([command, '--profile', profile if profile in ('syntax', 'synthetic') else 'syntax'])
    if args.command == 'report' and args.mode != 'offline' and not args.operator and not args.job_id:
        import gateway_client
        if (gateway_client.STATE / 'last.json').is_file():
            return gateway_client.main(['report', *(['--refresh'] if args.refresh else [])])
    try:
        if args.command == 'status':
            ctl.status()
        elif args.command == 'prepare':
            if args.mode == 'offline':
                from offline_prepare import prepare
                print(json.dumps(prepare(args.kind), sort_keys=True))
            else:
                ctl.prepare()
        elif args.command == 'setup':
            if args.mode == 'offline':
                from offline_prepare import bootstrap
                print(json.dumps(bootstrap(), sort_keys=True))
            else:
                ctl.bootstrap()
        elif args.command == 'test':
            test(mode=args.mode, kind=args.kind)
        else:
            job = local_job(args.job_id)
            if args.refresh:
                if job['mode'] == 'offline':
                    raise ValueError('export_requires_review')
                value = exchange(f'{REMOTE} report {job["job_id"]}')
                save_result(value, job)
            else:
                folder = STATE / job['job_id']
                paths = [folder / (name + '.json') for name in ('passed', 'partial', 'failed', 'blocked', 'interrupted', 'running', 'queued')]
                path = next((path for path in paths if path.is_file()), None)
                if path is None:
                    raise ValueError('report_pending')
                value = jobs.validate_result(parse_json(side_read(jobs.trusted_path(path))), job)
            print(json.dumps(value, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        message = str(error)
        reason = message if message in jobs.REASONS | {'ssh_unavailable', 'audit_response_invalid', 'job_unavailable', 'report_pending'} else 'source_dirty' if message.startswith('Windows worktree is not clean') else 'source_rejected' if message.startswith(('Unsafe blob', 'Release size', 'Check failed')) else 'worker_failed'
        print(json.dumps({'status': 'blocked', 'reason': reason, 'fix': FIXES.get(reason, 'Review the saved job and its bounded diagnostics at the LAB console.')}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
