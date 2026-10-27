"""Forced-command submissions and a separately sandboxed, unprivileged worker."""

from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import ast
import errno
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile

import gateway_contract as contract
import lab_jobs as jobs
import lab_side as side
import lab_diagnostics as diagnostics
from lab_contract import MAX_REPORT, parse_json
from lab_runner import read_frame

ROOT = Path('/var/lib/malpdf-gateway')
CONFIG = Path('/etc/malpdf/gateway.json')
VERIFIED = Path('/etc/malpdf/gateway-verified.json')
HELPERS = ('gateway_contract.py', 'gateway_harness.py', 'lab_gateway.py', 'lab_contract.py',
           'lab_side.py', 'lab_jobs.py', 'lab_guard.py', 'lab_runner.py', 'lab_readonly.py', 'lab_diagnostics.py')
UNIT_NAMES = ('malpdf-gateway.service', 'malpdf-gateway-probe.service', 'malpdf-gateway.timer')


class UnsafeInstallation(ValueError):
    def __init__(self):
        super().__init__('setup_required')


class ContainmentFailure(ValueError):
    def __init__(self, reason):
        super().__init__(reason if reason in diagnostics.CONTAINMENT_REASONS else 'containment_failed')


def root_json(path):
    root_file(path)
    return parse_json(side.bounded_read(path, 32768))


def root_file(path):
    try:
        jobs.trusted_path(path)
    except ValueError:
        raise UnsafeInstallation() from None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise UnsafeInstallation()
    return path


def policy_hashes():
    base = Path(__file__).resolve().parent
    return {name: contract.sha(side.bounded_read(root_file(base / name), 2 * 1024**2)) for name in HELPERS}


def load_config(*, worker=False):
    if sys.platform != 'linux':
        raise ValueError('setup_required')
    value = root_json(Path('/gateway.json') if worker else CONFIG)
    if not isinstance(value, dict) or set(value) != {'api', 'runner_uid', 'worker_uid', 'policy', 'policy_sha256', 'profiles', 'units', 'sshd_sha256'} or type(value['api']) is not int or value['api'] != 1:
        raise ValueError('setup_required')
    if any(type(value[name]) is not int or value[name] < 1000 for name in ('runner_uid', 'worker_uid')) or value['runner_uid'] == value['worker_uid']:
        raise ValueError('setup_required')
    if value['profiles'] not in (['syntax'], ['syntax', 'synthetic']):
        raise ValueError('setup_required')
    for name, expected in (('policy', HELPERS), ('units', UNIT_NAMES)):
        entries = value[name]
        if not isinstance(entries, dict) or set(entries) != set(expected) or any(not isinstance(digest, str) or not contract.HEX.fullmatch(digest) for digest in entries.values()):
            raise ValueError('setup_required')
    if any(not isinstance(value[name], str) or not contract.HEX.fullmatch(value[name]) for name in ('policy_sha256', 'sshd_sha256')):
        raise ValueError('setup_required')
    return value


def verify_policy(value, actual):
    if value['policy'] != actual or value['policy_sha256'] != contract.sha(contract.encoded(actual)):
        raise ValueError('gateway_not_verified')


def verify_units(value):
    for name, expected in value['units'].items():
        path = root_file(Path('/etc/systemd/system') / name)
        if contract.sha(side.bounded_read(path, 32768)) != expected:
            raise ValueError('gateway_not_verified')


def verify_sshd(value):
    dropin = root_file(Path('/etc/ssh/sshd_config.d/00-malpdf-runner.conf'))
    if contract.sha(side.bounded_read(dropin, 16384)) != value['sshd_sha256']:
        raise ValueError('gateway_not_verified')


def config(*, worker=False):
    value = load_config(worker=worker)
    verify_policy(value, policy_hashes())
    if not worker:
        verify_units(value)
        verify_sshd(value)
    return value


def verified(cfg, *, worker=False):
    value = root_json(Path('/verified.json') if worker else VERIFIED)
    if not isinstance(value, dict) or type(value.get('api')) is not int or value.get('verified') is not True or value != {'api': 1, 'verified': True, 'policy_sha256': cfg['policy_sha256'], 'profiles': cfg['profiles'], 'units': cfg['units'], 'sshd_sha256': cfg['sshd_sha256']}:
        raise ValueError('gateway_not_verified')


def configuration_checks():
    checks = {name: 'not_checked' for name in ('configuration', 'helpers', 'policy', 'units', 'sshd', 'proof')}
    cfg = actual = None
    for name in checks:
        try:
            if name == 'configuration':
                cfg = load_config()
            elif name == 'helpers':
                actual = policy_hashes()
            elif cfg is None or name == 'policy' and actual is None:
                continue
            elif name == 'policy':
                verify_policy(cfg, actual)
            elif name == 'units':
                verify_units(cfg)
            elif name == 'sshd':
                verify_sshd(cfg)
            else:
                verified(cfg)
        except FileNotFoundError:
            checks[name] = 'missing'
        except PermissionError:
            checks[name] = 'unreadable'
        except UnsafeInstallation:
            checks[name] = 'unsafe'
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            checks[name] = 'mismatch' if isinstance(error, ValueError) and str(error) == 'gateway_not_verified' else 'invalid'
        else:
            checks[name] = 'passed'
    return checks


def capability():
    value = {'api': 1, 'installed': False, 'verified': False, 'profiles': [], 'policy_sha256': None, 'reason': 'setup_required'}
    try:
        cfg = config()
        value.update(installed=True, policy_sha256=cfg['policy_sha256'])
        verified(cfg)
        jobs.preflight('host-only')
        value.update(verified=True, profiles=cfg['profiles'], reason=None)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        value['reason'] = str(error) if str(error) in contract.REASONS else 'gateway_not_verified'
    return contract.validate_capability(value)


def command(original):
    for profile in sorted(contract.PROFILES):
        prefix = 'submit-' + profile + ' '
        if original.startswith(prefix) and contract.HEX.fullmatch(original[len(prefix):]):
            return profile, original[len(prefix):]
    raise ValueError('job_mismatch')


def paths(*, worker=False):
    return (Path('/source'), Path('/worker'), Path('/reports')) if worker else (ROOT / 'uploads', ROOT / 'worker', ROOT / 'reports')


@contextmanager
def release(job, *, worker=False):
    uploads, _, _ = paths(worker=worker)
    slot = jobs.trusted_path(uploads / job['manifest_sha256'])
    previous = side.INBOX, side.RELEASES
    side.INBOX, side.RELEASES = slot / 'inbox', slot / 'releases'
    try:
        yield slot
    finally:
        side.INBOX, side.RELEASES = previous


def acknowledge(job):
    return {'api': 1, 'job_id': job['job_id'], 'accepted': True}


@contextmanager
def submission_lock(uid):
    import fcntl
    path = jobs.trusted_path(ROOT / 'submit.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise ValueError('setup_required')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('resource_unavailable') from None
        yield
    finally:
        os.close(descriptor)


def receive(stream, profile, job_id):
    cfg = config()
    verified(cfg)
    if os.getuid() != cfg['runner_uid'] or profile not in cfg['profiles']:
        raise ValueError('profile_not_approved')
    with submission_lock(cfg['runner_uid']):
        return receive_locked(stream, profile, job_id, cfg)


def receive_locked(stream, profile, job_id, cfg):
    jobs.preflight('host-only')
    job = contract.validate_job(parse_json(read_frame(stream, MAX_REPORT)))
    if job['job_id'] != job_id or job['profile'] != profile or job['policy_sha256'] != cfg['policy_sha256']:
        raise ValueError('job_mismatch')
    manifest = read_frame(stream, 512 * 1024)
    archive = read_frame(stream, 40 * 1024**2)
    if stream.read(1) or contract.sha(manifest) != job['manifest_sha256'] or contract.sha(archive) != job['archive_sha256']:
        raise ValueError('source_rejected')
    metadata = parse_json(manifest)
    if not isinstance(metadata, dict) or metadata.get('commit') != job['base_commit'] or metadata.get('archive_sha256') != job['archive_sha256']:
        raise ValueError('source_rejected')
    uploads, _, _ = paths()
    jobs.trusted_path(uploads)
    if len(list(uploads.iterdir())) >= 32 and not (uploads / job['manifest_sha256']).exists() or shutil.disk_usage(uploads).free < 256 * 1024**2:
        raise ValueError('resource_unavailable')
    with release(job) as slot:
        slot.mkdir(mode=0o2750, exist_ok=True)
        side.INBOX.mkdir(mode=0o2750, exist_ok=True)
        for suffix, payload in (('.json', manifest), ('.tar', archive)):
            path = jobs.trusted_path(side.INBOX / (job['base_commit'] + suffix))
            if path.exists():
                if side.bounded_read(path, 40 * 1024**2) != payload:
                    raise ValueError('source_rejected')
            else:
                with path.open('xb') as output:
                    output.write(payload)
                path.chmod(0o640)
        if not (side.RELEASES / job['base_commit']).exists():
            with redirect_stdout(io.StringIO()):
                side.install(job['base_commit'])
            (side.RELEASES / job['base_commit']).chmod(0o750)
        side.verify_release(job['base_commit'], job['manifest_sha256'])
    request = jobs.trusted_path(ROOT / 'requests' / (job_id + '.json'))
    queued = jobs.trusted_path(ROOT / 'queued' / (job_id + '.json'))
    jobs.immutable(request, job)
    if not queued.exists():
        value = contract.result(job, 'queued')
        jobs.immutable(queued, value)
        diagnostics.write_latest(ROOT / 'queued/last-job.json', value, diagnostics.validate_job_result)
    contract.validate_result(parse_json(side.bounded_read(queued, MAX_REPORT)), job)
    return acknowledge(job)


def audit(job_id):
    if not contract.HEX.fullmatch(job_id):
        raise ValueError('job_mismatch')
    queued = jobs.trusted_path(ROOT / 'queued' / (job_id + '.json'))
    value = parse_json(side.bounded_read(queued, MAX_REPORT))
    job = contract.validate_job(value['job'])
    if job['job_id'] != job_id:
        raise ValueError('report_invalid')
    contract.validate_result(value, job)
    for suffix in ('.json', '.running.json'):
        path = jobs.trusted_path(ROOT / 'reports' / (job_id + suffix))
        if path.exists():
            value = contract.validate_result(parse_json(side.bounded_read(path, MAX_REPORT)), job)
            if value['status'] == 'running':
                started = datetime.strptime(value['generated_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - started).total_seconds() > 120:
                    value = {**value, 'status': 'interrupted', 'reason': 'already_claimed'}
            return contract.validate_result(value, job)
    return value


def cgroup_limits(cgroup):
    values = {}
    for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max'):
        try:
            descriptor = os.open(cgroup / name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError('unexpected_cgroup_type')
                payload = stream.read(129)
            if len(payload) > 128:
                raise ValueError('oversize_cgroup_value')
            values[name] = payload.decode('ascii').strip()
        except (OSError, ValueError, UnicodeError):
            raise ContainmentFailure('containment_cgroup_unavailable') from None
    try:
        memory = int(values['memory.max'])
    except ValueError:
        raise ContainmentFailure('containment_cgroup_memory_failed') from None
    if not 0 < memory <= contract.LIMITS['memory_bytes']:
        raise ContainmentFailure('containment_cgroup_memory_failed')
    if values['memory.swap.max'] != '0':
        raise ContainmentFailure('containment_cgroup_swap_failed')
    try:
        tasks = int(values['pids.max'])
    except ValueError:
        raise ContainmentFailure('containment_cgroup_tasks_failed') from None
    if not 0 < tasks <= contract.LIMITS['tasks']:
        raise ContainmentFailure('containment_cgroup_tasks_failed')
    try:
        quota, period = map(int, values['cpu.max'].split())
    except ValueError:
        raise ContainmentFailure('containment_cgroup_cpu_failed') from None
    if quota <= 0 or period <= 0 or quota * 2 > period:
        raise ContainmentFailure('containment_cgroup_cpu_failed')


def host_paths_hidden():
    for path in ('/home/remnux', '/root', '/etc/passwd', '/run/ssh-agent', '/mnt/hgfs'):
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.EACCES, errno.EPERM):
                raise ContainmentFailure('containment_paths_failed') from None
        else:
            os.close(descriptor)
            raise ContainmentFailure('containment_paths_failed')


def rlimit_checks():
    import resource
    for name, maximum in ((resource.RLIMIT_AS, contract.LIMITS['memory_bytes']),
            (resource.RLIMIT_CPU, contract.LIMITS['cpu_seconds']), (resource.RLIMIT_NOFILE, 64),
            (resource.RLIMIT_NPROC, contract.LIMITS['tasks']), (resource.RLIMIT_FSIZE, 1048576)):
        soft, hard = resource.getrlimit(name)
        if any(type(value) is not int or value == resource.RLIM_INFINITY or not 0 < value <= maximum for value in (soft, hard)) or soft > hard:
            raise ContainmentFailure('containment_rlimits_failed')
    core = resource.getrlimit(resource.RLIMIT_CORE)
    if core != (0, 0) or any(type(value) is not int for value in core):
        raise ContainmentFailure('containment_rlimits_failed')


def containment(cfg):
    if os.getuid() != cfg['worker_uid'] or os.getuid() == 0:
        raise ContainmentFailure('containment_uid_failed')
    host_paths_hidden()
    rlimit_checks()
    cgroup_limits(Path('/limits'))
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            value = socket.socket(family, socket.SOCK_STREAM)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT):
                raise ContainmentFailure('containment_network_failed') from None
        else:
            value.close()
            raise ContainmentFailure('containment_network_failed')
    probe = Path('/source') / ('probe-' + os.urandom(8).hex())
    try:
        descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno not in (errno.EROFS, errno.EACCES):
            raise ContainmentFailure('containment_source_failed') from None
    else:
        os.close(descriptor)
        probe.unlink()
        raise ContainmentFailure('containment_source_failed')
    return {'api': 1, 'policy_sha256': cfg['policy_sha256'], 'checks': {'nonroot': True, 'network_denied': True, 'source_readonly': True, 'host_data_hidden': True, 'resource_limits': True}}


def synthetic(source):
    with tempfile.TemporaryDirectory(prefix='pinned-lexer-') as temporary, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': temporary, 'TMPDIR': temporary}
        process = subprocess.Popen(['/usr/bin/python3', '-Es', '-B', str(Path(__file__).with_name('gateway_harness.py')), str(source)],
            cwd=temporary, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, start_new_session=True)
        try:
            code = process.wait(timeout=30)
        except BaseException:
            jobs.stop_worker(process)
            raise
        output.seek(0)
        value = parse_json(output.read(4097))
    if not isinstance(value, dict) or set(value) != {'passed', 'failed'} or any(type(count) is not int or count < 0 for count in value.values()) or sum(value.values()) != contract.SYNTHETIC_CASES or code != (1 if value['failed'] else 0):
        raise ValueError('worker_failed')
    return value


def work():
    cfg = config(worker=True)
    verified(cfg, worker=True)
    containment(cfg)
    uploads, state, reports = paths(worker=True)
    requests = sorted(uploads.parent.glob('requests/*.json')) if uploads != Path('/source') else sorted(Path('/requests').glob('*.json'))
    if len(requests) > 64:
        raise ValueError('resource_unavailable')
    for request in requests:
        job = contract.validate_job(parse_json(side.bounded_read(request, MAX_REPORT)))
        if request.stem != job['job_id']:
            raise ValueError('job_mismatch')
        claim = jobs.trusted_path(state / (job['job_id'] + '.claim'))
        if claim.exists():
            continue
        with claim.open('x') as output:
            output.write(job['job_id'])
        running = contract.result(job, 'running')
        jobs.immutable(reports / (job['job_id'] + '.running.json'), running)
        diagnostics.write_latest(reports / 'last-job.json', running, diagnostics.validate_job_result)
        approved = job['profile'] in cfg['profiles'] and job['policy_sha256'] == cfg['policy_sha256']
        try:
            if not approved:
                raise ValueError('profile_not_approved')
            with release(job, worker=True):
                metadata = side.verify_release(job['base_commit'], job['manifest_sha256'])
                source = side.RELEASES / job['base_commit']
                counts = {'passed': 0, 'failed': 0}
                for item in metadata['files']:
                    if item['path'].endswith('.py'):
                        try:
                            ast.parse(side.bounded_read(source / item['path'], 2 * 1024**2).decode('utf-8-sig'))
                        except (SyntaxError, UnicodeError, ValueError, RecursionError):
                            counts['failed'] += 1
                        else:
                            counts['passed'] += 1
                extra = synthetic(source) if job['profile'] == 'synthetic' and not counts['failed'] else None
                passed = counts['passed'] > 0 and not counts['failed'] and (job['profile'] == 'syntax' or extra == {'passed': 6, 'failed': 0})
                value = contract.result(job, 'passed' if passed else 'failed', syntax=counts, synthetic=extra)
        except (OSError, ValueError, subprocess.SubprocessError, MemoryError, RecursionError):
            value = contract.result(job, 'failed', reason='worker_failed' if approved else 'profile_not_approved')
        jobs.immutable(reports / (job['job_id'] + '.json'), value)
        diagnostics.write_latest(reports / 'last-job.json', value, diagnostics.validate_job_result)
        return value


def run_probe():
    cfg = None
    phase = 'configuration'
    try:
        cfg = config(worker=True)
        phase = 'containment'
        proof = containment(cfg)
        diagnostics.write_latest(Path('/reports/probe.json'), proof, lambda value: value)
        value = {'api': 1, 'status': 'passed', 'phase': 'complete', 'reason': None,
                 'policy_sha256': cfg['policy_sha256'], 'job_id': None, 'generated_utc': diagnostics.stamp()}
        code = 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, MemoryError, RecursionError) as error:
        reason = str(error) if isinstance(error, ContainmentFailure) else phase + '_failed'
        value = {'api': 1, 'status': 'failed', 'phase': phase, 'reason': reason,
                 'policy_sha256': cfg['policy_sha256'] if cfg else None, 'job_id': None, 'generated_utc': diagnostics.stamp()}
        code = 1
    diagnostics.write_latest(Path('/reports/probe-status.json'), value, diagnostics.validate_run)
    return code


def run_worker():
    try:
        result = work()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, MemoryError, RecursionError) as error:
        reason = str(error) if isinstance(error, ContainmentFailure) else 'worker_failed'
        value = {'api': 1, 'status': 'failed', 'phase': 'containment' if isinstance(error, ContainmentFailure) else 'poll', 'reason': reason,
                 'policy_sha256': None, 'job_id': None, 'generated_utc': diagnostics.stamp()}
        code = 1
    else:
        failed = result is not None and result['status'] != 'passed'
        value = {'api': 1, 'status': 'idle' if result is None else 'failed' if failed else 'passed',
                 'phase': 'poll' if result is None else 'job', 'reason': 'job_failed' if failed else None,
                 'policy_sha256': result['job']['policy_sha256'] if result else None,
                 'job_id': result['job']['job_id'] if result else None, 'generated_utc': diagnostics.stamp()}
        code = 0
    diagnostics.write_latest(Path('/reports/worker-status.json'), value, diagnostics.validate_run)
    return code


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ('worker', 'probe'):
        os.umask(0o027)
        if sys.argv[1] == 'worker':
            return run_worker()
        return run_probe()
    if os.environ.get('SSH_ORIGINAL_COMMAND') == 'probe':
        value = capability()
        print(json.dumps(value, separators=(',', ':')))
        return 0 if value['verified'] else 3
    try:
        profile, identity = command(os.environ.get('SSH_ORIGINAL_COMMAND', ''))
    except (TypeError, ValueError):
        return 2
    if sys.platform != 'linux':
        return 2
    import resource
    for limit, amount in ((resource.RLIMIT_AS, 536870912), (resource.RLIMIT_CPU, 30), (resource.RLIMIT_FSIZE, 41943040), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 32), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(limit, (amount, amount))
    os.umask(0o027)
    signal.alarm(60)
    try:
        print(json.dumps(receive(sys.stdin.buffer, profile, identity), separators=(',', ':')))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, MemoryError, RecursionError) as error:
        reason = str(error) if str(error) in contract.REASONS else 'source_rejected'
        print(json.dumps({'api': 1, 'status': 'blocked', 'reason': reason}))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
