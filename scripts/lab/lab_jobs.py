"""Fixed job contracts and fail-closed LAB operations; no arbitrary commands."""

from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import math
import time
import tempfile

import lab_side as side
from lab_contract import MAX_REPORT, REV_RE, parse_json, validate_report

API = 1
JOBS = Path('/var/lib/malpdf/jobs')
CONFIG = Path('/etc/malpdf/runner.json')
HEX = re.compile(r'[0-9a-f]{64}\Z')
PDF_KINDS = {'pdf-static', 'pdf-static-cve', 'pdf-static-cic-full'}
KINDS = {'syntax', 'synthetic', *PDF_KINDS}
LIMITS = {'wall_seconds': 1800, 'file_wall_seconds': 60, 'file_cpu_seconds': 45,
          'file_memory_bytes': 1073741824, 'file_max_bytes': 10485760,
          'samples': 64, 'workers': 5, 'output_bytes': 536870912}
REASONS = {'network_blocked', 'runtime_unavailable', 'manifest_unavailable', 'release_mismatch',
           'already_claimed', 'dependency_mismatch', 'resource_unavailable', 'worker_timeout',
           'worker_failed', 'report_invalid', 'setup_required', 'approval_required', 'job_mismatch'}
REASONS.update({'export_requires_review', 'credential_present'})
PDF_STATUSES = frozenset({'observed', 'absent_within_scope', 'partial', 'decode_error', 'unsupported',
                          'encrypted', 'timeout', 'resource_limit', 'not_run', 'bounded_complete'})
SUMMARY_COUNTS = ('completed', 'observed', 'partial', 'failed', 'primary_available', 'timeout',
                  'elapsed_ms', 'peak_rss_bytes')
SUMMARY_FIELDS = {*SUMMARY_COUNTS, 'planned', 'status_counts'}
MAX_CREDENTIAL_REASONS = 12


def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def legacy_summary_valid(summary):
    fields = {*SUMMARY_COUNTS, 'planned'}
    if not isinstance(summary, dict) or set(summary) != fields or any(type(summary[name]) is not int or not 0 <= summary[name] <= 10**12 for name in fields):
        return False
    return (summary['completed'] <= summary['planned'] and summary['primary_available'] <= summary['completed']
            and summary['timeout'] <= summary['completed']
            and summary['observed'] + summary['partial'] + summary['failed'] == summary['completed'])


def status_bucket(name):
    return 'observed' if name in ('observed', 'bounded_complete') else name if name == 'partial' else 'failed'


def summary_valid(summary):
    if not isinstance(summary, dict) or any(type(summary.get(name)) is not int or not 0 <= summary[name] <= 10**12 for name in SUMMARY_COUNTS):
        return False
    if 'bounded_complete' in summary and (type(summary['bounded_complete']) is not int or not 0 <= summary['bounded_complete'] <= summary['observed']):
        return False
    counts = summary.get('status_counts')
    if not isinstance(counts, dict) or any(not isinstance(name, str) or name not in PDF_STATUSES or type(amount) is not int or not 0 <= amount <= 10**12 for name, amount in counts.items()):
        return False
    buckets = {}
    for name, amount in counts.items():
        key = status_bucket(name)
        buckets[key] = buckets.get(key, 0) + amount
    return (sum(counts.values()) == summary['completed'] == summary['observed'] + summary['partial'] + summary['failed']
            and all(buckets.get(name, 0) == summary[name] for name in ('observed', 'partial', 'failed')))


def policy(kind):
    if kind == 'pdf-static':
        return LIMITS.copy()
    if kind == 'pdf-static-cic-full':
        return {**LIMITS, 'samples': 1452, 'wall_seconds': 7200, 'workers': 10,
                'file_wall_seconds': 35, 'file_cpu_seconds': 30, 'output_bytes': 2 * 1024**3}
    if kind == 'pdf-static-cve':
        return {**LIMITS, 'samples': 5, 'wall_seconds': 180, 'output_bytes': 40 * 1024**2}
    return {**LIMITS, 'wall_seconds': 240, 'file_wall_seconds': 90 if kind == 'synthetic' else 60,
            'file_cpu_seconds': 60 if kind == 'synthetic' else 30,
            'file_memory_bytes': 256 * 1024**2 if kind == 'synthetic' else 512 * 1024**2,
            'file_max_bytes': 2 * 1024**2, 'samples': 1, 'output_bytes': 2 * 1024**2}


@contextmanager
def execution_limits(kind):
    import resource
    import signal
    usage = resource.getrusage(resource.RUSAGE_SELF)
    bounds = ((resource.RLIMIT_AS, 512 * 1024**2),
              (resource.RLIMIT_CPU, math.ceil(usage.ru_utime + usage.ru_stime) + 120),
              (resource.RLIMIT_FSIZE, 64 * 1024**2), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 2048))
    old = {name: resource.getrlimit(name) for name, _ in bounds}
    signals = {name: signal.getsignal(name) for name in (signal.SIGALRM, signal.SIGXCPU)}
    def expired(*args):
        raise ValueError('worker_timeout')
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    try:
        for name, amount in bounds:
            hard = old[name][1]
            resource.setrlimit(name, (amount if hard == resource.RLIM_INFINITY else min(amount, hard), hard))
        for name in signals:
            signal.signal(name, expired)
        wall = policy(kind)['wall_seconds'] + 5 if kind in PDF_KINDS else 230
        signal.setitimer(signal.ITIMER_REAL, min(wall, previous_timer[0]) if previous_timer[0] else wall)
        yield
    finally:
        remaining = max(0.001, previous_timer[0] - (time.monotonic() - started)) if previous_timer[0] else 0
        signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])
        for name, handler in signals.items():
            signal.signal(name, handler)
        for name, limits in old.items():
            resource.setrlimit(name, limits)


def make_job(commit, archive_sha256, manifest_sha256, *, mode='host-only', kind='synthetic', attempt=None):
    body = {'schema_version': 1, 'api': API, 'commit': commit, 'archive_sha256': archive_sha256,
            'manifest_sha256': manifest_sha256, 'mode': mode, 'kind': kind, 'limits': policy(kind), 'attempt': attempt or uuid.uuid4().hex}
    return validate_job({**body, 'job_id': sha(encoded(body))})


def validate_job(job):
    fields = {'schema_version', 'api', 'commit', 'archive_sha256', 'manifest_sha256', 'mode', 'kind', 'limits', 'job_id', 'attempt'}
    if not isinstance(job, dict) or set(job) != fields or type(job['schema_version']) is not int or job['schema_version'] != 1 or type(job['api']) is not int or job['api'] != API:
        raise ValueError('job_mismatch')
    if not isinstance(job['commit'], str) or not REV_RE.fullmatch(job['commit']):
        raise ValueError('job_mismatch')
    if not isinstance(job['attempt'], str) or not re.fullmatch(r'[0-9a-f]{32}', job['attempt']):
        raise ValueError('job_mismatch')
    if any(not isinstance(job[name], str) or not HEX.fullmatch(job[name]) for name in ('archive_sha256', 'manifest_sha256', 'job_id')):
        raise ValueError('job_mismatch')
    if not isinstance(job['kind'], str) or not isinstance(job['mode'], str) or job['mode'] not in ('host-only', 'offline') or job['kind'] not in KINDS or job['kind'] in PDF_KINDS and job['mode'] != 'offline':
        raise ValueError('job_mismatch')
    if type(job['limits']) is not dict or job['limits'] != policy(job['kind']) or any(type(value) is not int for value in job['limits'].values()):
        raise ValueError('job_mismatch')
    if sha(encoded({name: value for name, value in job.items() if name != 'job_id'})) != job['job_id']:
        raise ValueError('job_mismatch')
    return job


def trusted_path(path):
    path = Path(path).absolute()
    if path.resolve() != path or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('setup_required')
    return path


def config():
    path = trusted_path(CONFIG)
    info = path.stat()
    if sys.platform != 'linux' or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('setup_required')
    value = parse_json(side.bounded_read(path, 8192))
    if set(value) != {'schema_version', 'data_root', 'python', 'uid'} or value['schema_version'] != 1 or type(value['uid']) is not int or value['uid'] < 1000 or os.getuid() != value['uid']:
        raise ValueError('setup_required')
    for key in ('data_root', 'python'):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
            raise ValueError('setup_required')
        trusted_path(Path(value[key]).parent if key == 'python' else value[key])
    if not Path(value['python']).is_file():
        raise ValueError('dependency_mismatch')
    return value


def guard_module():
    installed = Path(__file__).with_name('lab_guard.py')
    path = installed if installed.is_file() else Path(__file__).resolve().parents[2] / 'src/malpdf/static/lab_guard.py'
    spec = importlib.util.spec_from_file_location('malpdf_installed_lab_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_helpers(metadata):
    expected = {item['path']: item['sha256'] for item in metadata['files']}
    for name in ('lab_contract.py', 'lab_readonly.py', 'lab_side.py', 'lab_jobs.py', 'lab_runner.py', 'check_local.py', 'lab_guard.py'):
        relative = 'src/malpdf/static/lab_guard.py' if name == 'lab_guard.py' else 'scripts/lab/' + name
        path = Path(__file__).with_name(name)
        if name == 'lab_guard.py' and not path.is_file():
            path = Path(__file__).resolve().parents[2] / relative
        if path.is_symlink() or relative not in expected or sha(side.bounded_read(path, 2 * 1024**2)) != expected[relative]:
            raise ValueError('setup_required')


def ip_json(*args):
    result = subprocess.run(['/usr/sbin/ip', '-j', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
    if len(result.stdout) > 65536:
        raise ValueError('network_blocked')
    return parse_json(result.stdout)


def route_network(route, version):
    try:
        network = ipaddress.ip_network(route.get('dst', 'default'), strict=False)
    except (TypeError, ValueError):
        raise ValueError('network_blocked') from None
    if network.version != version:
        raise ValueError('network_blocked')
    return network


def host_only_network():
    addresses = ip_json('address', 'show')
    active = [item for item in addresses if item.get('ifname') != 'lo' and 'UP' in item.get('flags', [])]
    if len(active) != 1:
        raise ValueError('network_blocked')
    v4 = [item for item in active[0].get('addr_info', []) if item.get('family') == 'inet']
    if len(v4) != 1 or v4[0].get('local') != '192.168.217.10' or v4[0].get('prefixlen') != 24:
        raise ValueError('network_blocked')
    for item in active[0].get('addr_info', []):
        if item.get('family') == 'inet6' and item.get('scope') != 'link':
            raise ValueError('network_blocked')
    for route in ip_json('-4', 'route', 'show', 'table', 'all'):
        network = route_network(route, 4)
        if route.get('gateway') or not any(network.subnet_of(allowed) for allowed in (ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('192.168.217.0/24'))):
            raise ValueError('network_blocked')
        if route.get('dev') not in ('lo', active[0]['ifname']):
            raise ValueError('network_blocked')
    for route in ip_json('-6', 'route', 'show', 'table', 'all'):
        network = route_network(route, 6)
        if route.get('gateway') or not any(network.subnet_of(allowed) for allowed in (ipaddress.ip_network('fe80::/10'), ipaddress.ip_network('ff00::/8'), ipaddress.ip_network('::1/128'))):
            raise ValueError('network_blocked')


def preflight(mode, *, attested=False):
    if sys.platform != 'linux' or os.getuid() == 0 or not (3, 11) <= sys.version_info[:2] < (3, 14):
        raise ValueError('runtime_unavailable')
    state = guard_module().lab_state()
    if state['shared_mounts'] or state['unknown_interfaces']:
        raise ValueError('network_blocked')
    if mode == 'offline':
        guard_module().require_offline_lab(attested, state=state)
    else:
        host_only_network()
    result = subprocess.run(['/usr/bin/git', '--version'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError('dependency_mismatch')
    return {'mode': mode, 'guest_network_checked': True, 'stdlib_dependencies_checked': True,
            'hypervisor_controls_attested': bool(attested)}


def probe():
    host_ready = offline_ready = False
    try:
        preflight('host-only')
        host_ready = True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        preflight('offline', attested=True)
        offline_ready = True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return {'api': API, 'installed': CONFIG.is_file(), 'host_only_ready': host_ready,
            'offline_guest_ready': offline_ready, 'reason': None if host_ready or offline_ready else 'network_blocked'}


def job_directory(job_id):
    if not isinstance(job_id, str) or not HEX.fullmatch(job_id):
        raise ValueError('job_mismatch')
    return trusted_path(JOBS / job_id)


def immutable(path, value):
    path = trusted_path(path)
    payload = encoded(value) + b'\n'
    if path.exists():
        if side.bounded_read(path, 512 * 1024) != payload:
            raise ValueError('job_mismatch')
        return
    with path.open('xb') as stream:
        stream.write(payload)


def save_job(job):
    validate_job(job)
    directory = job_directory(job['job_id'])
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    immutable(directory / 'job.json', job)
    return directory


def load_job(job_id):
    return validate_job(parse_json(side.bounded_read(job_directory(job_id) / 'job.json', MAX_REPORT)))


def validate_result(value, job):
    validate_job(job)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'job', 'status', 'reason', 'checks', 'pdf_summary', 'preflight', 'generated_utc'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['job'] != job:
        raise ValueError('report_invalid')
    if not isinstance(value['status'], str) or value['status'] not in ('queued', 'running', 'passed', 'partial', 'failed', 'blocked', 'interrupted') or value['reason'] is not None and (not isinstance(value['reason'], str) or value['reason'] not in REASONS):
        raise ValueError('report_invalid')
    if not isinstance(value['checks'], list) or len(value['checks']) > 2:
        raise ValueError('report_invalid')
    for check in value['checks']:
        validate_report(check, job['commit'])
    expected_kinds = ['ast_syntax', 'synthetic_security'] if job['kind'] == 'synthetic' else ['ast_syntax'] if job['kind'] == 'syntax' else []
    if [check['kind'] for check in value['checks']] != expected_kinds[:len(value['checks'])]:
        raise ValueError('report_invalid')
    expected = {'mode', 'guest_network_checked', 'stdlib_dependencies_checked', 'hypervisor_controls_attested'}
    env = value['preflight']
    if not isinstance(env, dict) or set(env) != expected or env['mode'] != job['mode'] or any(type(env[key]) is not bool for key in expected - {'mode'}):
        raise ValueError('report_invalid')
    summary = value['pdf_summary']
    if summary is not None:
        if job['kind'] not in PDF_KINDS or not isinstance(summary, dict) or set(summary) - {'bounded_complete'} != SUMMARY_FIELDS or not summary_valid(summary):
            raise ValueError('report_invalid')
        if summary['planned'] != job['limits']['samples'] or summary['completed'] > summary['planned'] or summary['primary_available'] > summary['completed']:
            raise ValueError('report_invalid')
        if summary['timeout'] > summary['completed'] or summary['elapsed_ms'] > job['limits']['wall_seconds'] * 1000 or summary['peak_rss_bytes'] > 2 * 1024**3:
            raise ValueError('report_invalid')
    if value['status'] == 'queued' and (job['mode'] != 'offline' or value['checks'] or summary is not None):
        raise ValueError('report_invalid')
    if value['status'] in ('passed', 'partial'):
        if not env['guest_network_checked'] or not env['stdlib_dependencies_checked'] or value['reason'] is not None:
            raise ValueError('report_invalid')
        if job['kind'] in PDF_KINDS:
            if summary is None or not env['hypervisor_controls_attested'] or job['mode'] != 'offline':
                raise ValueError('report_invalid')
            if value['status'] == 'passed' and (summary['observed'] != summary['planned'] or summary['primary_available'] != summary['planned']):
                raise ValueError('report_invalid')
        elif len(value['checks']) != (2 if job['kind'] == 'synthetic' else 1):
            raise ValueError('report_invalid')
        elif value['status'] == 'passed' and any(check['status'] != 'passed' for check in value['checks']):
            raise ValueError('report_invalid')
    if not isinstance(value['generated_utc'], str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value['generated_utc']):
        raise ValueError('report_invalid')
    datetime.strptime(value['generated_utc'], '%Y-%m-%dT%H:%M:%SZ')
    if len(encoded(value)) > MAX_REPORT:
        raise ValueError('report_invalid')
    return value


def result(job, status, *, checks=None, summary=None, environment=None, reason=None):
    env = {'mode': job['mode'], 'guest_network_checked': False,
           'stdlib_dependencies_checked': False, 'hypervisor_controls_attested': False}
    return validate_result({'schema_version': 1, 'job': job, 'status': status, 'reason': reason,
        'checks': checks or [], 'pdf_summary': summary, 'preflight': environment or env,
        'generated_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}, job)


def read_result(job_id):
    job = load_job(job_id)
    directory = job_directory(job_id)
    if (directory / 'result.json').is_file():
        return validate_result(parse_json(side.bounded_read(directory / 'result.json', MAX_REPORT)), job)
    if (directory / 'claim.json').is_file():
        claim = parse_json(side.bounded_read(directory / 'claim.json', 4096))
        if not isinstance(claim, dict) or set(claim) != {'job_id', 'parent_pid', 'start_ticks', 'generated_utc', 'hypervisor_controls_attested'} or claim['job_id'] != job_id:
            raise ValueError('report_invalid')
        active = claim.get('start_ticks') is not None and process_identity(claim.get('parent_pid')) == claim.get('start_ticks')
        value = result(job, 'running' if active else 'interrupted', reason=None if active else 'already_claimed')
        value['generated_utc'] = claim['generated_utc']
        return validate_result(value, job)
    if (directory / 'queued.json').is_file():
        return validate_result(parse_json(side.bounded_read(directory / 'queued.json', MAX_REPORT)), job)
    raise ValueError('already_claimed')


def process_identity(pid):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        value = side.bounded_read(Path(f'/proc/{pid}/stat'), 8192).decode('ascii')
        return int(value[value.rfind(')') + 2:].split()[19])
    except (OSError, ValueError, IndexError, UnicodeError):
        return None


def catalog():
    trusted_path(JOBS)
    if not JOBS.is_dir():
        return []
    entries = []
    for index, directory in enumerate(JOBS.iterdir()):
        if index >= 512:
            raise ValueError('resource_unavailable')
        if directory.is_dir() and HEX.fullmatch(directory.name):
            entries.append(directory.name)
    catalogued = []
    for name in sorted(entries):
        try:
            catalogued.append(load_job(name))
        except ValueError as error:
            if str(error) != 'job_mismatch':
                raise
    return catalogued


def pending():
    items = []
    for job in catalog():
        directory = job_directory(job['job_id'])
        if not (directory / 'queued.json').is_file() or (directory / 'result.json').is_file():
            continue
        claim_file = directory / 'claim.json'
        if not claim_file.exists():
            items.append(job)
            continue
        try:
            claim = parse_json(side.bounded_read(claim_file, 4096))
            pid = claim.get('parent_pid')
            ticks = claim.get('start_ticks')
            if pid is None or process_identity(pid) != ticks:
                items.append(job)
        except (OSError, ValueError):
            pass
    return items


def execute(job, *, attested=False, resume=False):
    validate_job(job)
    jobs_config = config()
    if job['kind'] in PDF_KINDS:
        check_credentials(Path(jobs_config['data_root']))
    directory = job_directory(job['job_id'])
    if (directory / 'result.json').exists():
        return read_result(job['job_id'])
    claim_file = directory / 'claim.json'
    if claim_file.exists():
        if not resume:
            raise ValueError('already_claimed')
        try:
            claim = parse_json(side.bounded_read(claim_file, 4096))
            pid = claim.get('parent_pid')
            ticks = claim.get('start_ticks')
            if pid is not None and process_identity(pid) == ticks:
                raise ValueError('already_claimed')
        except (OSError, ValueError):
            raise ValueError('already_claimed')
    environment = preflight(job['mode'], attested=attested)
    metadata = side.verify_release(job['commit'], job['manifest_sha256'])
    verify_helpers(metadata)
    directory = save_job(job)
    claim_payload = {'job_id': job['job_id'], 'parent_pid': os.getpid(),
                     'start_ticks': process_identity(os.getpid()),
                     'generated_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                     'hypervisor_controls_attested': bool(attested)}
    claim_tmp = directory / 'claim.json.tmp'
    with claim_tmp.open('w', encoding='ascii') as stream:
        json.dump(claim_payload, stream)
    os.replace(claim_tmp, claim_file)
    try:
        checks = []
        if job['kind'] in PDF_KINDS:
            summary = pdf_task(job, directory)
            value = result(job, 'passed' if summary['observed'] == summary['primary_available'] == job['limits']['samples'] else 'partial', summary=summary, environment=environment)
        else:
            with redirect_stdout(io.StringIO()):
                checks.append(side.syntax(job['commit']))
                if job['kind'] == 'synthetic' and checks[0]['status'] == 'passed':
                    checks.append(side.synthetic(job['commit']))
            status = 'failed' if any(check['status'] == 'failed' for check in checks) else 'partial' if any(check['status'] == 'partial' for check in checks) else 'passed'
            value = result(job, status, checks=checks, environment=environment)
    except (OSError, ValueError, subprocess.SubprocessError, MemoryError) as error:
        value = result(job, 'failed', environment=environment, reason='worker_timeout' if str(error) == 'worker_timeout' else 'worker_failed')
    immutable(directory / 'result.json', value)
    return value


def pdf_task(job, directory):
    cfg = config()
    if shutil.disk_usage(directory).free < job['limits']['output_bytes'] + 256 * 1024**2:
        raise ValueError('resource_unavailable')
    count = job['limits']['workers']
    deadline = time.monotonic() + job['limits']['wall_seconds']
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(Path.home()),
        'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1'}
    streams, processes = [], []
    outputs = directory / 'private_bundles'
    planned = job['limits']['samples']
    started = time.monotonic()
    last_print = 0.0
    last_completed = -1
    seen_bundles = set()
    if outputs.is_dir():
        for name in os.listdir(outputs):
            if name.endswith('.json') and not name.endswith('.tmp'):
                try:
                    seen_bundles.add(int(name[:-5]))
                except ValueError:
                    pass
    try:
        for shard in range(count):
            stdout, stderr = tempfile.TemporaryFile(), tempfile.TemporaryFile()
            streams.extend((stdout, stderr))
            command = [cfg['python'], '-Es', '-B', str(Path(__file__).with_name('lab_runner.py')),
                'pdf-worker', job['job_id'], '--shard', str(shard), '--of', str(count)]
            processes.append(subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=stderr, start_new_session=True, env=environment))
        while True:
            alive = [process for process in processes if process.poll() is None]
            try:
                completed = len(os.listdir(outputs)) if outputs.is_dir() else 0
            except OSError:
                completed = 0
            if outputs.is_dir():
                for name in sorted(os.listdir(outputs)):
                    if name.endswith('.json') and not name.endswith('.tmp'):
                        try:
                            idx = int(name[:-5])
                            if idx not in seen_bundles:
                                seen_bundles.add(idx)
                                bundle_path = outputs / name
                                try:
                                    bundle_data = parse_json(side.bounded_read(bundle_path, 8 * 1024**2 + 1024))
                                    b_status = bundle_data.get('status', 'complete')
                                except (OSError, ValueError):
                                    b_status = 'observed'
                                icon = '✓' if b_status in ('bounded_complete', 'observed') else '⏱' if b_status in ('timeout', 'timeout_partial') else '!'
                                evasive_tag = ' [Evasive]' if b_status in ('timeout', 'timeout_partial') else ''
                                tag_line = f"[{icon} {idx:04d}/{planned}] PDF {idx:04d} -> {b_status}{evasive_tag} | Workers: {len(alive)}/{count}"
                                if sys.stdout.isatty():
                                    sys.stdout.write(f"\r{tag_line:<80s}\n")
                                    sys.stdout.flush()
                                else:
                                    print(tag_line, flush=True)
                        except ValueError:
                            pass
            try:
                meminfo = side.bounded_read(Path('/proc/meminfo'), 8192).decode('ascii')
                for mline in meminfo.splitlines():
                    if mline.startswith('MemAvailable:'):
                        if int(mline.split()[1]) < 1200 * 1024:
                            time.sleep(0.5)
                        break
            except (OSError, ValueError):
                pass
            now = time.monotonic()
            if now - last_print >= 0.5 or completed != last_completed or not alive:
                last_print = now
                last_completed = completed
                pct = (completed * 100) // planned if planned else 100
                elapsed = int(now - started)
                elapsed_str = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
                active_count = len(alive)
                if completed > 0 and planned > completed:
                    eta_sec = int((planned - completed) * (now - started) / completed)
                    eta_str = f"~{eta_sec // 60:02d}:{eta_sec % 60:02d}"
                elif completed >= planned:
                    eta_str = "00:00"
                else:
                    eta_str = "--:--"
                message = f"Tien trinh: {completed}/{planned} ({pct}%) | Da chay: {elapsed_str} | Con lai: {eta_str} | Workers: {active_count}/{count}"
                if sys.stdout.isatty():
                    sys.stdout.write(f"\r{message:<80s}")
                    sys.stdout.flush()
                elif completed != last_completed or not alive:
                    print(message, flush=True)
            if not alive:
                break
            if now > deadline:
                raise subprocess.TimeoutExpired(command, deadline - started)
            time.sleep(0.2)
        if sys.stdout.isatty():
            sys.stdout.write("\n\a\a")
            banner = [
                "=" * 80,
                f"                    MALPDF EXTRACTION COMPLETED SUCCESSFULLY                   ",
                "=" * 80,
                f"  Job ID:        {job['job_id']}",
                f"  Total Samples: {last_completed} / {planned} ({pct}%)",
                f"  Elapsed Time:  {elapsed_str}",
                f"  Workers:       {count} workers",
                "=" * 80,
            ]
            sys.stdout.write("\n".join(banner) + "\n")
            sys.stdout.flush()
        codes = [process.returncode for process in processes]
    except subprocess.TimeoutExpired:
        for process in processes:
            stop_worker(process)
        raise ValueError('worker_timeout') from None
    except BaseException:
        for process in processes:
            stop_worker(process)
        raise
    finally:
        for stream in streams:
            stream.close()
    if any(code != 0 for code in codes):
        for shard, code in enumerate(codes):
            if code != 0 and len(streams) > shard * 2 + 1:
                try:
                    stderr_stream = streams[shard * 2 + 1]
                    stderr_stream.seek(0)
                    detail = stderr_stream.read(2048).decode('utf-8', errors='replace').strip()
                    if detail and sys.stdout.isatty():
                        sys.stderr.write(f"Worker {shard} error: {detail}\n")
                except OSError:
                    pass
        raise ValueError('worker_failed')
    summary = merge_summary(job, directory, count)
    return summary


def merge_summary(job, directory, count):
    fields = {*SUMMARY_FIELDS, 'shard', 'shards'}
    totals = dict.fromkeys(('completed', 'observed', 'bounded_complete', 'partial', 'failed', 'primary_available', 'timeout'), 0)
    counts = {}
    elapsed_ms = 0
    peak_rss_bytes = 0
    for shard in range(count):
        value = parse_json(side.bounded_read(directory / f'pdf_summary.{shard}.json', 16384))
        if (not isinstance(value, dict) or set(value) - {'bounded_complete'} != fields
                or value.get('shard') != shard or value.get('shards') != count
                or value.get('planned') != job['limits']['samples']):
            raise ValueError('report_invalid')
        if any(type(value[name]) is not int or not 0 <= value[name] <= 10**12 for name in set(value) - {'status_counts'}) or not summary_valid(value):
            raise ValueError('report_invalid')
        for name in totals:
            totals[name] += value.get(name, 0)
        elapsed_ms = max(elapsed_ms, value['elapsed_ms'])
        peak_rss_bytes = max(peak_rss_bytes, value['peak_rss_bytes'])
        for name, amount in value['status_counts'].items():
            counts[name] = counts.get(name, 0) + amount
    totals['bounded_complete'] = counts.get('bounded_complete', totals.get('bounded_complete', 0))
    summary = {'planned': job['limits']['samples'], 'elapsed_ms': elapsed_ms, 'peak_rss_bytes': peak_rss_bytes,
               'status_counts': dict(sorted(counts.items())), **totals}
    if not summary_valid(summary):
        raise ValueError('report_invalid')
    immutable(directory / 'pdf_summary.json', summary)
    return summary


def credential_reasons(data_root):
    sensitive = ('.codex/auth.json', '.aws/credentials', '.kaggle/kaggle.json', '.git-credentials', '.netrc', '.env', '.config/gcloud/application_default_credentials.json')
    reasons = []
    for label, root in (('home', Path.home()), ('data', Path(data_root))):
        for name in sensitive:
            if (root / name).exists() or (root / name).is_symlink():
                reasons.append(label + ':' + name)
    ssh = Path.home() / '.ssh'
    if ssh.is_dir() and any(path.name.startswith('id_') and path.suffix != '.pub' for path in ssh.iterdir()):
        reasons.append('home:.ssh/id_*')
    for name in sorted(os.environ):
        if os.environ[name] and (name in {'SSH_AUTH_SOCK', 'SSH_AGENT_PID'} or name.endswith(('_TOKEN', '_API_KEY', '_PASSWORD', '_SECRET'))):
            reasons.append('env:' + name)
    return reasons[:MAX_CREDENTIAL_REASONS]


def check_credentials(data_root):
    if credential_reasons(data_root):
        raise ValueError('credential_present')


def stop_worker(process):
    import signal
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except ProcessLookupError:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
