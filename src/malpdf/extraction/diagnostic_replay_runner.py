import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import time
import uuid
from collections import Counter

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.diagnostic_replay import KIND, LOCK_PATH, MAX_BUNDLE, canonical, load_replay, read, sha
from malpdf.extraction.diagnostic_replay_results import make_case, snapshot
from malpdf.extraction.orchestrator import extract_pdf


PACKAGE_NAMES = ('numpy', 'pandas', 'pypdf', 'PyMuPDF', 'pikepdf', 'esprima', 'torch', 'torchvision')
THREAD_VARIABLES = ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS')
ENVIRONMENT_FIELDS = {'python', 'platform', 'machine', 'logical_cpus', 'memory_bytes', 'packages', 'thread_environment'}
PINNED_ENVIRONMENT_FIELDS = ('python', 'machine', 'packages', 'thread_environment')
PRE_SPAWN_PHASES = ('validation', 'profile_boundary', 'worker_admission', 'worker_start')


def environment():
    memory = None
    if Path('/proc/meminfo').is_file():
        memory = next((int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
            if line.startswith('MemTotal:')), None)
    return {'python': platform.python_version(), 'platform': platform.platform(), 'machine': platform.machine(),
        'logical_cpus': os.cpu_count(), 'memory_bytes': memory,
        'packages': {name: importlib.metadata.version(name) for name in PACKAGE_NAMES},
        'thread_environment': {name: os.environ.get(name) for name in THREAD_VARIABLES}}


def valid_environment(value, min_memory_bytes):
    if not isinstance(value, dict) or set(value) != ENVIRONMENT_FIELDS:
        return False
    if any(not isinstance(value[name], str) or not value[name] for name in ('python', 'platform', 'machine')):
        return False
    if type(value['logical_cpus']) is not int or value['logical_cpus'] < 1:
        return False
    if type(value['memory_bytes']) is not int or value['memory_bytes'] < min_memory_bytes:
        return False
    packages, threads = value['packages'], value['thread_environment']
    if not isinstance(packages, dict) or set(packages) != set(PACKAGE_NAMES) or any(not isinstance(item, str) or not item for item in packages.values()):
        return False
    if not isinstance(threads, dict) or set(threads) != set(THREAD_VARIABLES) or any(item is not None and not isinstance(item, str) for item in threads.values()):
        return False
    return True


def methodology_value(job, source, lock, runtime_env):
    return {'schema_version': 1, 'stage': lock['stage'], 'job_id': job['job_id'],
        'commit': job['commit'], 'archive_sha256': job['archive_sha256'], 'manifest_sha256': job['manifest_sha256'],
        'replay_lock_sha256': sha(read(Path(source) / LOCK_PATH, source, 128 * 1024)),
        'baseline_job_id': lock['baseline_job_id'], 'baseline_job_sha256': lock['baseline_job_sha256'],
        'baseline_result_sha256': lock['baseline_result_sha256'], 'baseline_selection_sha256': lock['baseline_selection_sha256'],
        'audit_cases_sha256': lock['audit_cases_sha256'], 'records': lock['records'], 'limits': job['limits'],
        'node_cap': lock['node_cap'], 'unchanged_code_sha256': lock['unchanged_code_sha256'],
        'cache_policy': 'no baseline cache; only validated completed records from this same replay job may resume',
        'environment': runtime_env, 'training_executed': False, 'b2_executed': False}


def prepare_replay(job, directory, source, operations):
    if sys.platform != 'linux' or job['kind'] != KIND or job['mode'] != 'offline':
        raise ValueError('replay_offline_lab_required')
    lock, _ = load_replay(source, operations.JOBS)
    if job['limits'] != {**lock['baseline_limits'], 'samples': lock['samples']}:
        raise ValueError('replay_limits_changed')
    now = environment()
    if not valid_environment(now, job['limits']['file_memory_bytes']):
        raise ValueError('replay_environment_invalid')
    value = methodology_value(job, source, lock, now)
    operations.immutable(Path(directory) / 'locked_methodology.json', value)
    return lock


def verify_replay(job, directory, source, operations, *, shard=0):
    if sys.platform != 'linux' or job['kind'] != KIND or job['mode'] != 'offline':
        raise ValueError('replay_offline_lab_required')
    directory = Path(directory)
    lock, _ = load_replay(source, operations.JOBS)
    if job['limits'] != {**lock['baseline_limits'], 'samples': lock['samples']}:
        raise ValueError('replay_limits_changed')
    methodology_path = directory / 'locked_methodology.json'
    if not methodology_path.is_file():
        raise ValueError('replay_methodology_missing')
    saved = json.loads(read(methodology_path, directory, 256 * 1024))
    now = environment()
    min_memory = job['limits']['file_memory_bytes']
    if not valid_environment(now, min_memory):
        raise ValueError('replay_environment_invalid')
    expected = methodology_value(job, source, lock, now)
    if not isinstance(saved, dict) or set(saved) != set(expected):
        raise ValueError('replay_methodology_changed')
    if {key: item for key, item in saved.items() if key != 'environment'} != {key: item for key, item in expected.items() if key != 'environment'}:
        raise ValueError('replay_methodology_changed')
    saved_env = saved['environment']
    if not valid_environment(saved_env, min_memory):
        raise ValueError('replay_methodology_changed')
    if any(saved_env[name] != now[name] for name in PINNED_ENVIRONMENT_FIELDS):
        raise ValueError('replay_environment_changed')
    outer = directory / 'private_outer'
    outer.mkdir(mode=0o700, exist_ok=True)
    env_path = outer / f'environment.{shard}.json'
    if env_path.exists():
        env_path = outer / f'environment.{shard}.{uuid.uuid4().hex[:12]}.json'
    operations.immutable(env_path, {'schema_version': 1, 'run_id': job['job_id'], 'shard': shard, 'environment': now})
    return lock


def summary_status(case):
    replay = case['replay']
    if replay['parent_exception'] is not None:
        return 'partial' if replay['bundle_status'] is not None else 'not_run'
    return replay['bundle_status'] or 'not_run'


def saved_case(directory, ordinal, record, run_id):
    path = directory / 'private_cases' / f'{ordinal:04d}.json'
    if not path.is_file():
        return None
    case = json.loads(read(path, directory, 128 * 1024))
    from malpdf.extraction.diagnostic_replay_report import validate_case
    validate_case(case, record, ordinal, run_id)
    expected = case['replay']['bundle_sha256']
    if expected is not None and sha(read(directory / 'private_bundles' / f'{ordinal:04d}.json', directory, MAX_BUNDLE)) != expected:
        raise ValueError('replay_resume_bundle_changed')
    return case


def run_shard(job, directory, source, data_root, rows, limits, catalog, shard, count, operations):
    lock = verify_replay(job, directory, source, operations, shard=shard)
    directory, data_root = Path(directory), Path(data_root)
    if (limits.wall_seconds != job['limits']['file_wall_seconds'] or limits.cpu_seconds != job['limits']['file_cpu_seconds']
            or limits.memory_bytes != job['limits']['file_memory_bytes'] or limits.max_file_bytes != job['limits']['file_max_bytes']):
        raise ValueError('replay_worker_limits_changed')
    for name in ('private_cases', 'private_bundles', 'private_attempts'):
        (directory / name).mkdir(mode=0o700, exist_ok=True)
    summary_path = directory / f'pdf_summary.{shard}.json'
    if summary_path.is_file():
        previous = json.loads(read(summary_path, directory, 16384))
        statuses = Counter()
        for ordinal, row in rows:
            record = lock['records'][ordinal]
            case = saved_case(directory, ordinal, record, job['job_id'])
            if case is None or row['pdf_sha256'] != record['sha256']:
                raise ValueError('replay_resume_incomplete')
            statuses[summary_status(case)] += 1
        if (not operations.summary_valid(previous) or previous.get('planned') != 74 or previous.get('shard') != shard
                or previous.get('shards') != count or previous['completed'] != len(rows) or previous['status_counts'] != dict(statuses)):
            raise ValueError('replay_resume_summary')
        return previous
    started = time.monotonic()
    summary = dict.fromkeys(('completed', 'observed', 'bounded_complete', 'partial', 'failed', 'primary_available',
        'timeout', 'elapsed_ms', 'peak_rss_bytes'), 0)
    summary.update(planned=74, shard=shard, shards=count)
    statuses = {}
    os.environ['MALPDF_LAB_ISOLATED'] = '1'
    for ordinal, row in rows:
        if time.monotonic() - started > job['limits']['wall_seconds'] - 25:
            operations.write_pdf_halt(job, directory, shard=shard, index=ordinal, reason='wall_limit')
            break
        record = lock['records'][ordinal]
        if row['pdf_sha256'] != record['sha256']:
            raise ValueError('replay_selection_identity')
        case = saved_case(directory, ordinal, record, job['job_id'])
        bundle_path = directory / 'private_bundles' / f'{ordinal:04d}.json'
        bundle = None
        profile = {}
        if case is None:
            if bundle_path.exists():
                bundle = validate_bundle(json.loads(read(bundle_path, directory, MAX_BUNDLE)))
                profile = bundle['coverage_report']['worker']
                case = make_case(record, ordinal, job['job_id'], bundle=bundle, profile=profile)
            else:
                attempt = directory / 'private_attempts' / f'{ordinal:04d}_{uuid.uuid4().hex}'
                attempt.mkdir(mode=0o700)
                def observe(value):
                    nonlocal profile
                    profile = snapshot(value)
                    operations.immutable(attempt / 'worker.json', profile)
                phase = 'extract_boundary'
                try:
                    bundle = extract_pdf(data_root / row['pdf_relative_path'], boundary=data_root / 'data/raw/cic_pdf',
                        profile=lock['profile'], expected_sha256=record['sha256'], limits=limits, arlington_catalog=catalog,
                        run_id=job['job_id'], entry_point='lab_runner.diagnostic_replay', profile_observer=observe)
                    validate_bundle(bundle)
                    payload = canonical(bundle)
                    if len(payload) > 8 * 1024**2:
                        raise ValueError('replay_bundle_size_limit')
                    staged_bundle = attempt / 'bundle.json'
                    with staged_bundle.open('xb') as output:
                        output.write(payload)
                    os.link(staged_bundle, bundle_path)
                    phase = 'numeric_projection'
                    case = make_case(record, ordinal, job['job_id'], bundle=bundle, profile=profile)
                except Exception as error:
                    if phase == 'extract_boundary' and profile:
                        phase = 'bundle_build'
                    case = make_case(record, ordinal, job['job_id'],
                        bundle=bundle if phase == 'numeric_projection' else None,
                        profile=profile, parent_error=error, phase=phase)
                operations.immutable(attempt / 'case.json', case)
            operations.immutable(directory / 'private_cases' / f'{ordinal:04d}.json', case)
        if bundle is None and bundle_path.is_file():
            bundle = validate_bundle(json.loads(read(bundle_path, directory, MAX_BUNDLE)))
        if bundle is not None:
            summary['primary_available'] += any(item['kind'] == 'primary_checkpoint' for item in bundle['evidence_store']['records'])
        status = summary_status(case)
        statuses[status] = statuses.get(status, 0) + 1
        summary['completed'] += 1
        summary[operations.status_bucket(status)] += 1
        summary['bounded_complete'] += status == 'bounded_complete'
        summary['timeout'] += case['replay']['diagnostic'] is not None and case['replay']['diagnostic'].get('timeout_reason') == 'wall_timeout'
        diagnostic = case['replay']['diagnostic'] or {}
        summary['peak_rss_bytes'] = max(summary['peak_rss_bytes'], diagnostic.get('peak_rss_bytes') or 0)
        cleanup = diagnostic.get('cleanup_complete')
        no_worker = (
            (cleanup is None and diagnostic.get('worker_exit_code') is None
             and diagnostic.get('cleanup_exit_code') is None
             and diagnostic.get('last_phase') in PRE_SPAWN_PHASES)
            or (case['replay']['diagnostic'] is None and case['replay']['profile_status'] == 'input_error')
        )
        if cleanup is not True and not no_worker:
            operations.write_pdf_halt(job, directory, shard=shard, index=ordinal, reason='worker_cleanup_incomplete')
            break
    summary.update(elapsed_ms=int((time.monotonic() - started) * 1000), status_counts=statuses)
    operations.immutable(directory / f'pdf_summary.{shard}.json', summary)
