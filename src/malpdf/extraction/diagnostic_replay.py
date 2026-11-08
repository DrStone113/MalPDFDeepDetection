from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.numeric_export import MAX_NODES, project_numeric_bundle
from malpdf.static.safety import read_bounded_bytes


KIND = 'pdf-diagnostic-replay'
LOCK_PATH = 'configs/pdf_diagnostic_replay.json'
HASH = re.compile(r'[a-f0-9]{64}\Z')
MAX_BUNDLE = 8 * 1024**2 + 1024
LOCK_FIELDS = {'schema_version', 'stage', 'baseline_job_id', 'baseline_job_sha256', 'baseline_result_sha256',
    'baseline_selection_sha256', 'audit_cases_sha256', 'samples', 'seed', 'node_cap', 'profile', 'cache_reuse',
    'unchanged_code_sha256', 'baseline_limits', 'records'}
RECORD_FIELDS = {'baseline_index', 'sha256', 'label', 'split', 'baseline_bundle_sha256',
    'baseline_bundle_status', 'baseline_worker', 'baseline_failure_family', 'baseline_graph'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def validate_lock(value):
    if (not isinstance(value, dict) or set(value) != LOCK_FIELDS or value['schema_version'] != 1
            or value['stage'] != 'BUG-007B1' or value['samples'] != 74 or value['seed'] != 42
            or value['node_cap'] != MAX_NODES or value['profile'] != 'deep-static' or value['cache_reuse'] is not False):
        raise ValueError('replay_lock')
    for key in ('baseline_job_id', 'baseline_job_sha256', 'baseline_result_sha256', 'baseline_selection_sha256', 'audit_cases_sha256'):
        if not isinstance(value[key], str) or not HASH.fullmatch(value[key]):
            raise ValueError('replay_lock_hash')
    records = value['records']
    if not isinstance(records, list) or len(records) != 74:
        raise ValueError('replay_records')
    indices = []
    for row in records:
        if (not isinstance(row, dict) or set(row) != RECORD_FIELDS
                or type(row['baseline_index']) is not int or not 0 <= row['baseline_index'] < 1452
                or type(row['label']) is not int or row['label'] not in (0, 1)
                or row['split'] not in ('train', 'validation', 'test')
                or row['baseline_failure_family'] not in ('timeout', 'worker_error_unspecified')
                or row['baseline_graph'] != {'projected_nodes': 0, 'projected_edges': 0}):
            raise ValueError('replay_record')
        if any(not isinstance(row[key], str) or not HASH.fullmatch(row[key]) for key in ('sha256', 'baseline_bundle_sha256')):
            raise ValueError('replay_record_hash')
        indices.append(row['baseline_index'])
    if indices != sorted(set(indices)) or 141 in indices or Counter(row['baseline_failure_family'] for row in records) != {
            'worker_error_unspecified': 70, 'timeout': 4}:
        raise ValueError('replay_scope')
    code = value['unchanged_code_sha256']
    if not isinstance(code, dict) or not code or any(not isinstance(name, str) or not name.startswith(('src/malpdf/', 'scripts/lab/'))
            or '..' in PurePosixPath(name).parts or not isinstance(digest, str) or not HASH.fullmatch(digest) for name, digest in code.items()):
        raise ValueError('replay_code_contract')
    canonical(value)
    return value


def select_rows(lock, selection):
    validate_lock(lock)
    if (not isinstance(selection, dict) or set(selection) != {'job_id', 'rows', 'selection_sha256'}
            or selection['job_id'] != lock['baseline_job_id'] or not isinstance(selection['rows'], list)
            or len(selection['rows']) != 1452 or sha(canonical(selection['rows'])) != selection['selection_sha256']
            or selection['selection_sha256'] != lock['baseline_selection_sha256']):
        raise ValueError('replay_selection')
    selected = []
    for item in lock['records']:
        row = selection['rows'][item['baseline_index']]
        if (not isinstance(row, dict) or row.get('pdf_sha256') != item['sha256']
                or row.get('split') != item['split'] or str(row.get('Label')) != str(item['label'])):
            raise ValueError('replay_selection_identity')
        path = row.get('pdf_relative_path')
        if (not isinstance(path, str) or not path.startswith('data/raw/cic_pdf/') or '\\' in path
                or any(part in ('', '.', '..') for part in path.split('/')) or PurePosixPath(path).suffix.lower() != '.pdf'):
            raise ValueError('replay_selection_path')
        selected.append(dict(row))
    return selected


def read(path, boundary, limit):
    return read_bounded_bytes(Path(path), boundary=Path(boundary), max_bytes=limit)


def load_replay(source, jobs_root):
    source, jobs_root = Path(source), Path(jobs_root)
    lock = validate_lock(json.loads(read(source / LOCK_PATH, source, 128 * 1024)))
    for name, expected in lock['unchanged_code_sha256'].items():
        if sha(read(source / name, source, 2 * 1024**2).replace(b'\r\n', b'\n')) != expected:
            raise ValueError('replay_code_changed')
    baseline = jobs_root / lock['baseline_job_id']
    for name, key in (('job.json', 'baseline_job_sha256'), ('result.json', 'baseline_result_sha256')):
        if sha(read(baseline / name, jobs_root, 65536)) != lock[key]:
            raise ValueError('replay_baseline_changed')
    job = json.loads(read(baseline / 'job.json', jobs_root, 65536))
    if job.get('job_id') != lock['baseline_job_id'] or job.get('limits') != lock['baseline_limits']:
        raise ValueError('replay_baseline_limits')
    selection = json.loads(read(baseline / 'selection.json', jobs_root, 4 * 1024**2))
    rows = select_rows(lock, selection)
    for record in lock['records']:
        payload = read(baseline / 'private_bundles' / f"{record['baseline_index']:04d}.json", jobs_root, MAX_BUNDLE)
        if sha(payload) != record['baseline_bundle_sha256']:
            raise ValueError('replay_baseline_bundle_changed')
        bundle = validate_bundle(json.loads(payload))
        if bundle['sample_sha256'] != record['sha256'] or bundle['status'] != record['baseline_bundle_status']:
            raise ValueError('replay_baseline_identity')
        graph = project_numeric_bundle(bundle, record['sha256'])['graph']
        if len(graph['node_types']) or len(graph['edge_src']):
            raise ValueError('replay_baseline_graph')
        worker = bundle['coverage_report']['worker']
        observed = {key: worker.get(name) for key, name in (
            ('status', 'status'), ('last_stage', 'last_stage'), ('exit_code', 'worker_exit_code'), ('cleanup_complete', 'worker_cleanup_complete'))}
        if observed != record['baseline_worker']:
            raise ValueError('replay_baseline_worker')
    return lock, rows


def cohort_contract(source):
    source = Path(source)
    lock = validate_lock(json.loads(read(source / LOCK_PATH, source, 128 * 1024)))
    return {'stage': lock['stage'], 'samples': lock['samples'], 'seed': lock['seed'],
        'baseline_job_id': lock['baseline_job_id'], 'baseline_indices': [row['baseline_index'] for row in lock['records']],
        'node_cap': lock['node_cap'], 'profile': lock['profile'], 'cache_reuse': False,
        'groups': dict(Counter(row['baseline_failure_family'] for row in lock['records']))}
