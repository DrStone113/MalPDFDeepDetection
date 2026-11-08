import json
from pathlib import Path

from malpdf.extraction.diagnostic_replay import canonical, read, sha
from malpdf.extraction.diagnostic_replay_results import EXCEPTIONS, safe_trace


def optional(path, directory, limit):
    if not path.is_file():
        return None, False
    try:
        value = json.loads(read(path, directory, limit))
        return (value, False) if isinstance(value, dict) else (None, True)
    except (OSError, ValueError, TypeError):
        return None, True


def outer_records(job, directory, lock):
    directory = Path(directory)
    cleanup_path = directory / 'private_outer/cleanup.json'
    cleanup, cleanup_invalid = optional(cleanup_path, directory, 16384)
    if cleanup is not None and (set(cleanup) != {'run_id', 'exit_codes'} or cleanup['run_id'] != job['job_id']
            or not isinstance(cleanup['exit_codes'], list) or len(cleanup['exit_codes']) > job['limits']['workers']):
        raise ValueError('replay_outer_cleanup')
    records = []
    for shard in range(job['limits']['workers']):
        transport_path = directory / 'private_outer' / f'transport.{shard}.json'
        error_path = directory / 'private_outer' / f'exception.{shard}.json'
        transport, transport_invalid = optional(transport_path, directory, 256 * 1024)
        error, error_invalid = optional(error_path, directory, 128 * 1024)
        for value in (transport, error):
            if value is not None and (value.get('run_id') != job['job_id'] or value.get('shard') != shard):
                raise ValueError('replay_outer_identity')
        stderr = transport.get('stderr') if transport is not None else None
        if stderr is not None and (not isinstance(stderr, str) or len(stderr.encode('utf-8')) > 65536):
            raise ValueError('replay_outer_stderr')
        name = error.get('exception_type') if error is not None else None
        last = error.get('last_phase') if error is not None else None
        record = {'schema_version': 1, 'run_id': job['job_id'], 'scope': 'outer_shard_not_per_pdf', 'shard': shard,
            'assigned_baseline_indices': [row['baseline_index'] for ordinal, row in enumerate(lock['records']) if ordinal % job['limits']['workers'] == shard],
            'transport_available': transport is not None, 'exception_available': error is not None,
            'transport_record_invalid': transport_invalid, 'exception_record_invalid': error_invalid, 'cleanup_record_invalid': cleanup_invalid,
            'exit_before_cleanup': transport.get('exit_before_cleanup') if transport is not None else None,
            'cleanup_exit_code': cleanup['exit_codes'][shard] if cleanup is not None and shard < len(cleanup['exit_codes']) else None,
            'supervisor_reason': transport.get('supervisor_reason') if transport is not None else None,
            'exception_type': name if name in EXCEPTIONS else 'OtherError' if name is not None else None,
            'exception_errno': error.get('exception_errno') if error is not None else None,
            'traceback': safe_trace(error.get('traceback')) if error is not None else None,
            'last_phase': last if isinstance(last, str) and len(last) <= 80 and last.isidentifier() else None,
            'elapsed_ms': error.get('elapsed_ms') if error is not None else None,
            'stderr_text_returned': False, 'stderr_utf8_bytes': len(stderr.encode('utf-8')) if stderr is not None else None,
            'stderr_sha256': sha(stderr.encode('utf-8')) if stderr is not None else None}
        for key in ('exit_before_cleanup', 'cleanup_exit_code', 'exception_errno', 'elapsed_ms', 'stderr_utf8_bytes'):
            if record[key] is not None and (type(record[key]) is not int or not -2**31 <= record[key] <= 10**12):
                raise ValueError('replay_outer_number')
        if record['supervisor_reason'] not in (None, 'observed_process_exit', 'timeout', 'supervisor_exception'):
            raise ValueError('replay_outer_reason')
        records.append(record)
    return {'schema_version': 1, 'run_id': job['job_id'], 'records': records,
        'scope': 'Shard diagnostics identify setup/supervisor failures; missing per-PDF attempts remain null.'}


def write_outer(job, directory, lock):
    directory = Path(directory)
    value = outer_records(job, directory, lock)
    payload = canonical(value) + b'\n'
    path = directory / 'analysis/outer_diagnostics.json'
    if path.exists():
        if read(path, directory, 256 * 1024) != payload:
            raise ValueError('replay_outer_report_collision')
    else:
        with path.open('xb') as stream:
            stream.write(payload)
    return sha(payload)
