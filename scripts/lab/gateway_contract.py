"""Closed contracts for the unprivileged, source-only automation gateway."""

from datetime import datetime, timezone
import hashlib
import json
import re

from lab_contract import MAX_REPORT, REV_RE

API = 1
HEX = re.compile(r'[0-9a-f]{64}\Z')
PROFILES = {'syntax', 'synthetic'}
REASONS = {'setup_required', 'gateway_not_verified', 'profile_not_approved', 'source_rejected',
           'job_mismatch', 'resource_unavailable', 'network_blocked', 'worker_failed',
           'worker_timeout', 'already_claimed', 'report_pending', 'ssh_unavailable', 'report_invalid'}
LIMITS = {'wall_seconds': 90, 'cpu_seconds': 60, 'memory_bytes': 536870912,
          'tasks': 32, 'files': 3000, 'source_bytes': 33554432, 'report_bytes': 16384}
SYNTHETIC_CASES = 6


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def validate_capability(value):
    fields = {'api', 'installed', 'verified', 'profiles', 'policy_sha256', 'reason'}
    if not isinstance(value, dict) or set(value) != fields or type(value['api']) is not int or value['api'] != API:
        raise ValueError('report_invalid')
    if any(type(value[key]) is not bool for key in ('installed', 'verified')):
        raise ValueError('report_invalid')
    if not isinstance(value['profiles'], list) or any(not isinstance(name, str) or name not in PROFILES for name in value['profiles']) or value['profiles'] != sorted(set(value['profiles'])):
        raise ValueError('report_invalid')
    if value['policy_sha256'] is not None and (not isinstance(value['policy_sha256'], str) or not HEX.fullmatch(value['policy_sha256'])):
        raise ValueError('report_invalid')
    if value['reason'] is not None and (not isinstance(value['reason'], str) or value['reason'] not in REASONS):
        raise ValueError('report_invalid')
    if value['verified'] and (not value['installed'] or not value['profiles'] or value['policy_sha256'] is None or value['reason'] is not None):
        raise ValueError('report_invalid')
    if not value['verified'] and value['profiles']:
        raise ValueError('report_invalid')
    return value


def make_job(commit, manifest_sha256, archive_sha256, profile, policy_sha256):
    body = {'api': API, 'base_commit': commit, 'source_kind': 'validated_worktree_snapshot',
            'manifest_sha256': manifest_sha256, 'archive_sha256': archive_sha256,
            'profile': profile, 'policy_sha256': policy_sha256, 'limits': LIMITS.copy()}
    return validate_job({**body, 'job_id': sha(encoded(body))})


def validate_job(value):
    fields = {'api', 'base_commit', 'source_kind', 'manifest_sha256', 'archive_sha256',
              'profile', 'policy_sha256', 'limits', 'job_id'}
    if not isinstance(value, dict) or set(value) != fields or type(value['api']) is not int or value['api'] != API:
        raise ValueError('job_mismatch')
    if not isinstance(value['base_commit'], str) or not REV_RE.fullmatch(value['base_commit']) or value['source_kind'] != 'validated_worktree_snapshot':
        raise ValueError('job_mismatch')
    for name in ('manifest_sha256', 'archive_sha256', 'policy_sha256', 'job_id'):
        if not isinstance(value[name], str) or not HEX.fullmatch(value[name]):
            raise ValueError('job_mismatch')
    if not isinstance(value['profile'], str) or value['profile'] not in PROFILES or value['limits'] != LIMITS or any(type(item) is not int for item in value['limits'].values()):
        raise ValueError('job_mismatch')
    if sha(encoded({key: item for key, item in value.items() if key != 'job_id'})) != value['job_id']:
        raise ValueError('job_mismatch')
    return value


def result(job, status, *, syntax=None, synthetic=None, reason=None):
    return validate_result({'api': API, 'job': job, 'status': status, 'reason': reason,
        'syntax': syntax, 'synthetic': synthetic,
        'generated_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}, job)


def validate_result(value, job):
    validate_job(job)
    if not isinstance(value, dict) or set(value) != {'api', 'job', 'status', 'reason', 'syntax', 'synthetic', 'generated_utc'} or type(value['api']) is not int or value['api'] != API or value['job'] != job:
        raise ValueError('report_invalid')
    if not isinstance(value['status'], str) or value['status'] not in ('queued', 'running', 'passed', 'failed', 'interrupted') or value['reason'] is not None and (not isinstance(value['reason'], str) or value['reason'] not in REASONS):
        raise ValueError('report_invalid')
    for name in ('syntax', 'synthetic'):
        counts = value[name]
        if counts is not None and (not isinstance(counts, dict) or set(counts) != {'passed', 'failed'} or any(type(count) is not int or not 0 <= count <= LIMITS['files'] for count in counts.values())):
            raise ValueError('report_invalid')
    if value['synthetic'] is not None and (job['profile'] != 'synthetic' or sum(value['synthetic'].values()) != SYNTHETIC_CASES):
        raise ValueError('report_invalid')
    if value['status'] == 'passed' and (value['reason'] is not None or value['syntax'] is None or not value['syntax']['passed'] or value['syntax']['failed'] or job['profile'] == 'synthetic' and value['synthetic'] != {'passed': SYNTHETIC_CASES, 'failed': 0}):
        raise ValueError('report_invalid')
    stamp = value['generated_utc']
    if not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', stamp):
        raise ValueError('report_invalid')
    datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    if len(encoded(value)) > MAX_REPORT:
        raise ValueError('report_invalid')
    return value
