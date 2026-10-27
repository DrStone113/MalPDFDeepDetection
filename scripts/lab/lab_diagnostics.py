"""Fixed read-only gateway diagnostics and closed metadata contracts."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading

from lab_contract import MAX_REPORT, parse_json
from lab_side import bounded_read

UNITS = ('malpdf-gateway.service', 'malpdf-gateway-probe.service', 'malpdf-gateway.timer')
INSTALLATION = Path('/etc/malpdf/gateway-installation.json')
ROOT = Path('/var/lib/malpdf-gateway')
HEX = re.compile(r'[0-9a-f]{64}\Z')
PHASES = {'configuration', 'sshd_syntax', 'sshd_policy', 'unit_validation', 'manager_reload',
          'containment', 'command_refusals', 'ssh_reload', 'timer_enable', 'complete'}
INSTALL_REASONS = {'sudo_policy_invalid', 'operator_console_root_required', 'unsupported_python',
    'bootstrap_rejected', 'audit_account_missing', 'audit_group_missing', 'audit_key_missing',
    'runner_key_must_be_separate', 'sshd_include_required', 'symlinked_destination', 'destination_permissions',
    'existing_account_requires_review', 'existing_privilege_or_session', 'systemd_required',
    'cgroup_v2_controllers_required', 'required_file_missing', 'permission_denied', 'command_failed',
    'command_timeout', 'sshd_config_invalid', 'sshd_policy_mismatch', 'systemd_unit_invalid',
    'systemd_reload_failed', 'containment_probe_failed', 'forced_command_probe_failed',
    'ssh_reload_failed', 'timer_enable_failed', 'runtime_layout_mismatch',
    'existing_worker_requires_review', 'lock_type_mismatch', 'validation_failed'}
INSTALL_REASONS.update({'sshd_restore_failed', 'runner_process_present', 'worker_process_present', 'runner_sudo_listing_allowed',
                        'worker_sudo_listing_allowed', 'account_process_check_failed', 'account_sudo_check_failed'})
CONTAINMENT_REASONS = {'containment_uid_failed', 'containment_paths_failed', 'containment_rlimits_failed',
    'containment_cgroup_memory_failed', 'containment_cgroup_swap_failed', 'containment_cgroup_tasks_failed',
    'containment_cgroup_cpu_failed', 'containment_cgroup_unavailable', 'containment_network_failed',
    'containment_source_failed'}
RUN_REASONS = {'configuration_failed', 'containment_failed', 'worker_failed', 'job_failed'} | CONTAINMENT_REASONS
LOAD = {'loaded', 'not-found', 'masked', 'error', 'bad-setting', 'stub', 'merged', 'unknown'}
ACTIVE = {'active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'refreshing', 'unknown'}
SUB = {'dead', 'running', 'exited', 'failed', 'waiting', 'elapsed', 'start-pre', 'start', 'start-post',
       'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'auto-restart', 'final-sigterm', 'final-sigkill', 'unknown'}
UNIT_FILE = {'enabled', 'enabled-runtime', 'disabled', 'static', 'masked', 'masked-runtime', 'indirect',
             'generated', 'transient', 'alias', 'linked', 'linked-runtime', 'not-found', 'unknown'}
RESULT = {'success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump', 'watchdog',
          'start-limit-hit', 'protocol', 'oom-kill', 'condition', 'assert', 'unknown'}
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'Result', 'ExecMainCode',
              'ExecMainStatus', 'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic',
              'LastTriggerUSecMonotonic')
RECORD_ERRORS = {'installation_invalid', 'installation_unavailable', 'probe_invalid', 'probe_unavailable',
                 'worker_invalid', 'worker_unavailable', 'job_invalid', 'job_unavailable'}
CONFIG_CHECKS = {'configuration', 'helpers', 'policy', 'units', 'sshd', 'proof'}
CHECK_STATES = {'not_checked', 'passed', 'missing', 'unreadable', 'unsafe', 'invalid', 'mismatch'}


def stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def identity(value):
    if value is not None and (not isinstance(value, str) or not HEX.fullmatch(value)):
        raise ValueError('diagnostics_invalid')


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
        raise ValueError('diagnostics_invalid')
    datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')


def validate_installation(value):
    if not isinstance(value, dict) or set(value) != {'api', 'status', 'phase', 'reason', 'policy_sha256', 'generated_utc'} or type(value['api']) is not int or value['api'] != 1:
        raise ValueError('diagnostics_invalid')
    if value['status'] not in ('running', 'passed', 'failed') or not isinstance(value['phase'], str) or value['phase'] not in PHASES or value['reason'] is not None and (not isinstance(value['reason'], str) or value['reason'] not in INSTALL_REASONS):
        raise ValueError('diagnostics_invalid')
    if (value['status'] == 'failed') != (value['reason'] is not None) or value['status'] == 'passed' and (value['phase'] != 'complete' or value['policy_sha256'] is None):
        raise ValueError('diagnostics_invalid')
    identity(value['policy_sha256'])
    timestamp(value['generated_utc'])
    return value


def validate_run(value):
    if not isinstance(value, dict) or set(value) != {'api', 'status', 'phase', 'reason', 'policy_sha256', 'job_id', 'generated_utc'} or type(value['api']) is not int or value['api'] != 1:
        raise ValueError('diagnostics_invalid')
    if value['status'] not in ('idle', 'passed', 'failed') or value['phase'] not in ('configuration', 'containment', 'job', 'poll', 'complete') or value['reason'] is not None and (not isinstance(value['reason'], str) or value['reason'] not in RUN_REASONS):
        raise ValueError('diagnostics_invalid')
    if (value['status'] == 'failed') != (value['reason'] is not None):
        raise ValueError('diagnostics_invalid')
    if value['status'] == 'passed' and (value['policy_sha256'] is None or value['phase'] not in ('complete', 'job')):
        raise ValueError('diagnostics_invalid')
    identity(value['policy_sha256'])
    identity(value['job_id'])
    timestamp(value['generated_utc'])
    return value


def unit_unknown():
    return {'load': 'unknown', 'active': 'unknown', 'sub': 'unknown', 'unit_file': 'unknown',
            'result': 'unknown', 'exit_code': None, 'exit_status': None,
            'started': None, 'finished': None, 'timer_triggered': None}


def validate_job_result(value):
    from gateway_contract import validate_job, validate_result
    if not isinstance(value, dict) or 'job' not in value:
        raise ValueError('diagnostics_invalid')
    return validate_result(value, validate_job(value['job']))


def validate_report(value):
    from gateway_contract import encoded, validate_capability
    fields = {'api', 'generated_utc', 'gateway', 'systemd', 'units', 'installation', 'probe', 'worker', 'last_job', 'record_errors'}
    if not isinstance(value, dict) or type(value.get('api')) is not int or value['api'] not in (1, 2) or set(value) != fields | ({'configuration_checks'} if value['api'] == 2 else set()):
        raise ValueError('diagnostics_invalid')
    if value['api'] == 2:
        checks = value['configuration_checks']
        if not isinstance(checks, dict) or set(checks) != CONFIG_CHECKS or any(not isinstance(state, str) or state not in CHECK_STATES for state in checks.values()):
            raise ValueError('diagnostics_invalid')
    timestamp(value['generated_utc'])
    validate_capability(value['gateway'])
    if value['systemd'] not in ('ok', 'unavailable', 'timeout', 'oversize', 'invalid') or not isinstance(value['units'], dict) or set(value['units']) != set(UNITS):
        raise ValueError('diagnostics_invalid')
    for unit in value['units'].values():
        if not isinstance(unit, dict) or set(unit) != set(unit_unknown()):
            raise ValueError('diagnostics_invalid')
        for key, allowed in [('load', LOAD), ('active', ACTIVE), ('sub', SUB), ('unit_file', UNIT_FILE), ('result', RESULT)]:
            if not isinstance(unit[key], str) or unit[key] not in allowed:
                raise ValueError('diagnostics_invalid')
        for key, maximum in [('exit_code', 6), ('exit_status', 255)]:
            if unit[key] is not None and (type(unit[key]) is not int or not 0 <= unit[key] <= maximum):
                raise ValueError('diagnostics_invalid')
        if any(unit[key] is not None and type(unit[key]) is not bool for key in ('started', 'finished', 'timer_triggered')):
            raise ValueError('diagnostics_invalid')
    for key, validator in [('installation', validate_installation), ('probe', validate_run), ('worker', validate_run), ('last_job', validate_job_result)]:
        if value[key] is not None:
            validator(value[key])
    if value['probe'] is not None and (value['probe']['status'] == 'idle' or value['probe']['job_id'] is not None or value['probe']['phase'] not in ('configuration', 'containment', 'complete')):
        raise ValueError('diagnostics_invalid')
    errors = value['record_errors']
    if not isinstance(errors, list) or any(not isinstance(item, str) or item not in RECORD_ERRORS for item in errors) or errors != sorted(set(errors)) or len(encoded(value)) > MAX_REPORT:
        raise ValueError('diagnostics_invalid')
    return value


def query_systemd():
    command = ['/usr/bin/systemctl', '--system', '--no-pager', '--no-ask-password', '--all', 'show',
               '--property=' + ','.join(PROPERTIES), '--', *UNITS]
    output = bytearray()
    exceeded = threading.Event()
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'SYSTEMD_COLORS': '0'}
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=environment) as process:
        def drain():
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    return
                if len(output) + len(chunk) > MAX_REPORT:
                    exceeded.set()
                    process.kill()
                    return
                output.extend(chunk)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
            reader.join(timeout=1)
            return 'timeout', b''
        reader.join(timeout=1)
        if exceeded.is_set() or reader.is_alive():
            return 'oversize', b''
        return ('ok', bytes(output)) if code == 0 else ('unavailable', b'')


def monotonic_state(value, *, timespan=False):
    if value in (None, ''):
        return None
    if re.fullmatch('[0-9]{1,20}', value):
        if int(value) > 2**64 - 1:
            raise ValueError('diagnostics_invalid')
        return int(value) != 0
    if not timespan or len(value) > 128:
        raise ValueError('diagnostics_invalid')
    scales = {'y': 31557600000000, 'month': 2629800000000, 'w': 604800000000,
              'd': 86400000000, 'h': 3600000000, 'min': 60000000, 's': 1000000, 'ms': 1000, 'us': 1}
    parts = value.split(' ')
    total, previous = 0, -1
    if len(parts) > len(scales):
        raise ValueError('diagnostics_invalid')
    for index, part in enumerate(parts):
        match = re.fullmatch(r'([0-9]{1,20})(?:\.([0-9]{1,6}))?(y|month|w|d|h|min|s|ms|us)', part)
        if match is None:
            raise ValueError('diagnostics_invalid')
        whole, fraction, suffix = match.groups()
        rank = tuple(scales).index(suffix)
        if rank <= previous or fraction is not None and (index != len(parts) - 1 or suffix not in ('s', 'ms')):
            raise ValueError('diagnostics_invalid')
        fraction = fraction or ''
        amount, remainder = divmod(int(whole + fraction) * scales[suffix], 10**len(fraction))
        total += amount
        if remainder or total > 2**64 - 1:
            raise ValueError('diagnostics_invalid')
        previous = rank
    return total != 0


def parse_units(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_REPORT:
        raise ValueError('diagnostics_invalid')
    units = {}
    for block in raw.decode('utf-8', 'strict').strip().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in PROPERTIES or key in fields:
                raise ValueError('diagnostics_invalid')
            fields[key] = value
        name = fields.pop('Id', None)
        if name not in UNITS or name in units or not {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'} <= set(fields):
            raise ValueError('diagnostics_invalid')
        unit = unit_unknown()
        for source, target, allowed in [('LoadState', 'load', LOAD), ('ActiveState', 'active', ACTIVE),
                                        ('SubState', 'sub', SUB), ('UnitFileState', 'unit_file', UNIT_FILE), ('Result', 'result', RESULT)]:
            unit[target] = fields.get(source) if fields.get(source) in allowed else 'unknown'
        for source, target, maximum in [('ExecMainCode', 'exit_code', 6), ('ExecMainStatus', 'exit_status', 255)]:
            if fields.get(source, ''):
                if not re.fullmatch('[0-9]{1,3}', fields[source]) or int(fields[source]) > maximum:
                    raise ValueError('diagnostics_invalid')
                unit[target] = int(fields[source])
        for source, target in [('ExecMainStartTimestampMonotonic', 'started'), ('ExecMainExitTimestampMonotonic', 'finished'), ('LastTriggerUSecMonotonic', 'timer_triggered')]:
            unit[target] = monotonic_state(fields.get(source), timespan=source == 'LastTriggerUSecMonotonic')
        units[name] = unit
    if set(units) != set(UNITS):
        raise ValueError('diagnostics_invalid')
    return units


def read_record(path, validator, *, root_owned=False):
    if path.resolve() != path.absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('diagnostics_invalid')
    if root_owned:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('diagnostics_invalid')
    return validator(parse_json(bounded_read(path, MAX_REPORT)))


def write_latest(path, value, validator):
    validator(value)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(payload) > MAX_REPORT or path.resolve() != path.absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('diagnostics_invalid')
    descriptor, filename = tempfile.mkstemp(prefix='metadata-', dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload)
        temporary.chmod(0o640)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def collect():
    from lab_gateway import capability, configuration_checks
    value = {'api': 2, 'generated_utc': stamp(), 'gateway': capability(), 'configuration_checks': configuration_checks(), 'systemd': 'unavailable',
             'units': {name: unit_unknown() for name in UNITS}, 'installation': None, 'probe': None,
             'worker': None, 'last_job': None, 'record_errors': []}
    try:
        state, raw = query_systemd()
        value['systemd'] = state
        if state == 'ok':
            value['units'] = parse_units(raw)
    except ValueError:
        value['systemd'] = 'invalid'
    except (OSError, subprocess.SubprocessError):
        value['systemd'] = 'unavailable'
    records = [('installation', INSTALLATION, validate_installation),
               ('probe', ROOT / 'reports/probe-status.json', validate_run),
               ('worker', ROOT / 'reports/worker-status.json', validate_run),
               ('job', ROOT / 'reports/last-job.json', validate_job_result),
               ('job', ROOT / 'queued/last-job.json', validate_job_result)]
    for name, path, validator in records:
        try:
            record = read_record(path, validator, root_owned=name == 'installation')
        except FileNotFoundError:
            continue
        except (ValueError, TypeError, KeyError, RecursionError):
            value['record_errors'].append(name + '_invalid')
            continue
        except OSError:
            value['record_errors'].append(name + '_unavailable')
            continue
        if name == 'job':
            previous = value['last_job']
            ranks = {'queued': 0, 'running': 1, 'passed': 2, 'failed': 2, 'interrupted': 2}
            if previous is None or record['generated_utc'] > previous['generated_utc'] or record['generated_utc'] == previous['generated_utc'] and (record['job']['job_id'] != previous['job']['job_id'] or ranks[record['status']] >= ranks[previous['status']]):
                value['last_job'] = record
        else:
            value[name] = record
    value['record_errors'] = sorted(set(value['record_errors']))
    return validate_report(value)


def classify(value):
    validate_report(value)
    for name in ('configuration', 'helpers', 'policy', 'units', 'sshd') if value['api'] == 2 else ():
        state = value['configuration_checks'][name]
        if state != 'passed':
            return 'not_ready', name + '_' + state
    if value['systemd'] != 'ok':
        return 'not_ready', 'systemd_' + value['systemd']
    if value['record_errors']:
        return 'not_ready', 'diagnostic_records_invalid'
    if value['installation'] is not None and value['installation']['status'] == 'failed':
        probe = value['probe']
        unit = value['units'][UNITS[1]]
        if value['installation']['phase'] == 'containment' and unit['active'] == 'failed' and unit['result'] in ('signal', 'core-dump') and unit['exit_code'] in (2, 3) and unit['started'] is True and unit['finished'] is True:
            return 'not_ready', 'containment_probe_signalled'
        if value['installation']['phase'] == 'containment' and probe is not None and probe['status'] == 'failed' and probe['policy_sha256'] == value['installation']['policy_sha256'] and probe['reason'] in CONTAINMENT_REASONS:
            return 'not_ready', probe['reason']
        return 'not_ready', value['installation']['reason']
    if value['installation'] is not None and value['installation']['status'] == 'running':
        return 'not_ready', 'installation_incomplete'
    for name in ('probe', 'worker'):
        if value[name] is not None and value[name]['status'] == 'failed' and value[name]['reason'] in CONTAINMENT_REASONS:
            return 'failed', value[name]['reason']
    if value['api'] == 2 and value['configuration_checks']['proof'] != 'passed':
        return 'not_ready', 'proof_' + value['configuration_checks']['proof']
    if not value['gateway']['installed']:
        return 'not_ready', 'setup_required'
    for name in UNITS:
        unit = value['units'][name]
        if unit['load'] != 'loaded':
            return 'not_ready', 'unit_unavailable'
        if unit['active'] == 'unknown' or unit['sub'] == 'unknown':
            return 'not_ready', 'unit_metadata_unknown'
        if unit['active'] == 'failed' or unit['started'] is True and unit['finished'] is True and (unit['result'] != 'success' or unit['exit_status'] not in (None, 0) or unit['exit_code'] not in (None, 1)):
            return 'failed', 'service_failed'
    for name in ('probe', 'worker'):
        if value[name] is not None and value[name]['status'] == 'failed':
            return 'failed', value[name]['reason']
    if not value['gateway']['verified']:
        return 'not_ready', 'gateway_not_verified'
    timer = value['units'][UNITS[2]]
    if timer['active'] != 'active' or timer['sub'] != 'waiting' or timer['unit_file'] not in ('enabled', 'enabled-runtime', 'static'):
        return 'not_ready', 'timer_inactive'
    job = value['last_job']
    if job is not None:
        if job['job']['policy_sha256'] != value['gateway']['policy_sha256']:
            return 'ready', 'ready_idle'
        if job['status'] in ('queued', 'running'):
            return 'pending', 'job_pending'
        if job['status'] in ('failed', 'interrupted'):
            return 'failed', 'job_failed'
        return 'ready', 'last_job_passed'
    return ('ready', 'ready_idle') if value['units'][UNITS[0]]['started'] else ('ready', 'waiting_for_timer')
