"""Keep completed static evidence when an independent VM supplement fails."""

from collections.abc import Callable

from malpdf.static.execution import is_vm


def run_branch(result: dict, name: str, operation: Callable[[], dict], limits: object) -> dict | None:
    try:
        value = operation()
    except (BrokenPipeError, ConnectionError):
        raise
    except Exception as error:
        if not is_vm(limits):
            raise
        status = 'resource_limit' if isinstance(error, (MemoryError, RecursionError)) else 'partial'
        code = 'extraction_branch_resource_limit' if status == 'resource_limit' else 'extraction_branch_failed'
        result.setdefault('primary_status', result['status'])
        result['status'] = 'partial'
        result['errors'] = sorted(set(result.get('errors', [])) | {code})
        result.setdefault('stage_failures', []).append({'stage': name, 'status': status,
            'reason_code': code, 'error_type': type(error).__name__})
        return None
    result[name] = value
    return value


def restore_failed_prefixes(result: dict, checkpoint: dict | None) -> None:
    for failure in result.get('stage_failures', []):
        name = failure['stage']
        if name not in result and checkpoint is not None and isinstance(checkpoint.get(name), dict):
            value = checkpoint[name]
            result[name] = {**value, 'status': 'partial', 'complete': False,
                'reason_codes': sorted(set(value.get('reason_codes', [])) | {failure['reason_code']}),
                'worker_failure_codes': [failure['reason_code']]}
