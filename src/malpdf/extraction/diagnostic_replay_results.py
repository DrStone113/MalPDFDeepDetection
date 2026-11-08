import builtins
from copy import deepcopy
import re

from malpdf.extraction.diagnostic_replay import canonical, sha
from malpdf.extraction.numeric_export import project_numeric_bundle
from malpdf.static.worker_diagnostics import exception_record


GRAPH_FIELDS = ('evidence_nodes', 'evidence_edges', 'projected_nodes', 'projected_edges', 'node_sizes_known', 'node_sizes_unknown')
MECHANISMS = frozenset({'wall_timeout', 'allocation_failure', 'memory_error', 'signal_exit_unresolved',
    'worker_exit_unresolved', 'ipc_serialization_error', 'admission_exception', 'worker_exception',
    'graph_build_exception', 'post_worker_exception', 'extraction_boundary_exception', 'no_worker_failure_observed', 'unresolved'})
EXCEPTIONS = {name for name in dir(builtins) if isinstance(getattr(builtins, name), type)
    and issubclass(getattr(builtins, name), BaseException)} | {
    'OtherError', 'PdfReadError', 'PdfStreamError', 'EmptyFileError', 'FileNotDecryptedError',
    'DependencyError', 'ParseError', 'PdfError', 'PasswordError', 'CodeInspectionError', 'JSONDecodeError'}
PHASES = {'validation', 'worker_admission', 'worker_start', 'worker_bootstrap', 'resource_limits', 'profile_boundary',
    'read_hash', 'raw_scan', 'parse_pdf', 'stream_decode', 'js_ast', 'inference_gate', 'inference', 'code',
    'analysis_v8', 'analysis_v9', 'stream_analysis', 'carving', 'parser_analysis', 'raw_forensic', 'script_semantics',
    'byte_images', 'plugin_features', 'checkpoint_serialization', 'result_serialization'}
CLEAN_DIAGNOSTIC_FIELDS = {'schema_version', 'sample_id', 'run_id', 'worker_exit_code', 'cleanup_exit_code',
    'exception_errno', 'elapsed_ms', 'timeout_reason', 'peak_rss_bytes', 'preserved_before_cleanup',
    'checkpoint_received', 'checkpoint_status', 'stderr_truncated', 'stderr_capture_complete', 'exception_type',
    'last_phase', 'exception_phase', 'traceback', 'stderr_text_returned', 'stderr_utf8_bytes', 'stderr_sha256'}


def snapshot(profile):
    return {name: deepcopy(profile.get(name)) for name in (
        'status', 'errors', 'diagnostic', 'worker_cleanup_complete', 'worker_exit_code', 'last_stage')}


def mechanism(diagnostic, parent_error=None, phase=None):
    if parent_error is not None:
        functions = {frame['function'] for frame in exception_record(parent_error)['traceback']}
        if phase == 'numeric_projection' or 'normalize_profile' in functions:
            return 'graph_build_exception'
        return 'post_worker_exception' if phase == 'bundle_build' else 'extraction_boundary_exception'
    if not isinstance(diagnostic, dict):
        return 'unresolved'
    if diagnostic.get('timeout_reason') == 'wall_timeout':
        return 'wall_timeout'
    if diagnostic.get('exception_errno') == 12:
        return 'allocation_failure'
    if diagnostic.get('exception_type') == 'MemoryError':
        return 'memory_error'
    if diagnostic.get('failure_kind') == 'ipc_serialization_error':
        return 'ipc_serialization_error'
    code = diagnostic.get('worker_exit_code')
    if type(code) is int and code != 0 and diagnostic.get('exception_type') in (None, 'EOFError', 'BrokenPipeError'):
        return 'signal_exit_unresolved' if code < 0 else 'worker_exit_unresolved'
    if diagnostic.get('exception_type') is not None:
        return 'admission_exception' if diagnostic.get('last_phase') in ('worker_admission', 'worker_start') else 'worker_exception'
    if type(code) is int and code != 0:
        return 'signal_exit_unresolved' if code < 0 else 'worker_exit_unresolved'
    return 'no_worker_failure_observed' if diagnostic.get('failure_kind') is None and diagnostic.get('cleanup_complete') is True else 'unresolved'


def make_case(record, ordinal, run_id, *, bundle=None, profile=None, parent_error=None, phase=None):
    profile = profile or {}
    diagnostic = deepcopy(profile.get('diagnostic'))
    if diagnostic is None and bundle is not None:
        diagnostic = deepcopy(bundle['coverage_report']['worker'].get('diagnostic'))
    if diagnostic is not None and (diagnostic.get('sample_id') != record['sha256']
            or diagnostic.get('run_id') != run_id or diagnostic.get('schema_version') != 'pdf-worker-diagnostic-v1'):
        raise ValueError('replay_diagnostic_identity')
    graph = {name: None for name in GRAPH_FIELDS}
    if bundle is not None and not (parent_error is not None and phase == 'numeric_projection'):
        numeric = project_numeric_bundle(bundle, record['sha256'])['graph']
        graph.update(evidence_nodes=len(bundle['evidence_store']['records']), evidence_edges=len(bundle['evidence_store']['edges']),
            projected_nodes=len(numeric['node_types']), projected_edges=len(numeric['edge_src']),
            node_sizes_known=sum(item is not None for item in numeric['node_sizes_bytes']),
            node_sizes_unknown=sum(item is None for item in numeric['node_sizes_bytes']))
    graph.update(model_feature_dim=None, model_input_ready=False)
    observed = mechanism(diagnostic, parent_error, phase)
    parent = exception_record(parent_error) if parent_error is not None else None
    signature_input = ({key: diagnostic.get(key) for key in ('exception_type', 'exception_errno', 'exception_phase',
        'last_phase', 'timeout_reason', 'worker_exit_code', 'traceback')} if diagnostic is not None else None)
    signature = sha(canonical({'mechanism': observed, 'diagnostic': signature_input, 'parent': parent})) if diagnostic is not None or parent is not None else None
    status = bundle['status'] if bundle is not None else None
    nodes = graph['projected_nodes']
    return {'schema_version': 1, 'run_id': run_id, 'replay_ordinal': ordinal, 'baseline_index': record['baseline_index'],
        'sha256': record['sha256'], 'label': record['label'], 'split': record['split'],
        'baseline': {name: deepcopy(record[name]) for name in ('baseline_bundle_sha256', 'baseline_bundle_status',
            'baseline_worker', 'baseline_failure_family', 'baseline_graph')},
        'replay': {'bundle_status': status, 'bundle_sha256': sha(canonical(bundle)) if bundle is not None else None,
            'profile_status': profile.get('status'), 'diagnostic': diagnostic, 'graph': graph,
            'parent_exception': parent, 'parent_exception_phase': phase},
        'comparison': {'bundle_status_changed': status != record['baseline_bundle_status'] if status is not None else None,
            'graph_restored': nodes > 0 if nodes is not None else None},
        'classification': {'observed_mechanism': observed, 'root_cause': None,
            'diagnostic_signature': signature, 'parser_corruption_confirmed': False}}


def safe_trace(frames):
    if frames is None:
        return None
    if not isinstance(frames, list) or len(frames) > 32:
        raise ValueError('replay_trace')
    result = []
    for frame in frames:
        if not isinstance(frame, dict) or set(frame) != {'file', 'function', 'line'}:
            raise ValueError('replay_trace_frame')
        file, function, line = frame['file'], frame['function'], frame['line']
        if not isinstance(file, str) or not isinstance(function, str) or type(line) is not int or not 0 <= line <= 10**7:
            raise ValueError('replay_trace_frame')
        if len(file) > 180 or not re.fullmatch(r'(?:malpdf/[A-Za-z0-9_/]+|[A-Za-z0-9_]+)\.py', file):
            file = 'external.py'
        if len(function) > 80 or not (function.isidentifier() or function in ('<module>', '<lambda>', '<listcomp>', '<dictcomp>', '<setcomp>', '<genexpr>')):
            function = 'unknown'
        result.append({'file': file, 'function': function, 'line': line})
    return result


def sanitized_case(case):
    result = deepcopy(case)
    diagnostic = result['replay']['diagnostic']
    if diagnostic is not None:
        clean = {key: diagnostic.get(key) for key in ('schema_version', 'sample_id', 'run_id', 'worker_exit_code',
            'cleanup_exit_code', 'exception_errno', 'elapsed_ms', 'timeout_reason', 'peak_rss_bytes',
            'preserved_before_cleanup', 'checkpoint_received', 'checkpoint_status', 'stderr_truncated', 'stderr_capture_complete')}
        clean['exception_type'] = diagnostic.get('exception_type') if diagnostic.get('exception_type') in EXCEPTIONS else 'OtherError'
        if diagnostic.get('exception_type') is None:
            clean['exception_type'] = None
        for key in ('last_phase', 'exception_phase'):
            clean[key] = diagnostic.get(key) if diagnostic.get(key) in PHASES else None
        clean['traceback'] = safe_trace(diagnostic.get('traceback'))
        stderr = diagnostic.get('stderr')
        clean['stderr_text_returned'] = False
        clean['stderr_utf8_bytes'] = len(stderr.encode('utf-8')) if isinstance(stderr, str) else None
        clean['stderr_sha256'] = sha(stderr.encode('utf-8')) if isinstance(stderr, str) else None
        result['replay']['diagnostic'] = clean
    parent = result['replay']['parent_exception']
    if parent is not None:
        result['replay']['parent_exception'] = {'exception_type': parent['exception_type'] if parent['exception_type'] in EXCEPTIONS else 'OtherError',
            'exception_errno': parent['exception_errno'], 'traceback': safe_trace(parent['traceback'])}
    if result['classification']['observed_mechanism'] not in MECHANISMS:
        raise ValueError('replay_mechanism')
    return result
