from collections import Counter, defaultdict
import json
from pathlib import Path

from malpdf.extraction.diagnostic_replay import HASH, MAX_BUNDLE, canonical, read, sha
from malpdf.extraction.diagnostic_replay_results import (
    CLEAN_DIAGNOSTIC_FIELDS, EXCEPTIONS, GRAPH_FIELDS, MECHANISMS, PHASES, safe_trace, sanitized_case,
)
from malpdf.extraction.numeric_export import STATUSES


CASE_FIELDS = {'schema_version', 'run_id', 'replay_ordinal', 'baseline_index', 'sha256', 'label', 'split',
    'baseline', 'replay', 'comparison', 'classification'}
REPLAY_FIELDS = {'bundle_status', 'bundle_sha256', 'profile_status', 'diagnostic', 'graph', 'parent_exception', 'parent_exception_phase'}
PROFILE_STATUSES = {'complete', 'partial', 'parser_error', 'input_error', 'worker_error', 'timeout', 'resource_limit_or_signal'}


def validate_case(case, record, ordinal, run_id):
    if (not isinstance(case, dict) or set(case) != CASE_FIELDS or type(case['schema_version']) is not int or case['schema_version'] != 1
            or type(case['replay_ordinal']) is not int or type(case['baseline_index']) is not int
            or case['run_id'] != run_id or case['replay_ordinal'] != ordinal or case['baseline_index'] != record['baseline_index']
            or case['sha256'] != record['sha256'] or type(case['label']) is not int or case['label'] != record['label']
            or case['split'] != record['split']):
        raise ValueError('replay_case_identity')
    expected = {key: record[key] for key in ('baseline_bundle_sha256', 'baseline_bundle_status', 'baseline_worker',
        'baseline_failure_family', 'baseline_graph')}
    if case['baseline'] != expected:
        raise ValueError('replay_case_baseline')
    value = case['replay']
    if not isinstance(value, dict) or set(value) != REPLAY_FIELDS:
        raise ValueError('replay_case_shape')
    if value['bundle_status'] is not None and value['bundle_status'] not in STATUSES:
        raise ValueError('replay_case_status')
    if value['profile_status'] is not None and value['profile_status'] not in PROFILE_STATUSES:
        raise ValueError('replay_profile_status')
    if value['bundle_sha256'] is not None and (not isinstance(value['bundle_sha256'], str) or not HASH.fullmatch(value['bundle_sha256'])):
        raise ValueError('replay_case_hash')
    if value['parent_exception_phase'] not in (None, 'extract_boundary', 'bundle_build', 'numeric_projection'):
        raise ValueError('replay_parent_phase')
    graph = value['graph']
    if (not isinstance(graph, dict) or set(graph) != {*GRAPH_FIELDS, 'model_feature_dim', 'model_input_ready'}
            or graph['model_feature_dim'] is not None or graph['model_input_ready'] is not False
            or any(graph[key] is not None and (type(graph[key]) is not int or not 0 <= graph[key] <= 10**9) for key in GRAPH_FIELDS)):
        raise ValueError('replay_graph')
    nodes = graph['projected_nodes']
    if (nodes is None and any(graph[key] is not None for key in GRAPH_FIELDS)
            or nodes is not None and any(graph[key] is None for key in GRAPH_FIELDS)):
        raise ValueError('replay_graph_availability')
    if nodes is not None and (nodes > 200 or graph['node_sizes_known'] is None or graph['node_sizes_unknown'] is None
            or graph['node_sizes_known'] + graph['node_sizes_unknown'] != nodes):
        raise ValueError('replay_graph_sizes')
    comparison = {'bundle_status_changed': value['bundle_status'] != record['baseline_bundle_status'] if value['bundle_status'] is not None else None,
        'graph_restored': nodes > 0 if nodes is not None else None}
    if case['comparison'] != comparison:
        raise ValueError('replay_case_comparison')
    classification = case['classification']
    if (not isinstance(classification, dict) or set(classification) != {'observed_mechanism', 'root_cause', 'diagnostic_signature', 'parser_corruption_confirmed'}
            or classification['observed_mechanism'] not in MECHANISMS or classification['root_cause'] is not None
            or classification['parser_corruption_confirmed'] is not False
            or classification['diagnostic_signature'] is not None and (not isinstance(classification['diagnostic_signature'], str)
                or not HASH.fullmatch(classification['diagnostic_signature']))):
        raise ValueError('replay_classification')
    diagnostic = value['diagnostic']
    if diagnostic is not None:
        if (not isinstance(diagnostic, dict) or diagnostic.get('schema_version') != 'pdf-worker-diagnostic-v1'
                or diagnostic.get('sample_id') != record['sha256'] or diagnostic.get('run_id') != run_id):
            raise ValueError('replay_diagnostic_identity')
        for key in ('worker_exit_code', 'cleanup_exit_code', 'exception_errno', 'elapsed_ms', 'peak_rss_bytes'):
            number = diagnostic.get(key)
            if number is not None and (type(number) is not int or not -2**31 <= number <= 10**12):
                raise ValueError('replay_diagnostic_number')
        for key in ('preserved_before_cleanup', 'checkpoint_received', 'stderr_truncated', 'stderr_capture_complete'):
            if diagnostic.get(key) is not None and type(diagnostic[key]) is not bool:
                raise ValueError('replay_diagnostic_flag')
        if diagnostic.get('timeout_reason') not in (None, 'wall_timeout') or diagnostic.get('checkpoint_status') not in (None, *PROFILE_STATUSES):
            raise ValueError('replay_diagnostic_enum')
        text = diagnostic.get('stderr')
        if text is not None and (not isinstance(text, str) or len(text.encode('utf-8')) > 65536):
            raise ValueError('replay_diagnostic_stderr')
    sanitized_case(case)
    return case


def summarize(records, lock, run_id):
    groups = defaultdict(list)
    availability, mechanisms = Counter(), Counter()
    diagnostic_count = restored = graph_observed = 0
    for row in records:
        availability[row['availability']] += 1
        if row['case'] is not None:
            case = row['case']
            diagnostic = case['replay']['diagnostic']
            diagnostic_count += (diagnostic is not None and diagnostic.get('preserved_before_cleanup') is True
                and diagnostic.get('elapsed_ms') is not None and diagnostic.get('last_phase') is not None)
            restored += case['comparison']['graph_restored'] is True
            graph_observed += case['replay']['graph']['projected_nodes'] is not None
            mechanisms[case['classification']['observed_mechanism']] += 1
            signature = case['classification']['diagnostic_signature']
            if signature is not None:
                groups[signature].append(row['baseline_index'])
    return {'schema_version': 1, 'stage': 'BUG-007B1', 'run_id': run_id,
        'baseline_job_id': lock['baseline_job_id'], 'planned': 74, 'availability_counts': dict(availability),
        'diagnostic_records': diagnostic_count, 'graph_results_observed': graph_observed, 'graphs_restored': restored,
        'diagnostic_coverage_complete': availability['present'] == diagnostic_count == 74,
        'observed_mechanism_counts': dict(mechanisms),
        'diagnostic_groups': [{'signature': signature, 'baseline_indices': indices} for signature, indices in sorted(groups.items())],
        'grouping_scope': 'matching diagnostic signatures are not proof of a common root cause',
        'historical_root_causes_confirmed': None, 'node_cap': 200, 'model_feature_dim': None,
        'model_input_ready': False, 'b2_executed': False, 'training_executed': False, 'stderr_text_returned': False}


def validate_export(records, summary, lock, run_id):
    if not isinstance(records, list) or len(records) != 74:
        raise ValueError('replay_export_denominator')
    fields = {'schema_version', 'run_id', 'replay_ordinal', 'baseline_index', 'sha256', 'label', 'split', 'availability', 'case'}
    for ordinal, (row, pinned) in enumerate(zip(records, lock['records'])):
        if (not isinstance(row, dict) or set(row) != fields or row['schema_version'] != 1 or row['run_id'] != run_id
                or type(row['replay_ordinal']) is not int or row['replay_ordinal'] != ordinal
                or type(row['baseline_index']) is not int or row['baseline_index'] != pinned['baseline_index']
                or row['sha256'] != pinned['sha256'] or type(row['label']) is not int or row['label'] != pinned['label']
                or row['split'] != pinned['split'] or row['availability'] not in ('present', 'missing', 'invalid')):
            raise ValueError('replay_export_identity')
        if row['availability'] != 'present':
            if row['case'] is not None:
                raise ValueError('replay_export_unavailable')
            continue
        case = validate_case(row['case'], pinned, ordinal, run_id)
        diagnostic = case['replay']['diagnostic']
        if diagnostic is not None:
            if (set(diagnostic) != CLEAN_DIAGNOSTIC_FIELDS or diagnostic['stderr_text_returned'] is not False
                    or diagnostic['exception_type'] is not None and diagnostic['exception_type'] not in EXCEPTIONS
                    or diagnostic['last_phase'] is not None and diagnostic['last_phase'] not in PHASES
                    or diagnostic['exception_phase'] is not None and diagnostic['exception_phase'] not in PHASES
                    or safe_trace(diagnostic['traceback']) != diagnostic['traceback']):
                raise ValueError('replay_export_diagnostic')
            size, digest = diagnostic['stderr_utf8_bytes'], diagnostic['stderr_sha256']
            if (size is not None and (type(size) is not int or not 0 <= size <= 65536)
                    or digest is not None and (not isinstance(digest, str) or not HASH.fullmatch(digest))
                    or (size is None) != (digest is None)):
                raise ValueError('replay_export_stderr_metadata')
        parent = case['replay']['parent_exception']
        if parent is not None and (set(parent) != {'exception_type', 'exception_errno', 'traceback'}
                or parent['exception_type'] not in EXCEPTIONS or safe_trace(parent['traceback']) != parent['traceback']):
            raise ValueError('replay_export_parent')
    if canonical(summary) != canonical(summarize(records, lock, run_id)):
        raise ValueError('replay_export_summary')
    return summary


def render_report(records, summary):
    def cell(value):
        return 'null' if value is None else str(value)
    lines = ['# BUG-007B1 — Diagnostic Replay', '', f"Run: `{summary['run_id']}`", '',
        f"Planned: 74; diagnostic records: {summary['diagnostic_records']}; graphs restored: {summary['graphs_restored']}.",
        'Root causes remain null where the evidence establishes only a mechanism. Matching signatures do not prove a common root cause.',
        'Baseline exit codes are legacy post-cleanup observations. Replay exit and cleanup codes are separate.',
        'Outer shard setup/supervisor diagnostics are in outer_diagnostics.json; missing per-PDF attempts remain null.',
        'Graph restored means a nonempty projection under the unchanged graph definition and node cap 200; model inputs remain unavailable.', '',
        '| Baseline index | Split | Label | Replay status | Exit before cleanup | Cleanup exit | Last phase | Exception | Nodes | Edges | Mechanism |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in records:
        case = row['case']
        replay = case['replay'] if case is not None else {}
        diagnostic, graph = replay.get('diagnostic') or {}, replay.get('graph') or {}
        mechanism = case['classification']['observed_mechanism'] if case is not None else None
        values = (row['baseline_index'], row['split'], row['label'], replay.get('bundle_status'), diagnostic.get('worker_exit_code'),
            diagnostic.get('cleanup_exit_code'), diagnostic.get('last_phase'), diagnostic.get('exception_type'),
            graph.get('projected_nodes'), graph.get('projected_edges'), mechanism)
        lines.append('| ' + ' | '.join(cell(value) for value in values) + ' |')
    return '\n'.join(lines) + '\n'


def finalize_report(job, directory, lock, operations):
    directory = Path(directory)
    records = []
    for ordinal, pinned in enumerate(lock['records']):
        row = {'schema_version': 1, 'run_id': job['job_id'], 'replay_ordinal': ordinal,
            'baseline_index': pinned['baseline_index'], 'sha256': pinned['sha256'], 'label': pinned['label'], 'split': pinned['split'],
            'availability': 'missing', 'case': None}
        path = directory / 'private_cases' / f'{ordinal:04d}.json'
        if path.exists():
            try:
                case = validate_case(json.loads(read(path, directory, 128 * 1024)), pinned, ordinal, job['job_id'])
                digest = case['replay']['bundle_sha256']
                if digest is not None and sha(read(directory / 'private_bundles' / f'{ordinal:04d}.json', directory, MAX_BUNDLE)) != digest:
                    raise ValueError('replay_bundle_changed')
                row.update(availability='present', case=sanitized_case(case))
            except (OSError, ValueError, TypeError, KeyError):
                row['availability'] = 'invalid'
        records.append(row)
    summary = summarize(records, lock, job['job_id'])
    validate_export(records, summary, lock, job['job_id'])
    output = directory / 'analysis'
    output.mkdir(mode=0o700, exist_ok=True)
    from malpdf.extraction.diagnostic_replay_outer import write_outer
    outer_sha256 = write_outer(job, directory, lock)
    rows_payload = b''.join(canonical(row) + b'\n' for row in records)
    path = output / 'cases.jsonl'
    if path.exists():
        if read(path, directory, 16 * 1024**2) != rows_payload:
            raise ValueError('replay_report_collision')
    else:
        with path.open('xb') as stream:
            stream.write(rows_payload)
    operations.immutable(output / 'summary.json', summary)
    report = render_report(records, summary).encode('utf-8')
    report_path = output / 'report.md'
    if report_path.exists():
        if read(report_path, directory, 256 * 1024) != report:
            raise ValueError('replay_report_collision')
    else:
        with report_path.open('xb') as stream:
            stream.write(report)
    operations.immutable(output / 'manifest.json', {'schema_version': 1, 'run_id': job['job_id'], 'files': {
        'cases.jsonl': sha(rows_payload), 'summary.json': sha(canonical(summary) + b'\n'),
        'report.md': sha(report), 'outer_diagnostics.json': outer_sha256}})
    return summary
