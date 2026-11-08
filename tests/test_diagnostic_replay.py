from copy import deepcopy
import hashlib
import importlib
import json
import os
from types import SimpleNamespace
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def locked():
    return json.loads((ROOT / 'configs/pdf_diagnostic_replay.json').read_text())


def test_replay_lock_selects_only_the_74_unresolved_cases_and_freezes_representation():
    from malpdf.extraction.diagnostic_replay import validate_lock
    value = validate_lock(locked())
    assert len(value['records']) == 74
    assert sum(row['baseline_failure_family'] == 'worker_error_unspecified' for row in value['records']) == 70
    assert sum(row['baseline_failure_family'] == 'timeout' for row in value['records']) == 4
    assert 141 not in [row['baseline_index'] for row in value['records']]
    assert value['node_cap'] == 200 and value['cache_reuse'] is False
    for name, expected in value['unchanged_code_sha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() == expected


@pytest.mark.parametrize('change', ['duplicate', 'label', 'cap', 'count', 'family', 'zero', 'cache'])
def test_replay_lock_refuses_tampered_scope(change):
    from malpdf.extraction.diagnostic_replay import validate_lock
    value = locked()
    if change == 'duplicate':
        value['records'][1]['baseline_index'] = value['records'][0]['baseline_index']
    elif change == 'label':
        value['records'][0]['label'] = True
    elif change == 'cap':
        value['node_cap'] = 400
    elif change == 'count':
        value['records'].pop()
    elif change == 'family':
        value['records'][0]['baseline_failure_family'] = 'parser_error'
    elif change == 'zero':
        value['records'][0]['baseline_graph']['projected_nodes'] = 1
    else:
        value['cache_reuse'] = True
    with pytest.raises(ValueError, match='replay_'):
        validate_lock(value)


def test_replay_rows_keep_original_identity_and_refuse_changed_selection():
    from malpdf.extraction.diagnostic_replay import select_rows, canonical
    lock = locked()
    rows = [{'pdf_sha256': 'f' * 64, 'Label': '0', 'split': 'train',
        'pdf_relative_path': 'data/raw/cic_pdf/reviewed.pdf'} for _ in range(1452)]
    for item in lock['records']:
        rows[item['baseline_index']] = {'pdf_sha256': item['sha256'], 'Label': str(item['label']),
            'split': item['split'], 'pdf_relative_path': f"data/raw/cic_pdf/{item['sha256']}.pdf"}
    lock['baseline_selection_sha256'] = hashlib.sha256(canonical(rows)).hexdigest()
    selection = {'job_id': lock['baseline_job_id'], 'selection_sha256': lock['baseline_selection_sha256'], 'rows': rows}
    before = deepcopy(selection)
    selected = select_rows(lock, selection)
    assert selected == [rows[item['baseline_index']] for item in lock['records']]
    assert before == selection
    selection['rows'][lock['records'][0]['baseline_index']]['split'] = 'test'
    with pytest.raises(ValueError, match='replay_selection'):
        select_rows(lock, selection)


def test_replay_policy_changes_only_sample_count_and_requires_offline(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts/lab'))
    jobs = importlib.import_module('lab_jobs')
    policy = jobs.policy('pdf-diagnostic-replay')
    assert policy == {**jobs.policy('pdf-static-cic-full'), 'samples': 74}
    job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-diagnostic-replay', mode='offline')
    assert jobs.validate_job(job) == job
    with pytest.raises(ValueError, match='job_mismatch'):
        jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-diagnostic-replay', mode='host-only')


@pytest.mark.skipif(os.name != 'posix', reason='Path extraction is restricted to the Linux LAB')
def test_profile_observer_saves_diagnostic_before_bundle_normalization(monkeypatch):
    from malpdf.extraction import orchestrator
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    fixture = ROOT / 'tests/fixtures/real_benign_document.pdf'
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    diagnostic = WorkerDiagnostics(digest, 'e' * 64).data
    observed = []
    monkeypatch.setattr(orchestrator, 'profile_pdf', lambda *args, **kwargs: {
        'status': 'worker_error', 'errors': ['worker_exit'], 'diagnostic': diagnostic})
    def normalize(*args, **kwargs):
        assert observed[0]['diagnostic'] == diagnostic
        raise ValueError('CONTROLLED_NORMALIZATION_FAILURE')
    monkeypatch.setattr(orchestrator, 'normalize_profile', normalize)
    with pytest.raises(ValueError, match='CONTROLLED_NORMALIZATION_FAILURE'):
        orchestrator.extract_pdf(fixture, profile_observer=observed.append)
    assert observed[0]['status'] == 'worker_error'


@pytest.mark.parametrize(('diagnostic', 'expected'), [
    ({'timeout_reason': 'wall_timeout'}, 'wall_timeout'),
    ({'worker_exit_code': -9}, 'signal_exit_unresolved'),
    ({'worker_exit_code': -9, 'exception_type': 'EOFError'}, 'signal_exit_unresolved'),
    ({'exception_type': 'MemoryError'}, 'memory_error'),
    ({'exception_type': 'OSError', 'exception_errno': 12}, 'allocation_failure'),
    ({'exception_type': 'ValueError', 'last_phase': 'parse_pdf'}, 'worker_exception'),
    ({'exception_type': 'ValueError', 'last_phase': 'worker_admission'}, 'admission_exception'),
    ({'failure_kind': 'ipc_serialization_error'}, 'ipc_serialization_error'),
    ({}, 'unresolved'),
])
def test_replay_classifies_only_observed_mechanisms(diagnostic, expected):
    from malpdf.extraction.diagnostic_replay_results import mechanism
    assert mechanism(diagnostic) == expected


def test_replay_keeps_unknown_graph_null_and_raw_stderr_private():
    from malpdf.extraction.diagnostic_replay_results import make_case, sanitized_case
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    row = locked()['records'][0]
    diagnostic = WorkerDiagnostics(row['sha256'], 'e' * 64).data
    diagnostic.update(stderr='PRIVATE_STDERR_MESSAGE', timeout_reason='wall_timeout',
        preserved_before_cleanup=True, last_phase='parse_pdf')
    case = make_case(row, 0, 'e' * 64, profile={'status': 'timeout', 'diagnostic': diagnostic})
    assert case['replay']['diagnostic']['stderr'] == 'PRIVATE_STDERR_MESSAGE'
    assert case['replay']['graph']['projected_nodes'] is None
    assert case['comparison']['graph_restored'] is None
    assert case['classification']['root_cause'] is None
    exported = sanitized_case(case)
    assert 'PRIVATE_STDERR_MESSAGE' not in json.dumps(exported)
    assert exported['replay']['diagnostic']['stderr_utf8_bytes'] == len('PRIVATE_STDERR_MESSAGE')
    assert exported['replay']['diagnostic']['stderr_text_returned'] is False
    assert exported['replay']['diagnostic']['worker_exit_code'] is None


def test_replay_diagnostic_for_another_run_or_sample_is_refused():
    from malpdf.extraction.diagnostic_replay_results import make_case
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    row = locked()['records'][0]
    diagnostic = WorkerDiagnostics(row['sha256'], 'f' * 64).data
    with pytest.raises(ValueError, match='replay_diagnostic_identity'):
        make_case(row, 0, 'e' * 64, profile={'diagnostic': diagnostic})


def operations(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts/lab'))
    jobs = importlib.import_module('lab_jobs')
    monkeypatch.setattr(jobs, 'JOBS', tmp_path / 'jobs')
    job = jobs.make_job('a' * 40, 'b' * 64, 'c' * 64, kind='pdf-diagnostic-replay', mode='offline')
    folder = jobs.save_job(job)
    return jobs, job, folder


def test_replay_report_preserves_74_denominator_and_never_exports_private_text(tmp_path, monkeypatch):
    from malpdf.extraction.diagnostic_replay import canonical
    from malpdf.extraction.diagnostic_replay_results import make_case
    from malpdf.extraction.diagnostic_replay_report import finalize_report, validate_export
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    jobs, job, folder = operations(monkeypatch, tmp_path)
    lock = locked()
    row = lock['records'][0]
    diagnostic = WorkerDiagnostics(row['sha256'], job['job_id']).data
    diagnostic.update(stderr='PRIVATE_PDF_STDERR', preserved_before_cleanup=True, elapsed_ms=99,
        last_phase='parse_pdf', timeout_reason='wall_timeout', resource_limits={'PRIVATE_RESOURCE': 'PRIVATE_PDF_STDERR'})
    case = make_case(row, 0, job['job_id'], profile={'status': 'timeout', 'diagnostic': diagnostic})
    (folder / 'private_cases').mkdir()
    jobs.immutable(folder / 'private_cases/0000.json', case)
    before = (folder / 'private_cases/0000.json').read_bytes()
    summary = finalize_report(job, folder, lock, jobs)
    assert summary['planned'] == 74
    assert summary['availability_counts'] == {'present': 1, 'missing': 73}
    assert summary['diagnostic_records'] == 1
    assert summary['graphs_restored'] == 0
    assert summary['historical_root_causes_confirmed'] is None
    assert summary['diagnostic_coverage_complete'] is False
    lines = (folder / 'analysis/cases.jsonl').read_text().splitlines()
    assert len(lines) == 74 and 'PRIVATE_PDF_STDERR' not in ''.join(lines)
    assert all(json.loads(line)['case'] is None for line in lines[1:])
    assert (folder / 'private_cases/0000.json').read_bytes() == before
    assert finalize_report(job, folder, lock, jobs) == summary
    manifest = json.loads((folder / 'analysis/manifest.json').read_text())
    for name, expected in manifest['files'].items():
        assert hashlib.sha256((folder / 'analysis' / name).read_bytes()).hexdigest() == expected
    exported = [json.loads(line) for line in lines]
    assert validate_export(exported, summary, lock, job['job_id']) == summary
    exported[0]['case']['replay']['diagnostic']['stderr'] = 'PRIVATE_INJECTED_TEXT'
    with pytest.raises(ValueError, match='replay_export_diagnostic'):
        validate_export(exported, summary, lock, job['job_id'])
    altered = deepcopy(summary)
    altered['graphs_restored'] = 74
    with pytest.raises(ValueError, match='replay_export_summary'):
        validate_export([json.loads(line) for line in lines], altered, lock, job['job_id'])
    assert 'null' in (folder / 'analysis/report.md').read_text()
    assert 'PRIVATE_PDF_STDERR' not in (folder / 'analysis/report.md').read_text()
    assert canonical(case)


def test_replay_case_with_unknown_field_is_invalid_without_replacing_nulls(tmp_path, monkeypatch):
    from malpdf.extraction.diagnostic_replay_results import make_case
    from malpdf.extraction.diagnostic_replay_report import finalize_report
    jobs, job, folder = operations(monkeypatch, tmp_path)
    lock = locked()
    case = make_case(lock['records'][0], 0, job['job_id'])
    case['private_text'] = 'PRIVATE_TEXT'
    (folder / 'private_cases').mkdir()
    jobs.immutable(folder / 'private_cases/0000.json', case)
    summary = finalize_report(job, folder, lock, jobs)
    assert summary['availability_counts'] == {'invalid': 1, 'missing': 73}
    exported = json.loads((folder / 'analysis/cases.jsonl').read_text().splitlines()[0])
    assert exported['availability'] == 'invalid' and exported['case'] is None
    assert 'PRIVATE_TEXT' not in (folder / 'analysis/cases.jsonl').read_text()


def test_replay_case_validates_restored_graph_without_filling_missing_node_size():
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.extraction.diagnostic_replay_results import make_case
    from malpdf.extraction.diagnostic_replay_report import validate_case
    row = locked()['records'][0]
    bundle = normalize_profile({'status': 'partial', 'errors': []}, row['sha256'], 'deep-static')
    bundle['evidence_store']['records'].append({'evidence_id': 'root', 'kind': 'catalog',
        'observation_status': 'observed', 'details': {}})
    case = make_case(row, 0, 'e' * 64, bundle=bundle)
    validate_case(case, row, 0, 'e' * 64)
    assert case['comparison']['graph_restored'] is True
    assert case['replay']['graph']['projected_nodes'] == 1
    assert case['replay']['graph']['node_sizes_unknown'] == 1
    assert case['replay']['graph']['model_feature_dim'] is None
    assert case['replay']['graph']['model_input_ready'] is False


@pytest.mark.parametrize('failed_build', [False, True])
def test_replay_shard_keeps_private_worker_snapshot_and_reuses_only_its_own_results(tmp_path, monkeypatch, failed_build):
    from malpdf.extraction import diagnostic_replay_runner as runner
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    jobs, job, folder = operations(monkeypatch, tmp_path)
    lock = locked()
    pinned = lock['records'][0]
    row = {'pdf_sha256': pinned['sha256'], 'pdf_relative_path': 'data/raw/cic_pdf/controlled.pdf'}
    monkeypatch.setattr(runner, 'verify_replay', lambda *args, **kwargs: lock)
    observed = []
    def extract(*args, **kwargs):
        diagnostic = WorkerDiagnostics(pinned['sha256'], job['job_id']).data
        diagnostic.update(preserved_before_cleanup=True, cleanup_complete=True, cleanup_exit_code=0,
            worker_exit_code=0, elapsed_ms=2, last_phase='result_serialization', stderr='PRIVATE_SHARD_STDERR')
        profile = {'status': 'complete', 'errors': [], 'diagnostic': diagnostic,
            'worker_cleanup_complete': True, 'worker_exit_code': 0}
        kwargs['profile_observer'](profile)
        files = list((folder / 'private_attempts').glob('*/worker.json'))
        assert len(files) == 1 and 'PRIVATE_SHARD_STDERR' in files[0].read_text()
        observed.append(True)
        if failed_build:
            raise ValueError('PRIVATE_BUILD_MESSAGE')
        return normalize_profile(profile, pinned['sha256'], 'deep-static')
    monkeypatch.setattr(runner, 'extract_pdf', extract)
    limits = CodeInspectionLimits(wall_seconds=35, cpu_seconds=30)
    runner.run_shard(job, folder, ROOT, tmp_path, [(0, row)], limits, None, 0, 1, jobs)
    case = json.loads((folder / 'private_cases/0000.json').read_text())
    assert len(observed) == 1
    if failed_build:
        assert case['replay']['graph']['projected_nodes'] is None
        assert case['classification']['observed_mechanism'] == 'post_worker_exception'
        assert 'PRIVATE_BUILD_MESSAGE' not in json.dumps(case)
    else:
        assert case['replay']['bundle_sha256'] == hashlib.sha256((folder / 'private_bundles/0000.json').read_bytes()).hexdigest()
    saved = (folder / 'private_cases/0000.json').read_bytes()
    monkeypatch.setattr(runner, 'extract_pdf', lambda *args, **kwargs: pytest.fail('Completed replay was run again'))
    runner.run_shard(job, folder, ROOT, tmp_path, [(0, row)], limits, None, 0, 1, jobs)
    assert (folder / 'private_cases/0000.json').read_bytes() == saved


def test_replay_shard_survives_boot_memtotal_shift_without_rewriting_methodology_and_rejects_package_drift(tmp_path, monkeypatch):
    from malpdf.extraction import diagnostic_replay_runner as runner
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    jobs, job, folder = operations(monkeypatch, tmp_path)
    lock = locked()
    pinned = lock['records'][0]
    row = {'pdf_sha256': pinned['sha256'], 'pdf_relative_path': 'data/raw/cic_pdf/controlled.pdf'}
    monkeypatch.setattr(runner.sys, 'platform', 'linux')
    monkeypatch.setattr(runner, 'load_replay', lambda *args: (lock, [row] * 74))
    staging_env = {
        'python': '3.11.17',
        'platform': 'Linux-6.8.0-147-generic-x86_64-with-glibc2.39',
        'machine': 'x86_64',
        'logical_cpus': 12,
        'memory_bytes': 6222553088,
        'packages': {'numpy': '2.4.6', 'pandas': '2.3.3', 'pypdf': '6.18.1', 'PyMuPDF': '1.26.7',
            'pikepdf': '10.17.0', 'esprima': '4.0.1', 'torch': '2.11.0+cpu', 'torchvision': '0.26.0+cpu'},
        'thread_environment': {'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1'},
    }
    monkeypatch.setattr(runner, 'environment', lambda: deepcopy(staging_env))
    runner.prepare_replay(job, folder, ROOT, jobs)
    locked_bytes_before = (folder / 'locked_methodology.json').read_bytes()
    runtime_env = {**deepcopy(staging_env), 'memory_bytes': 6222536704}
    monkeypatch.setattr(runner, 'environment', lambda: deepcopy(runtime_env))
    def extract(*args, **kwargs):
        diagnostic = WorkerDiagnostics(pinned['sha256'], job['job_id']).data
        diagnostic.update(preserved_before_cleanup=True, cleanup_complete=True, cleanup_exit_code=0,
            worker_exit_code=0, elapsed_ms=3, last_phase='result_serialization')
        profile = {'status': 'complete', 'errors': [], 'diagnostic': diagnostic,
            'worker_cleanup_complete': True, 'worker_exit_code': 0}
        kwargs['profile_observer'](profile)
        return normalize_profile(profile, pinned['sha256'], 'deep-static')
    monkeypatch.setattr(runner, 'extract_pdf', extract)
    limits = CodeInspectionLimits(wall_seconds=35, cpu_seconds=30)
    runner.run_shard(job, folder, ROOT, tmp_path, [(0, row)], limits, None, 0, 10, jobs)
    assert (folder / 'locked_methodology.json').read_bytes() == locked_bytes_before
    shard_env = json.loads((folder / 'private_outer/environment.0.json').read_text())
    assert shard_env['environment']['memory_bytes'] == 6222536704
    second_boot_env = {**deepcopy(staging_env), 'memory_bytes': 6222520320, 'platform': 'Linux-6.8.0-148-generic-x86_64-with-glibc2.39'}
    monkeypatch.setattr(runner, 'environment', lambda: deepcopy(second_boot_env))
    runner.run_shard(job, folder, ROOT, tmp_path, [(0, row)], limits, None, 0, 10, jobs)
    assert len(list((folder / 'private_outer').glob('environment.0*.json'))) == 2
    drifted_env = deepcopy(runtime_env)
    drifted_env['packages']['pypdf'] = '6.99.0'
    monkeypatch.setattr(runner, 'environment', lambda: deepcopy(drifted_env))
    with pytest.raises(ValueError, match='replay_environment_changed'):
        runner.run_shard(job, folder, ROOT, tmp_path, [], limits, None, 1, 10, jobs)
    tampered = json.loads((folder / 'locked_methodology.json').read_text())
    tampered['node_cap'] = 199
    (folder / 'locked_methodology.json').write_text(json.dumps(tampered))
    monkeypatch.setattr(runner, 'environment', lambda: deepcopy(runtime_env))
    with pytest.raises(ValueError, match='replay_methodology_changed'):
        runner.run_shard(job, folder, ROOT, tmp_path, [], limits, None, 2, 10, jobs)
    (folder / 'locked_methodology.json').unlink()
    with pytest.raises(ValueError, match='replay_methodology_missing'):
        runner.run_shard(job, folder, ROOT, tmp_path, [], limits, None, 3, 10, jobs)


def test_pre_spawn_worker_start_failure_continues_shard_while_post_spawn_uncertainty_halts(tmp_path, monkeypatch):
    from malpdf.extraction import diagnostic_replay_runner as runner
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    jobs, job, folder = operations(monkeypatch, tmp_path)
    lock = locked()
    monkeypatch.setattr(runner, 'verify_replay', lambda *args, **kwargs: lock)
    rows = [(0, {'pdf_sha256': lock['records'][0]['sha256'], 'pdf_relative_path': 'data/raw/cic_pdf/a.pdf'}),
            (10, {'pdf_sha256': lock['records'][10]['sha256'], 'pdf_relative_path': 'data/raw/cic_pdf/b.pdf'})]
    calls = []
    def extract_pre_spawn(path, **kwargs):
        digest = kwargs['expected_sha256']
        calls.append(digest)
        diagnostic = WorkerDiagnostics(digest, job['job_id']).data
        if len(calls) == 1:
            diagnostic.update(preserved_before_cleanup=True, cleanup_complete=None, cleanup_exit_code=None,
                worker_exit_code=None, elapsed_ms=1, last_phase='worker_start',
                exception_type='OSError', exception_errno=12)
            profile = {'status': 'worker_error', 'errors': ['worker_lifecycle_failed'],
                'diagnostic': diagnostic, 'worker_cleanup_complete': None, 'worker_exit_code': None}
        else:
            diagnostic.update(preserved_before_cleanup=True, cleanup_complete=True, cleanup_exit_code=0,
                worker_exit_code=0, elapsed_ms=2, last_phase='result_serialization')
            profile = {'status': 'complete', 'errors': [], 'diagnostic': diagnostic,
                'worker_cleanup_complete': True, 'worker_exit_code': 0}
        kwargs['profile_observer'](profile)
        return normalize_profile(profile, digest, 'deep-static')
    monkeypatch.setattr(runner, 'extract_pdf', extract_pre_spawn)
    limits = CodeInspectionLimits(wall_seconds=35, cpu_seconds=30)
    runner.run_shard(job, folder, ROOT, tmp_path, rows, limits, None, 0, 10, jobs)
    assert len(calls) == 2
    assert not (folder / 'pdf_halt.0.json').exists()
    first = json.loads((folder / 'private_cases/0000.json').read_text())
    assert first['classification']['observed_mechanism'] == 'allocation_failure'
    jobs2, job2, folder2 = operations(monkeypatch, tmp_path / 'second')
    monkeypatch.setattr(runner, 'verify_replay', lambda *args, **kwargs: lock)
    def extract_post_spawn(path, **kwargs):
        digest = kwargs['expected_sha256']
        diagnostic = WorkerDiagnostics(digest, job2['job_id']).data
        diagnostic.update(preserved_before_cleanup=True, cleanup_complete=False, cleanup_exit_code=None,
            worker_exit_code=None, elapsed_ms=5, last_phase='parse_pdf')
        profile = {'status': 'worker_error', 'errors': ['worker_lifecycle_failed'],
            'diagnostic': diagnostic, 'worker_cleanup_complete': False, 'worker_exit_code': None}
        kwargs['profile_observer'](profile)
        return normalize_profile(profile, digest, 'deep-static')
    monkeypatch.setattr(runner, 'extract_pdf', extract_post_spawn)
    runner.run_shard(job2, folder2, ROOT, tmp_path, rows, limits, None, 0, 10, jobs2)
    assert (folder2 / 'pdf_halt.0.json').is_file()
    assert not (folder2 / 'private_cases/0010.json').exists()


def test_safe_trace_accepts_zero_line_extension_frames_and_rejects_negative_lines():
    from malpdf.extraction.diagnostic_replay_results import safe_trace
    cleaned = safe_trace([{'file': '<frozen importlib._bootstrap>', 'function': '_call_with_frames_removed', 'line': 0}])
    assert cleaned == [{'file': 'external.py', 'function': '_call_with_frames_removed', 'line': 0}]
    with pytest.raises(ValueError, match='replay_trace_frame'):
        safe_trace([{'file': 'external.py', 'function': 'broken', 'line': -1}])


def test_outer_worker_exception_is_saved_before_process_exit(tmp_path, monkeypatch):
    jobs, job, folder = operations(monkeypatch, tmp_path)
    runner = importlib.import_module('lab_runner')
    def fail(*args, **kwargs):
        raise ValueError('PRIVATE_OUTER_MESSAGE')
    monkeypatch.setattr(runner, '_pdf_worker', fail)
    with pytest.raises(ValueError, match='PRIVATE_OUTER_MESSAGE'):
        runner.pdf_worker(job['job_id'], shard=0, count=10)
    record = json.loads((folder/'private_outer/exception.0.json').read_text())
    assert record['preserved_before_outer_exit'] is True
    assert record['exception_type'] == 'ValueError' and record['traceback']
    assert record['last_phase'] == 'fail'
    assert 'PRIVATE_OUTER_MESSAGE' not in json.dumps(record)


def test_outer_transport_keeps_pre_cleanup_exit_and_never_exports_raw_stderr(tmp_path, monkeypatch):
    from malpdf.extraction.diagnostic_replay_outer import outer_records
    jobs, job, folder = operations(monkeypatch, tmp_path)
    process = SimpleNamespace(poll=lambda: None)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stderr.write(b'PRIVATE_OUTER_STDERR' + b'x'*20000)
        stderr.flush()
        position = stderr.tell()
        assert jobs.replay_transport(job, folder, [process], [stdout, stderr], reason='timeout')
        assert stderr.tell() == position
        process.poll = lambda: -15
        assert jobs.replay_transport(job, folder, [process], [stdout, stderr])
        assert jobs.replay_cleanup(job, folder, [process])
    raw = json.loads((folder/'private_outer/transport.0.json').read_text())
    assert raw['exit_before_cleanup'] is None and len(raw['stderr']) == 16384
    exported = outer_records(job, folder, locked())
    assert exported['records'][0]['exit_before_cleanup'] is None
    assert exported['records'][0]['cleanup_exit_code'] == -15
    assert exported['records'][0]['supervisor_reason'] == 'timeout'
    assert 'PRIVATE_OUTER_STDERR' not in json.dumps(exported)
    assert exported['records'][1]['stderr_utf8_bytes'] is None


def test_failed_outer_workers_still_invoke_replay_analysis_before_raising(tmp_path, monkeypatch):
    jobs, job, folder = operations(monkeypatch, tmp_path)
    monkeypatch.setattr(jobs, 'config', lambda: {'python': 'unused-controlled-python'})
    monkeypatch.setattr(jobs.shutil, 'disk_usage', lambda *args: SimpleNamespace(free=10**12))
    monkeypatch.setattr(jobs.subprocess, 'Popen', lambda *args, **kwargs: SimpleNamespace(poll=lambda: 1, returncode=1))
    analyses = []
    monkeypatch.setattr(jobs, 'replay_analysis', lambda *args: analyses.append(True))
    with pytest.raises(ValueError, match='worker_failed'):
        jobs.pdf_task(job, folder)
    assert analyses == [True]
    assert (folder/'private_outer/transport.0.json').is_file()
    assert (folder/'private_outer/cleanup.json').is_file()


def test_transport_disk_failure_does_not_raise_before_cleanup(tmp_path, monkeypatch):
    jobs, job, folder = operations(monkeypatch, tmp_path)
    def full(*args):
        raise OSError(28, 'controlled disk full')
    monkeypatch.setattr(jobs, 'immutable', full)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        assert jobs.replay_transport(job, folder, [SimpleNamespace(poll=lambda: None)], [stdout, stderr]) is False
