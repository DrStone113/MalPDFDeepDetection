import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import time

import pytest

from malpdf.static import profile_worker
from malpdf.static.code_inspector import CodeInspectionLimits


def diagnostic_child(connection, path, boundary, digest, limits, *args):
    from malpdf.static.worker_diagnostics import report_phase
    report_phase('parse_pdf')
    os.write(2, b'controlled diagnostic stderr\n')
    mode = Path(path).stem
    if mode == 'exception':
        raise ValueError('PRIVATE_DOCUMENT_CONTENT')
    if mode == 'memory':
        raise MemoryError('PRIVATE_MEMORY_CONTENT')
    if mode == 'stderr':
        os.write(2, b'x' * 100000)
        time.sleep(0.1)
    if mode == 'checkpoint':
        connection.send_bytes(json.dumps({'event': 'checkpoint', 'profile': {
            'status': 'partial', 'errors': [], 'static': None, 'code': None}}).encode())
        time.sleep(10)
    if mode == 'crash':
        time.sleep(0.1)
        os._exit(7)
    if mode == 'timeout':
        time.sleep(10)
    if mode == 'ipc':
        connection.send_bytes(b'invalid JSON')
    else:
        connection.send_bytes(json.dumps({'event': 'result', 'profile': {
            'status': 'complete', 'errors': [], 'static': None, 'code': None}}).encode())


def stop_test_worker(process):
    process.join(timeout=0.2)
    if process.is_alive():
        process.kill()
    process.join(timeout=2)


@pytest.mark.parametrize('mode', ['complete', 'exception', 'crash', 'timeout', 'ipc', 'memory', 'stderr', 'checkpoint'])
def test_real_spawn_lifecycle_preserves_diagnostic_before_cleanup(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(profile_worker, '_profile_child', diagnostic_child)
    monkeypatch.setattr(profile_worker, '_worker_count', lambda *args: 1)
    monkeypatch.setattr(profile_worker, '_stop_code_process', stop_test_worker)
    before = {child.pid for child in multiprocessing.active_children()}
    result = profile_worker.profile_pdf(tmp_path / f'{mode}.pdf', boundary=tmp_path, digest='a' * 64,
        run_id='diagnostic-test', include_v8=mode == 'checkpoint',
        limits=CodeInspectionLimits(wall_seconds=2, cpu_seconds=1))
    diagnostic = result['diagnostic']
    assert diagnostic['sample_id'] == 'a' * 64
    assert diagnostic['run_id'] == 'diagnostic-test'
    assert diagnostic['last_phase'] == 'parse_pdf'
    assert diagnostic['elapsed_ms'] >= 0
    assert diagnostic['preserved_before_cleanup'] is True
    assert diagnostic['stderr'].startswith('controlled diagnostic stderr')
    assert diagnostic['cleanup_exit_code'] == result.get('worker_exit_code'), json.dumps(result)
    assert result['worker_cleanup_complete'] is True
    assert {child.pid for child in multiprocessing.active_children()} == before
    if mode == 'exception':
        assert diagnostic['exception_type'] == 'ValueError'
        assert diagnostic['traceback']
        assert 'PRIVATE_DOCUMENT_CONTENT' not in json.dumps(diagnostic)
    if mode == 'crash':
        assert diagnostic['worker_exit_code'] == 7
        assert diagnostic['failure_kind'] == 'worker_crash'
        assert diagnostic['stderr_capture_complete'] is None
        assert diagnostic['stderr_truncated'] is None
    if mode == 'timeout':
        assert diagnostic['worker_exit_code'] is None
        assert diagnostic['timeout_reason'] == 'wall_timeout'
    if mode == 'ipc':
        assert diagnostic['failure_kind'] == 'ipc_serialization_error'
    if mode == 'memory':
        assert diagnostic['failure_kind'] == 'memory_error'
    if mode == 'stderr':
        assert len(diagnostic['stderr'].encode()) <= 16384
        assert diagnostic['stderr_truncated'] is True
    if mode == 'checkpoint':
        assert diagnostic['checkpoint_received'] is True
        assert diagnostic['checkpoint_status'] == 'partial'


def test_admission_exception_retains_type_trace_and_unknown_resources(tmp_path, monkeypatch):
    def refuse(*args):
        raise OSError(12, 'PRIVATE_MEMORY_MESSAGE')
    monkeypatch.setattr(profile_worker, '_worker_count', refuse)
    result = profile_worker.profile_pdf(tmp_path / 'unused.pdf', boundary=tmp_path, digest='b' * 64)
    diagnostic = result['diagnostic']
    assert result['errors'] == ['worker_admission_failed']
    assert diagnostic['exception_type'] == 'OSError'
    assert diagnostic['exception_errno'] == 12
    assert diagnostic['last_phase'] == 'worker_admission'
    assert diagnostic['peak_rss_bytes'] is None
    assert diagnostic['stderr'] is None
    assert diagnostic['worker_exit_code'] is None
    assert 'PRIVATE_MEMORY_MESSAGE' not in json.dumps(diagnostic)


def test_process_start_failure_preserves_origin_and_does_not_claim_cleanup(tmp_path, monkeypatch):
    context = multiprocessing.get_context('spawn')
    original = context.Process
    def process(*args, **kwargs):
        worker = original(*args, **kwargs)
        def fail():
            raise OSError(24, 'PRIVATE_START_MESSAGE')
        worker.start = fail
        return worker
    monkeypatch.setattr(context, 'Process', process)
    monkeypatch.setattr(profile_worker, '_worker_count', lambda *args: 1)
    result = profile_worker.profile_pdf(tmp_path / 'unused.pdf', boundary=tmp_path, digest='d' * 64)
    diagnostic = result['diagnostic']
    assert diagnostic['last_phase'] == 'worker_start'
    assert diagnostic['failure_kind'] == 'worker_start_error'
    assert diagnostic['exception_errno'] == 24
    assert diagnostic['preserved_before_cleanup'] is True
    assert result['worker_cleanup_complete'] is None
    assert 'PRIVATE_START_MESSAGE' not in json.dumps(diagnostic)


@pytest.mark.skipif(os.name != 'posix', reason='Path extraction is restricted to the Linux LAB')
def test_orchestrator_boundary_preserves_diagnostic_in_bundle(tmp_path, monkeypatch):
    from malpdf.extraction import orchestrator
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    fixture = Path(__file__).parent / 'fixtures/real_benign_document.pdf'
    data = fixture.read_bytes()
    def fail(*args, **kwargs):
        raise ValueError('PRIVATE_BOUNDARY_MESSAGE')
    monkeypatch.setattr(orchestrator, 'profile_pdf', fail)
    bundle = orchestrator.extract_pdf(fixture, run_id='boundary-test')
    diagnostic = bundle['coverage_report']['worker']['diagnostic']
    assert diagnostic['sample_id'] == hashlib.sha256(data).hexdigest()
    assert diagnostic['run_id'] == 'boundary-test'
    assert diagnostic['last_phase'] == 'profile_boundary'
    assert diagnostic['exception_type'] == 'ValueError'
    assert 'PRIVATE_BOUNDARY_MESSAGE' not in json.dumps(diagnostic)


def test_normalization_keeps_diagnostic_but_numeric_export_excludes_private_stderr():
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.extraction.numeric_export import project_numeric_bundle
    from malpdf.static.worker_diagnostics import WorkerDiagnostics
    diagnostic = WorkerDiagnostics('c' * 64, 'numeric-test')
    diagnostic.data['stderr'] = 'PRIVATE_STDERR'
    bundle = normalize_profile({'status': 'worker_error', 'errors': ['worker_exit'],
        'diagnostic': diagnostic.data}, 'c' * 64, 'deep-static')
    assert bundle['coverage_report']['worker']['diagnostic']['stderr'] == 'PRIVATE_STDERR'
    exported = project_numeric_bundle(bundle, 'c' * 64)
    assert 'PRIVATE_STDERR' not in json.dumps(exported)


@pytest.mark.skipif(os.name != 'posix', reason='Path extraction is restricted to the Linux LAB')
def test_real_benign_fixture_has_diagnostic_and_preserves_original_sha256(monkeypatch):
    from malpdf.extraction.orchestrator import extract_pdf
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    fixture = Path(__file__).parent / 'fixtures/real_benign_document.pdf'
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    bundle = extract_pdf(fixture, profile='fast-static', run_id='real-fixture-test')
    diagnostic = bundle['coverage_report']['worker']['diagnostic']
    assert diagnostic['run_id'] == 'real-fixture-test'
    assert diagnostic['sample_id'] == bundle['sample_sha256'] == digest
    assert diagnostic['exception_type'] is None
    assert bundle['coverage_report']['worker']['worker_cleanup_complete'] is True
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == digest
