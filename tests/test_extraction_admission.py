"""Platform refusal before input access, with mocked workers and inert fixtures."""

from pathlib import Path
import subprocess
import sys

import pytest

from malpdf.extraction import batch, lab, orchestrator
from malpdf.static.code_inspector import CodeInspectionLimits, VMInspectionLimits


def denied(*args, **kwargs):
    raise AssertionError('Admission must precede filesystem access and parser startup')


@pytest.mark.parametrize('system', ['Windows', 'Darwin'])
@pytest.mark.parametrize('attestation', ['0', '1'])
def test_unsupported_platform_refuses_path_api_before_input_access(monkeypatch, system, attestation):
    monkeypatch.setattr(lab.platform, 'system', lambda: system)
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', attestation)
    monkeypatch.setattr(Path, 'resolve', denied)
    monkeypatch.setattr(orchestrator, 'read_bounded_bytes', denied)
    monkeypatch.setattr(orchestrator, 'profile_pdf', denied)
    with pytest.raises(PermissionError, match='approved Linux LAB'):
        orchestrator.extract_pdf('not-read.pdf')
    with pytest.raises(PermissionError, match='approved Linux LAB'):
        lab.require_lab_isolation()


def test_windows_batch_refuses_before_consuming_paths_or_loading_catalog(monkeypatch, tmp_path):
    monkeypatch.setattr(lab.platform, 'system', lambda: 'Windows')
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    def paths():
        denied()
        yield Path('not-read.pdf')
    monkeypatch.setattr(batch, 'ThreadPoolExecutor', denied)
    with pytest.raises(PermissionError, match='approved Linux LAB'):
        list(batch.extract_pdfs(paths(), boundary=tmp_path, arlington_lock='not-read.json'))


@pytest.mark.parametrize('suffix', ['data/raw/fixture.pdf', 'DATA/RAW/fixture.pdf', 'Data/External/fixture.pdf'])
def test_corpus_gate_is_case_insensitive_and_still_requires_attestation(monkeypatch, tmp_path, suffix):
    monkeypatch.setattr(lab.platform, 'system', lambda: 'Linux')
    monkeypatch.delenv('MALPDF_LAB_ISOLATED', raising=False)
    with pytest.raises(PermissionError, match='MALPDF_LAB_ISOLATED'):
        lab.require_live_path_isolation(tmp_path / suffix)


def test_linux_api_defaults_to_finite_limits_without_importing_worker(monkeypatch, tmp_path):
    previous_worker = sys.modules.get('malpdf.static.profile_worker')
    monkeypatch.setattr(lab.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(orchestrator, 'read_bounded_bytes', lambda *args, **kwargs: b'inert synthetic bytes')
    captured = []
    def profile(*args, **kwargs):
        captured.append(kwargs['limits'])
        return {'status': 'complete', 'errors': []}
    monkeypatch.setattr(orchestrator, 'profile_pdf', profile)
    result = orchestrator.extract_pdf(tmp_path / 'fixture.pdf')
    assert type(captured[0]) is CodeInspectionLimits
    assert captured[0].wall_seconds == 8 and captured[0].cpu_seconds == 4
    assert captured[0].memory_bytes == 1024**3
    assert result['coverage_report']['provenance']['execution_mode'] == 'bounded'
    assert sys.modules.get('malpdf.static.profile_worker') is previous_worker


def test_linux_batch_defaults_to_one_bounded_worker_and_preserves_failure_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(lab.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(batch, 'available_cpus', lambda: 32)
    captured = []
    def extract(*args, **kwargs):
        captured.append(kwargs)
        raise ValueError('inert failure')
    monkeypatch.setattr(batch, 'extract_pdf', extract)
    executor = batch.ThreadPoolExecutor
    counts = []
    def pool(**kwargs):
        counts.append(kwargs['max_workers'])
        return executor(**kwargs)
    monkeypatch.setattr(batch, 'ThreadPoolExecutor', pool)
    result = dict(batch.extract_pdfs([tmp_path / 'not-read.pdf'], boundary=tmp_path))
    assert counts == [1] and type(captured[0]['limits']) is CodeInspectionLimits
    assert result[0]['coverage_report']['provenance']['execution_mode'] == 'bounded'
    assert result[0]['sample_sha256'] is None
    result = dict(batch.extract_pdfs([tmp_path / 'not-read.pdf'], boundary=tmp_path, limits=VMInspectionLimits()))
    assert result[0]['coverage_report']['provenance']['execution_mode'] == 'vm'


def test_cli_defaults_to_bounded_extraction():
    from malpdf.cli import build_parser
    assert build_parser().parse_args(['extract', 'not-read.pdf']).execution_mode == 'bounded'


@pytest.mark.skipif(sys.platform != 'win32', reason='Exercise the actual Windows platform refusal')
def test_windows_extract_cli_refuses_without_reading_input_or_writing_output(monkeypatch, capsys):
    from malpdf.cli import main
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    monkeypatch.setattr(orchestrator, 'read_bounded_bytes', denied)
    monkeypatch.setattr(orchestrator, 'write_bundle', denied)
    assert main(['extract', 'not-read.pdf']) == 2
    assert 'approved Linux LAB' in capsys.readouterr().out


@pytest.mark.skipif(sys.platform != 'win32', reason='Exercise the actual Windows platform refusal')
@pytest.mark.parametrize('action', ['vm', 'run'])
def test_windows_job_script_refuses_before_loading_linux_modules(monkeypatch, action):
    monkeypatch.setenv('MALPDF_LAB_ISOLATED', '1')
    script = Path(__file__).resolve().parents[1] / 'scripts/22_extract_pdf.py'
    result = subprocess.run([sys.executable, '-B', str(script), action, '--lab-isolated'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    assert result.returncode == 2
    assert result.stdout == b''
    assert b'approved Linux LAB' in result.stderr
    assert b'Traceback' not in result.stderr and b'resource' not in result.stderr
