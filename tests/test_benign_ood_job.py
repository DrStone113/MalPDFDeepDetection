import importlib
import json
from pathlib import Path

import pytest

from malpdf.extraction import benign_ood_job as cohort


def test_publisher_cohort_requires_offline_and_has_fixed_sample_count(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    jobs = importlib.import_module('lab_jobs')
    identifiers = ('a' * 40, 'b' * 64, 'c' * 64)
    with pytest.raises(ValueError, match='job_mismatch'):
        jobs.make_job(*identifiers, mode='host-only', kind=jobs.BENIGN_OOD_KIND)
    job = jobs.make_job(*identifiers, mode='offline', kind=jobs.BENIGN_OOD_KIND)
    assert job['limits']['samples'] == cohort.SAMPLES == 83
    assert job['limits']['file_max_bytes'] == cohort.MAX_FILE_BYTES
    from malpdf.extraction import benign_ood_expanded_job as expanded

    with pytest.raises(ValueError, match='job_mismatch'):
        jobs.make_job(*identifiers, mode='host-only', kind=jobs.BENIGN_OOD_EXPANDED_KIND)
    second = jobs.make_job(*identifiers, mode='offline', kind=jobs.BENIGN_OOD_EXPANDED_KIND)
    assert second['limits']['samples'] == expanded.SAMPLES == 379
    assert jobs.validate_job(job)['limits']['samples'] == 83

    from malpdf.extraction import benign_ood_diverse_job as diverse

    with pytest.raises(ValueError, match='job_mismatch'):
        jobs.make_job(*identifiers, mode='host-only', kind=jobs.BENIGN_OOD_DIVERSE_KIND)
    third = jobs.make_job(*identifiers, mode='offline', kind=jobs.BENIGN_OOD_DIVERSE_KIND)
    assert third['limits']['samples'] == diverse.SAMPLES == 477
    assert third['limits']['file_max_bytes'] == cohort.MAX_FILE_BYTES
    assert jobs.validate_job(third)['limits']['samples'] == 477
    assert sum(diverse.SOURCE_COUNTS.values()) == 477
    assert diverse.contract()['samples'] == 477

    from malpdf.extraction import benign_v32_cohort_job as v32

    with pytest.raises(ValueError, match='job_mismatch'):
        jobs.make_job(*identifiers, mode='host-only', kind=jobs.BENIGN_V32_COHORT_KIND)
    fourth = jobs.make_job(*identifiers, mode='offline', kind=jobs.BENIGN_V32_COHORT_KIND)
    assert fourth['limits']['samples'] == v32.SAMPLES == 974
    assert fourth['limits']['output_bytes'] == 1024**3
    assert fourth['limits']['file_max_bytes'] == cohort.MAX_FILE_BYTES
    assert jobs.validate_job(fourth)['limits']['samples'] == 974
    assert sum(v32.SOURCE_COUNTS.values()) == 974
    assert v32.contract()['samples'] == 974


def test_manifest_preflight_only_checks_metadata_and_rejects_size_changes(tmp_path, monkeypatch):
    directory = tmp_path.resolve() / cohort.RAW_ROOT
    directory.mkdir(parents=True)
    identity = 'irs-004'
    fixture = directory / (identity + '.pdf')
    fixture.write_bytes(b'X' * 80)
    row = {'id': identity, 'source': 'irs', 'bytes': 80, 'sha256': 'f' * 64}
    manifest = json.dumps({'entries': [row]}).encode()
    monkeypatch.setattr(cohort, 'SAMPLES', 1)
    monkeypatch.setattr(cohort, 'SOURCE_COUNTS', {'irs': 1})
    monkeypatch.setattr(cohort, 'TOTAL_BYTES', 80)
    monkeypatch.setattr(cohort, 'pinned', lambda *args: manifest)
    assert cohort.load_rows(tmp_path.resolve())[0]['pdf_sha256'] == 'f' * 64
    fixture.write_bytes(b'X' * 81)
    with pytest.raises(ValueError, match='manifest_unavailable'):
        cohort.load_rows(tmp_path.resolve())


def test_expanded_batch_path_rejects_parent_traversal(tmp_path, monkeypatch):
    directory = tmp_path.resolve() / cohort.RAW_ROOT
    directory.mkdir(parents=True)
    fixture = directory / 'batch-01' / 'nasa-019.pdf'
    fixture.parent.mkdir()
    fixture.write_bytes(b'X' * 80)
    row = {'id': 'nasa-019', 'source': 'nasa', 'batch': 'batch-01', 'bytes': 80, 'sha256': 'f' * 64}
    monkeypatch.setattr(cohort, 'pinned', lambda *args: json.dumps({'entries': [row]}).encode())
    def prepare():
        return cohort.load_manifest_rows(tmp_path.resolve(), cohort.RAW_ROOT, 'a' * 64, {'nasa': 1}, 80, batched=True)
    assert prepare()[0]['pdf_relative_path'].endswith('/batch-01/nasa-019.pdf')
    row['batch'] = '../outside'
    with pytest.raises(ValueError, match='manifest_unavailable'):
        prepare()


def test_partial_bundle_without_verified_identity_is_not_projected(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    from scripts.lab.export_expanded_benign_ood import bundle_identity_verified

    sha = 'a' * 64
    assert not bundle_identity_verified({'status': 'partial', 'sample_sha256': None}, sha)
    assert bundle_identity_verified({'status': 'partial', 'sample_sha256': sha}, sha)
    with pytest.raises(ValueError, match='identity_changed'):
        bundle_identity_verified({'status': 'partial', 'sample_sha256': 'b' * 64}, sha)
    with pytest.raises(ValueError, match='identity_changed'):
        bundle_identity_verified({'status': 'bounded_complete', 'sample_sha256': None}, sha)


def test_publisher_worker_honors_job_file_limit(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    import lab_jobs
    from lab_runner import pdf_inspection_limits

    kind = lab_jobs.BENIGN_OOD_EXPANDED_KIND
    assert pdf_inspection_limits({'kind': kind, 'limits': lab_jobs.policy(kind)}).max_file_bytes == 12 * 1024**2
    static = 'pdf-static'
    assert pdf_inspection_limits({'kind': static, 'limits': lab_jobs.policy(static)}).max_file_bytes == 10 * 1024**2


def test_oversized_publisher_bundle_records_limit_after_verified_cleanup(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    from lab_runner import publisher_bundle_budget
    from malpdf.extraction.normalize import normalize_profile
    from malpdf.extraction.quality_gate import evaluate_sample_quality_v2

    sha = 'a' * 64
    bundle = normalize_profile({'status': 'complete', 'worker_cleanup_complete': True,
                                'worker_exit_code': 0, 'peak_rss_bytes': 500}, sha, 'deep-static')
    oversized = b'x' * (1024 * 1024)
    bounded, payload = publisher_bundle_budget(bundle, oversized, sha, 65536)
    assert len(payload) < 65536
    assert bounded['sample_sha256'] == sha
    assert bounded['status'] == 'resource_limit'
    assert not evaluate_sample_quality_v2(bounded, sha)['gnn_message_passing_eligible']
    assert not any(record['kind'] == 'primary_checkpoint' for record in bounded['evidence_store']['records'])
    assert bounded['coverage_report']['worker']['peak_rss_bytes'] == 500
    assert 'bundle_size_limit' in bounded['coverage_report']['limitations']

    bundle['coverage_report']['worker']['worker_cleanup_complete'] = False
    assert publisher_bundle_budget(bundle, oversized, sha, 65536) == (bundle, oversized)


def test_admission_excludes_close_and_incomplete_rows_before_scoring():
    from scripts.lab.score_benign_ood import admit, interval_summary

    rows = [dict(sha256=sha, tlsh=mark, source='irs', id=sha) for sha, mark in (
        ('a', 'close'), ('b', 'distant'), ('c', 'distant'), ('d', None), ('e', 'distant'))]
    references = {'z': 'train'}
    result = admit(rows, references, references, {'z', 'e'},
                   lambda _, queries: [30 if mark == 'close' else 31 for mark in queries],
                   lambda hashes: [0] * len(hashes))
    assert result['a']['admission'] == 'near_duplicate'
    assert result['b']['representative'] and result['c']['cluster'] == 'b' and not result['c']['representative']
    assert result['d']['admission'] == 'candidate_fingerprint_unavailable'
    assert result['e']['admission'] == 'exact_duplicate'
    assert interval_summary(0, 0)['fpr'] is None
    assert interval_summary(0, 83)['one_sided_95_upper'] > 0.01


def test_publisher_bundle_limit_allows_16mib_and_progress_status_reads_it(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    import lab_jobs
    from lab_runner import publisher_bundle_budget
    from malpdf.extraction.normalize import normalize_profile

    for kind in lab_jobs.BENIGN_OOD_KINDS:
        assert lab_jobs.pdf_bundle_limit(kind) == 16 * 1024**2
    assert lab_jobs.pdf_bundle_limit(lab_jobs.BENIGN_V32_COHORT_KIND) == 16 * 1024**2
    assert lab_jobs.pdf_bundle_limit('pdf-static') == 8 * 1024**2

    limit = lab_jobs.pdf_bundle_limit(lab_jobs.BENIGN_V32_COHORT_KIND)
    sha = 'a' * 64
    bundle = normalize_profile({'status': 'complete', 'worker_cleanup_complete': True,
                                'worker_exit_code': 0, 'peak_rss_bytes': 500}, sha, 'deep-static')
    nine_mib = b'x' * (9 * 1024**2)
    assert publisher_bundle_budget(bundle, nine_mib, sha, limit) == (bundle, nine_mib)

    seventeen_mib = b'x' * (17 * 1024**2)
    bounded, payload = publisher_bundle_budget(bundle, seventeen_mib, sha, limit)
    assert len(payload) < limit
    assert bounded['status'] == 'resource_limit'
    assert 'bundle_size_limit' in bounded['coverage_report']['limitations']

    bundle_file = tmp_path / '0858.json'
    bundle_file.write_text(json.dumps({'status': 'bounded_complete', 'pad': 'x' * (9 * 1024**2)}), encoding='ascii')
    assert bundle_file.stat().st_size > 9 * 1024**2
    assert lab_jobs.pdf_bundle_progress_status(bundle_file) == 'bounded_complete'
    assert lab_jobs.pdf_bundle_progress_status(bundle_file, max_bytes=8 * 1024**2) == 'unreadable'


def test_pdf_worker_rlimit_fsize_covers_publisher_bundle_limit(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
    import lab_jobs
    import lab_runner

    for kind in lab_jobs.PDF_KINDS:
        assert lab_jobs.pdf_worker_fsize_limit(kind) >= lab_jobs.pdf_bundle_limit(kind)
    assert lab_jobs.pdf_worker_fsize_limit(lab_jobs.BENIGN_V32_COHORT_KIND) == 16 * 1024**2
    assert lab_jobs.pdf_worker_fsize_limit(lab_jobs.HOLDOUT_TLSH_KIND) == 16 * 1024**2
    assert lab_jobs.pdf_worker_fsize_limit('pdf-static') == 8 * 1024**2

    recorded = {}
    fake_resource = SimpleNamespace(
        RLIMIT_CORE='core',
        RLIMIT_CPU='cpu',
        RLIMIT_AS='as',
        RLIMIT_FSIZE='fsize',
        RLIMIT_NOFILE='nofile',
        RLIMIT_NPROC='nproc',
        setrlimit=lambda name, bounds: recorded.__setitem__(name, bounds),
    )
    monkeypatch.setitem(sys.modules, 'resource', fake_resource)

    lab_runner.worker_limits(
        prepare=False,
        wall_seconds=21600,
        fsize_bytes=lab_jobs.pdf_worker_fsize_limit(lab_jobs.BENIGN_V32_COHORT_KIND),
    )
    assert recorded['fsize'] == (16 * 1024**2, 16 * 1024**2)

    lab_runner.worker_limits(
        prepare=True,
        wall_seconds=21600,
        fsize_bytes=lab_jobs.pdf_worker_fsize_limit(lab_jobs.BENIGN_V32_COHORT_KIND),
    )
    assert recorded['fsize'] == (32 * 1024**2, 32 * 1024**2)

    bundles = tmp_path / 'private_bundles'
    bundles.mkdir()
    payload = {'status': 'bounded_complete', 'feature_store': {'pad': 'x' * (9 * 1024**2)}}
    (bundles / '0858.json').write_text(json.dumps(payload), encoding='ascii')
    v32_limit = lab_jobs.pdf_bundle_limit(lab_jobs.BENIGN_V32_COHORT_KIND) + 1024
    assert lab_runner.bundle_view(tmp_path, 858, v32_limit)[0] == 'bounded_complete'
    with pytest.raises(ValueError, match='Unexpected input type/size'):
        lab_runner.bundle_view(tmp_path, 858)
