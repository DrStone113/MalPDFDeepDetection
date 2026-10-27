"""Offline Markov/cache tests using synthetic bytes and local fixture manifests."""

import csv
import hashlib
import io
import json
from pathlib import Path
import runpy

import numpy as np
import pytest

from malpdf.data.manifest_validator import validate_locked_source_manifest
from malpdf.data.markov_preparation import build_markov_cache
from malpdf.static import cache_manager
from malpdf.static.markov import byte_transition_matrix
from malpdf.static.safety import read_bounded_bytes


def digest(content):
    return hashlib.sha256(content).hexdigest()


def npy_bytes(array):
    output = io.BytesIO()
    np.save(output, array, allow_pickle=True)
    return output.getvalue()


@pytest.fixture
def locked_sources(tmp_path):
    root = tmp_path
    raw = root / "data/raw/cve_t4pdf"
    raw.mkdir(parents=True)
    prepared = root / "data/processed/source_preparation/run_fixture/cve_t4pdf"
    prepared.mkdir(parents=True)
    rows, inventory = [], []
    for index in range(2):
        data = "%PDF-1.4\n% synthetic benign fixture {}\n%%EOF\n".format(index).encode()
        path = raw / f"synthetic_{index}.pdf"
        path.write_bytes(data)
        copied = prepared / path.name
        copied.write_bytes(data)
        rows.append({"sample_id": f"cve_t4pdf:{path.name}", "Label": "1", "pdf_relative_path": copied.relative_to(root).as_posix(), "pdf_sha256": digest(data), "label_source": "user_requested_malicious"})
        inventory.append({"path": path.relative_to(root).as_posix(), "sha256": digest(data)})
    manifest = prepared / "source_pdf_manifest.csv"
    with manifest.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report = root / "artifacts/source_preparation/run_fixture/preparation_report.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"status": "completed", "source_inventory": inventory, "datasets": {"cve": {"manifest_path": manifest.relative_to(root).as_posix(), "manifest_sha256": digest(manifest.read_bytes()), "path": prepared.relative_to(root).as_posix(), "sample_count": 2, "labels": {"malicious": 2}}}}))
    log = root / "reports/research_log.md"
    log.parent.mkdir(parents=True)
    log.write_text("# Research log\nHistorical entry.\n")
    old = root / "reports/experiments/selective_ensemble/old_report.json"
    old.parent.mkdir(parents=True)
    old.write_text('{"historical": true}\n')
    (root / "data/processed/rit-pdfmal-2026_split_manifest.csv").write_bytes(b"existing RIT split must survive\n")
    return root, manifest, report, rows


def rewrite_locked_manifest(manifest, report, rows):
    with manifest.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    data = json.loads(report.read_text())
    data["datasets"]["cve"]["manifest_sha256"] = digest(manifest.read_bytes())
    report.write_text(json.dumps(data))


def test_markov_direction_counts_normalization_and_unseen_rows():
    matrix = byte_transition_matrix(bytes([0, 1, 0, 2, 0, 1]))
    assert matrix.shape == (256, 256) and matrix.dtype == np.float32
    assert matrix[0, 1] == np.float32(2 / 3)
    assert matrix[0, 2] == np.float32(1 / 3)
    assert matrix[1, 0] == matrix[2, 0] == 1
    assert np.count_nonzero(matrix) == 4
    assert not matrix[255].any()
    assert np.allclose(matrix.sum(axis=1)[:3], 1)
    assert np.array_equal(matrix, byte_transition_matrix(bytes([0, 1, 0, 2, 0, 1])))


def test_spawn_parallel_cache_is_equivalent_and_keeps_locked_sources(locked_sources, monkeypatch):
    from malpdf.data import markov_preparation
    root, manifest, report, _ = locked_sources
    monkeypatch.setattr(markov_preparation, 'effective_cpu_count', lambda: 2)
    before_manifest = manifest.read_bytes()
    outcome = build_markov_cache(root, manifest, report, run_id='parallel', workers='auto')
    assert outcome['workers'] == 2 and outcome['created'] == 2
    sources, _ = validate_locked_source_manifest(root, manifest, report)
    for source in sources:
        cache = root / 'data/processed/markov_cache' / (source.pdf_sha256 + '.npy')
        with source.raw_path.open('rb') as handle:
            expected = byte_transition_matrix(handle.read())
        assert np.array_equal(np.load(cache, allow_pickle=False), expected)
    assert manifest.read_bytes() == before_manifest
    assert 'cache preparation / completed' in (root / 'reports/research_log.md').read_text()


@pytest.mark.parametrize('workers', [0, -1, True, 'unbounded', 3])
def test_worker_budget_is_rejected_before_outputs(locked_sources, monkeypatch, workers):
    from malpdf.data import markov_preparation
    root, manifest, report, _ = locked_sources
    monkeypatch.setattr(markov_preparation, 'effective_cpu_count', lambda: 2)
    with pytest.raises(ValueError, match='workers'):
        build_markov_cache(root, manifest, report, run_id='bad_workers', workers=workers)
    assert not (root / 'reports/experiments/markov_cache/bad_workers').exists()


def test_parallel_duplicate_hash_has_one_cache_writer(locked_sources, monkeypatch):
    from malpdf.data import markov_preparation
    root, manifest, report, rows = locked_sources
    monkeypatch.setattr(markov_preparation, 'effective_cpu_count', lambda: 2)
    rows.append({**rows[0], 'sample_id': 'synthetic_alias'})
    rewrite_locked_manifest(manifest, report, rows)
    metadata = json.loads(report.read_text())
    metadata['datasets']['cve']['sample_count'] = 3
    metadata['datasets']['cve']['labels']['malicious'] = 3
    report.write_text(json.dumps(metadata))
    result = build_markov_cache(root, manifest, report, run_id='duplicate_parallel', workers=2)
    assert result['sample_count'] == 3 and result['created'] == 2 and result['reused'] == 1
    assert len(list((root / 'data/processed/markov_cache').glob('*.npy'))) == 2


def test_high_byte_indices_do_not_overflow():
    matrix = byte_transition_matrix(bytes([255, 255, 0, 255]))
    assert matrix[255, 255] == matrix[255, 0] == 0.5
    assert matrix[0, 255] == 1 and np.count_nonzero(matrix) == 3


@pytest.mark.parametrize("data", [b"", b"x", "not bytes"])
def test_no_transition_inputs_fail_closed(data):
    with pytest.raises(ValueError, match="At least two bytes"):
        byte_transition_matrix(data)


def test_manifest_resolves_raw_bytes_without_changing_label_provenance(locked_sources):
    root, manifest, report, rows = locked_sources
    samples, provenance = validate_locked_source_manifest(root, manifest, report)
    assert len(samples) == 2 and provenance["raw_checksum_match_fraction"] == 1.0
    assert all(sample.raw_path.is_relative_to(root / "data/raw") for sample in samples)
    assert all(sample.label == 1 and sample.label_source == "user_requested_malicious" for sample in samples)
    assert {sample.pdf_sha256 for sample in samples} == {row["pdf_sha256"] for row in rows}


@pytest.mark.parametrize("case", ["duplicate_id", "bad_label", "bad_sha", "traversal", "missing_column", "bad_split"])
def test_invalid_locked_manifest_rows_are_rejected(locked_sources, case):
    root, manifest, report, rows = locked_sources
    if case == "duplicate_id":
        rows[1]["sample_id"] = rows[0]["sample_id"]
    elif case == "bad_label":
        rows[0]["Label"] = "Malicious"
    elif case == "bad_sha":
        rows[0]["pdf_sha256"] = "../escape"
    elif case == "traversal":
        rows[0]["pdf_relative_path"] = "data/processed/../../outside.pdf"
    elif case == "bad_split":
        for row in rows:
            row["split"] = "unknown"
    else:
        for row in rows:
            del row["Label"]
    rewrite_locked_manifest(manifest, report, rows)
    with pytest.raises(ValueError):
        validate_locked_source_manifest(root, manifest, report)


def test_same_pdf_cannot_cross_partitions(locked_sources):
    root, manifest, report, rows = locked_sources
    rows[0]["split"] = "train"
    rows[1] = {**rows[0], "sample_id": "distinct_id", "split": "test"}
    rewrite_locked_manifest(manifest, report, rows)
    with pytest.raises(ValueError, match="crosses partitions"):
        validate_locked_source_manifest(root, manifest, report)


def test_changed_manifest_is_not_a_new_implicit_lock(locked_sources):
    root, manifest, report, _ = locked_sources
    with manifest.open("ab") as output:
        output.write(b"\n")
    with pytest.raises(ValueError, match="Manifest checksum"):
        validate_locked_source_manifest(root, manifest, report)


@pytest.mark.parametrize("case", ["report_type", "cohort_type", "count_type", "inventory_type"])
def test_malformed_provenance_objects_are_rejected(locked_sources, case):
    root, manifest, report, _ = locked_sources
    data = json.loads(report.read_text())
    if case == "report_type":
        data = []
    elif case == "cohort_type":
        data["datasets"]["cve"] = []
    elif case == "count_type":
        data["datasets"]["cve"]["sample_count"] = True
    else:
        data["source_inventory"] = ["not an inventory object"]
    report.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        validate_locked_source_manifest(root, manifest, report)


def test_all_sources_are_verified_before_any_cache_is_written(locked_sources):
    root, manifest, report, _ = locked_sources
    source = root / "data/raw/cve_t4pdf/synthetic_1.pdf"
    source.write_bytes(b"%PDF-1.4\n% changed synthetic bytes\n")
    with pytest.raises(ValueError, match="Raw PDF checksum"):
        build_markov_cache(root, manifest, report, run_id="failed_source")
    assert not (root / "data/processed/markov_cache").exists()
    summary = json.loads((root / "reports/experiments/markov_cache/failed_source/run_summary.json").read_text())
    assert summary["status"] == "failed" and summary["created"] == 0
    assert "cache preparation / failed" in (root / "reports/research_log.md").read_text()


def test_cache_hit_avoids_recomputation_but_still_checks_source_bytes(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    raw.mkdir()
    source = raw / "synthetic.pdf"
    data = b"%PDF-1.4\n% inert synthetic fixture\n%%EOF\n"
    source.write_bytes(data)
    kwargs = {"raw_boundary": raw, "cache_directory": tmp_path / "cache"}
    result = cache_manager.cache_markov_pdf(source, digest(data), **kwargs)
    content = result["path"].read_bytes()
    metadata = result["metadata_path"].read_bytes()
    assert result["path"].name == digest(data) + ".npy"
    assert np.array_equal(cache_manager.load_markov_npy(content), byte_transition_matrix(data))
    def unexpected_recompute(_):
        raise AssertionError("Cache hit recomputed its matrix")
    monkeypatch.setattr(cache_manager, "byte_transition_matrix", unexpected_recompute)
    assert cache_manager.cache_markov_pdf(source, digest(data), **kwargs)["status"] == "reused"
    assert result["path"].read_bytes() == content and result["metadata_path"].read_bytes() == metadata
    source.write_bytes(data + b"changed")
    with pytest.raises(ValueError, match="locked PDF checksum"):
        cache_manager.cache_markov_pdf(source, digest(data), **kwargs)


@pytest.mark.parametrize("case", ["npy_corruption", "metadata_corruption", "metadata_type", "missing_metadata"])
def test_corrupt_caches_are_never_repaired_or_overwritten(tmp_path, case):
    source = tmp_path / "fixture.pdf"
    source.write_bytes(b"%PDF-1.4\n% synthetic fixture\n%%EOF\n")
    kwargs = {"raw_boundary": tmp_path, "cache_directory": tmp_path / "cache"}
    sha = digest(source.read_bytes())
    result = cache_manager.cache_markov_pdf(source, sha, **kwargs)
    if case == "npy_corruption":
        result["path"].write_bytes(b"not a numpy file")
    elif case == "metadata_corruption":
        metadata = json.loads(result["metadata_path"].read_text())
        metadata["algorithm"] = "different algorithm"
        result["metadata_path"].write_text(json.dumps(metadata))
    elif case == "metadata_type":
        result["metadata_path"].write_text("[]")
    else:
        result["metadata_path"].unlink()
    before = result["path"].read_bytes()
    with pytest.raises((ValueError, FileNotFoundError)):
        cache_manager.cache_markov_pdf(source, sha, **kwargs)
    assert result["path"].read_bytes() == before


@pytest.mark.parametrize("case", ["object", "shape", "dtype", "nan", "unnormalized", "trailing_bytes"])
def test_unsafe_or_invalid_numpy_arrays_are_rejected(case):
    matrix = np.zeros((256, 256), dtype=np.float32)
    if case == "object":
        matrix = matrix.astype(object)
    elif case == "shape":
        matrix = matrix[:1]
    elif case == "dtype":
        matrix = matrix.astype(np.float64)
    elif case == "nan":
        matrix[0, 0] = np.nan
    elif case == "unnormalized":
        matrix[0, 0] = 0.5
    content = npy_bytes(matrix)
    if case == "trailing_bytes":
        content += b"unexpected"
    with pytest.raises(ValueError):
        cache_manager.load_markov_npy(content)


def test_forged_large_numpy_header_is_rejected_before_array_allocation(monkeypatch):
    content = io.BytesIO()
    np.lib.format.write_array_header_1_0(content, {"descr": "<f4", "fortran_order": False, "shape": (10**9, 10**9)})
    def forbidden_load(*args, **kwargs):
        raise AssertionError("Unvalidated header reached numpy.load")
    monkeypatch.setattr(np, "load", forbidden_load)
    with pytest.raises(ValueError, match="256, 256"):
        cache_manager.load_markov_npy(content.getvalue())


def test_bounded_reader_rejects_oversize_escapes_and_symlinks(tmp_path):
    boundary = tmp_path / "allowed"
    boundary.mkdir()
    path = boundary / "fixture.pdf"
    path.write_bytes(b"synthetic benign bytes")
    with pytest.raises(ValueError, match="byte cap"):
        read_bounded_bytes(path, boundary=boundary, max_bytes=2)
    with pytest.raises(ValueError, match="escapes"):
        read_bounded_bytes(tmp_path / "outside", boundary=boundary, max_bytes=100)
    link = boundary / "link.pdf"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="Symbolic links"):
        read_bounded_bytes(link, boundary=boundary, max_bytes=100)


def test_run_evidence_and_log_are_immutable_and_existing_cache_can_be_reused(locked_sources):
    root, manifest, report, _ = locked_sources
    preserved = {path: path.read_bytes() for boundary in (root / "data/raw", root / "data/processed", root / "artifacts/source_preparation", root / "reports/experiments") for path in boundary.rglob("*") if path.is_file()}
    log_before = (root / "reports/research_log.md").read_bytes()
    first = build_markov_cache(root, manifest, report, run_id="first")
    assert first["status"] == "completed" and first["created"] == 2
    assert all(path.read_bytes() == before for path, before in preserved.items())
    directory = root / "reports/experiments/markov_cache/first"
    assert all((directory / name).is_file() for name in ("locked_methodology.json", "model_comparison.csv", "environment_metadata.json", "source_provenance.json"))
    first_files = {path: path.read_bytes() for path in directory.iterdir()}
    caches = {path: path.read_bytes() for path in (root / "data/processed/markov_cache").iterdir()}
    second = build_markov_cache(root, manifest, report, run_id="second")
    assert second["created"] == 0 and second["reused"] == 2
    assert all(path.read_bytes() == before for path, before in {**first_files, **caches}.items())
    assert (root / "reports/research_log.md").read_bytes().startswith(log_before)
    with pytest.raises(ValueError, match="Run directory exists"):
        build_markov_cache(root, manifest, report, run_id="first")


def test_interrupted_run_preserves_evidence_and_is_logged(locked_sources, monkeypatch):
    root, manifest, report, _ = locked_sources
    from malpdf.data import markov_preparation
    def interruption(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(markov_preparation, "cache_markov_pdf", interruption)
    with pytest.raises(KeyboardInterrupt):
        build_markov_cache(root, manifest, report, run_id="interrupted")
    summary = json.loads((root / "reports/experiments/markov_cache/interrupted/run_summary.json").read_text())
    assert summary["status"] == "interrupted"
    assert "cache preparation / interrupted" in (root / "reports/research_log.md").read_text()


def test_cli_builds_from_explicit_fixture_config(locked_sources, monkeypatch, capsys):
    root, manifest, report, _ = locked_sources
    config = root / "markov.yaml"
    config.write_text(f"seed: 42\nmanifest: {manifest.relative_to(root)}\npreparation_report: {report.relative_to(root)}\nlimits:\n  max_pdf_bytes: 10485760\n  max_metadata_bytes: 2097152\n  max_samples: 100000\n")
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/02_build_markov_cache.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    assert main(["--config", str(config), "--run-id", "cli_fixture"]) == 0
    stdout = capsys.readouterr().out
    assert "2 PDFs; 2 caches created" in stdout and "<pdf_sha256>.npy" in stdout


@pytest.mark.parametrize("options", [{"seed": 43}, {"max_pdf_bytes": True}, {"run_id": "../escape"}])
def test_invalid_configuration_is_rejected_before_outputs(locked_sources, options):
    root, manifest, report, _ = locked_sources
    with pytest.raises(ValueError):
        build_markov_cache(root, manifest, report, **options)
    assert not (root / "reports/experiments/markov_cache").exists()
