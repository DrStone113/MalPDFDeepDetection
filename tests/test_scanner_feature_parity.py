from types import SimpleNamespace

import numpy as np

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.scanner import ingestion


def test_completed_scanner_ingestion_features_do_not_depend_on_elapsed_time(monkeypatch):
    scanner = ingestion.InstantPDFIngestion(as_numpy=True)
    pdf = load_real_benign_bytes()

    def ingest_with_reported_duration(seconds):
        readings = iter((100.0, 100.0 + seconds))
        monkeypatch.setattr(ingestion, "time", SimpleNamespace(perf_counter=lambda: next(readings)), raising=False)
        return scanner.ingest(pdf)

    fast = ingest_with_reported_duration(0.1)
    slow = ingest_with_reported_duration(35.0)
    position = fast["feature_names"].index("evasive_timeout_anomaly")
    assert slow["raw_feature_vec"][position] == fast["raw_feature_vec"][position] == 0.0
    assert fast["prediction_blockers"] == slow["prediction_blockers"] == []
    np.testing.assert_array_equal(slow["tab_features"], fast["tab_features"])


def test_lab_vector_keeps_missing_derived_inputs_as_unknown():
    from scripts.lab.scanner_feature_audit import lab_vector

    features = {"canonical_stream": {"value": 2, "observation_status": "observed"}}
    report = lab_vector(features, ["Stream", "density_stream_ratio"])
    assert report["Stream"]["value"] == 2
    assert report["density_stream_ratio"]["value"] is None


def test_lab_audit_uses_coalesced_checkpoints(monkeypatch):
    from malpdf import extraction
    from scripts.lab.scanner_feature_audit import DEFAULT_FIXTURE, DEFAULT_SCALER, FIXTURE_HASH, measure

    def extract(fixture, *, expected_sha256, coalesce_checkpoints=False):
        assert fixture == DEFAULT_FIXTURE
        assert expected_sha256 == FIXTURE_HASH
        assert coalesce_checkpoints is True
        return {
            "sample_sha256": FIXTURE_HASH,
            "status": "observed",
            "feature_store": {"records": []},
            "coverage_report": {
                "worker": {"status": "complete", "worker_exit_code": 0, "last_stage": "raw_scan",
                           "worker_seconds": 1.2, "worker_cleanup_complete": True},
                "backends": {"byte_images": {"observation_status": "partial"}},
            },
        }

    monkeypatch.setattr(extraction, "extract_pdf", extract)

    report = measure("lab", DEFAULT_FIXTURE, DEFAULT_SCALER)

    assert report["worker_coverage"]["checkpoint_coalescing"] is True
    assert report["worker_coverage"]["worker_cleanup_complete"] is True


def test_comparison_preserves_interrupted_lab_worker_coverage():
    from scripts.lab.scanner_feature_audit import compare

    identity = {"fixture_sha256": "fixture", "scaler_sha256": "scaler", "feature_order": ["encoded_ratio"]}
    coverage = {
        "worker_status": "resource_limit_or_signal",
        "worker_exit_code": -9,
        "last_worker_stage": "parse_pdf",
        "byte_image_status": "not_run",
    }
    lab = dict(identity, measurement="lab", features={"encoded_ratio": {"value": None, "sources": ["encoded_ratio"]}},
               extraction_status="bounded_complete", worker_coverage=coverage)
    scanner = dict(identity, measurement="scanner", features={"encoded_ratio": {"value": 1.0}},
                   prediction_blocker_count=0)

    report = compare(lab, scanner)

    assert report["lab_extraction_status"] == "bounded_complete"
    assert report["lab_worker_coverage"] == coverage
    assert report["columns"][0]["comparison"] == "unavailable"


def test_ember_metadata_collapses_equal_rows_and_rejects_conflicting_labels():
    import pytest

    from scripts.lab.audit_ember_pdf_candidates import deduplicate_metadata

    first = {"sha256": "1" * 64, "label": 0, "week_id": 52}
    assert deduplicate_metadata([first, dict(first)]) == [first]
    conflicting = dict(first, label=1)
    with pytest.raises(ValueError, match="conflicting_EMBER"):
        deduplicate_metadata([first, conflicting])
