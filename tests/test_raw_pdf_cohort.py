"""Offline static/cohort checks use local inert PDFs and synthetic feature tables."""

import csv
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pymupdf
import pytest

from malpdf.data.raw_cohort import RAW_FEATURES, read_acquired_inventory, isolated_features, locked_raw_split
from malpdf.data.manifest_validator import validate_locked_source_manifest
from malpdf.static.rit_reference import inspect_rit_reference_features
from malpdf.static.safety import StaticInspectionLimits


def benign_pdf(path):
    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((50, 50), "Synthetic benign text fixture " * 4)
    document.set_metadata({"title": "benign fixture"})
    document.save(path)
    document.close()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_isolated_parser_measures_full_features_and_fails_closed_on_bad_pdf(tmp_path):
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    good = raw / "benign.pdf"
    sha = benign_pdf(good)
    bad = raw / "malformed.pdf"
    bad.write_bytes(b"%PDF-1.4\n% inert malformed fixture\n")
    rows = pd.DataFrame([{"pdf_relative_path": str(p.relative_to(tmp_path)), "pdf_sha256": digest}
                         for p, digest in [(good, sha), (bad, hashlib.sha256(bad.read_bytes()).hexdigest())]])
    outcomes = dict(isolated_features(rows, tmp_path, workers=1, memory_bytes=4 * 1024**3))
    assert outcomes[0]["complete"] and set(outcomes[0]["features"]) == set(RAW_FEATURES)
    assert outcomes[0]["features"]["pages"] == 1
    assert outcomes[0]["features"]["ObfuscationCount"] == 0
    assert not outcomes[1]["complete"] and outcomes[1]["errors"]
    assert outcomes[1]["features"].get("pages") is None


def test_object_cap_stops_reference_before_page_text_processing(tmp_path):
    path = tmp_path / "benign.pdf"
    benign_pdf(path)
    data = path.read_bytes()
    outcome = inspect_rit_reference_features(data, len(data), StaticInspectionLimits(max_objects=1))
    assert not outcome.success and outcome.features["contains_text"] is None
    assert any(e.code == "reference_object_limit" and e.fatal for e in outcome.errors)


def test_group_split_preserves_mixed_labels_vectors_and_related_samples():
    rows = [{"sample_id": f"inert_{i}", **{f: float(i + j) for j, f in enumerate(RAW_FEATURES)}, "Label": i % 2} for i in range(100)]
    table = pd.DataFrame(rows)
    table.loc[1, list(RAW_FEATURES)] = table.loc[0, list(RAW_FEATURES)].to_numpy()
    source = pd.DataFrame({"sample_id": table.sample_id, "pdf_sha256": [f"hash{i}" for i in range(100)],
                           "related_group_id": ["related" if i in (2, 3, 4, 5) else f"single{i}" for i in range(100)]})
    manifest, evidence = locked_raw_split(table, source)
    assert len(manifest) == len(table) and evidence["zero_group_overlap"]
    assert evidence["mixed_label_groups"] >= 1
    assert manifest.iloc[[0, 1]].split.nunique() == 1
    assert manifest.iloc[[2, 3, 4, 5]].split.nunique() == 1
    pd.testing.assert_frame_equal(manifest, locked_raw_split(table, source)[0])


def test_raw_manifest_allows_explicit_unlabeled_cache_rows_without_relabeling(tmp_path):
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    path = raw / "benign.pdf"
    sha = benign_pdf(path)
    processed = tmp_path / "data/processed/raw_pdf_cohort/run_fixture"
    processed.mkdir(parents=True)
    manifest = processed / "source_pdf_manifest.csv"
    pd.DataFrame([{"sample_id": "public_pdf:" + sha, "Label": "", "pdf_relative_path": str(path.relative_to(tmp_path)), "pdf_sha256": sha}]).to_csv(manifest, index=False)
    report = tmp_path / "artifacts/raw_pdf_cohort/run_fixture/source_preparation_report.json"
    report.parent.mkdir(parents=True)
    lock = {"status": "completed", "cohort_type": "public_raw_pdf_v1", "cohort": {"path": str(processed.relative_to(tmp_path)), "manifest_path": str(manifest.relative_to(tmp_path)), "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "sample_count": 1, "labels": {"unlabeled": 1}}, "source_inventory": [{"path": str(path.relative_to(tmp_path)), "sha256": sha}]}
    report.write_text(json.dumps(lock))
    samples, provenance = validate_locked_source_manifest(tmp_path, manifest, report)
    assert samples[0].label is None and provenance["label_counts"]["unlabeled"] == 1
    manifest.write_text(manifest.read_text().replace("public_pdf:", "wrong:"))
    with pytest.raises(ValueError, match="checksum"):
        validate_locked_source_manifest(tmp_path, manifest, report)
