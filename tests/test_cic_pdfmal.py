"""Synthetic, non-malware tests for the CIC tabular audit utilities."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from malpdf.data.cic_pdfmal import (
    CICDatasetError,
    EXPECTED_FILENAME,
    discover_cic_dataset,
    inspect_cic_pdfmal,
    load_cic_pdfmal,
    propose_canonical_label_mapping,
    validate_cic_pdfmal,
    write_cic_audit_outputs,
)
from malpdf.data.rit_pdfmal import sha256_file


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "FileName": ["a" * 64, "b" * 64, "c" * 64, "d" * 64],
            "PdfSize": [8.0, -1.0, 9.0, 8.0],
            "Images": pd.Categorical(["0", "1", "1(1)", "0"]),
            "Text": pd.Categorical(["No", "Yes", "unclear", "-1"]),
            "Header": pd.Categorical(["\t%PDF-1.7", "\t%PDF-1.4", "", "\ta"]),
            "Class": pd.Categorical(["Benign", "Malicious", "Malicious", "Benign"]),
        }
    )


def test_discovery_prefers_expected_filename_and_reports_ambiguous_alternatives(tmp_path):
    expected = tmp_path / EXPECTED_FILENAME
    expected.write_bytes(b"synthetic")
    (tmp_path / "other.csv").write_text("x\n1\n", encoding="utf-8")
    discovered = discover_cic_dataset(tmp_path)
    assert discovered.selected_path == expected
    assert "expected" in discovered.selection_reason

    expected.unlink()
    (tmp_path / "another.parquet").write_bytes(b"synthetic")
    with pytest.raises(CICDatasetError, match="Multiple CIC"):
        discover_cic_dataset(tmp_path)


def test_csv_loading_preserves_raw_file_and_schema(tmp_path):
    path = tmp_path / "fixture.csv"
    _frame().to_csv(path, index=False)
    before = sha256_file(path)
    loaded = load_cic_pdfmal(path)
    assert list(loaded.columns) == list(_frame().columns)
    assert loaded.loc[2, "Images"] == "1(1)"
    assert sha256_file(path) == before


def test_parquet_loading_is_supported_without_modifying_source(tmp_path):
    path = tmp_path / EXPECTED_FILENAME
    _frame().to_parquet(path, index=False)
    before = sha256_file(path)
    loaded = load_cic_pdfmal(path)
    assert loaded.shape == (4, 6)
    assert str(loaded["Class"].dtype) == "category"
    assert sha256_file(path) == before


def test_target_detection_label_proposal_and_official_count_discrepancy_are_explicit():
    report = validate_cic_pdfmal(_frame())
    assert report["target"]["candidate_column"] == "Class"
    assert report["target"]["proposed_label_mapping"]["raw_to_canonical_mapping"] == {"Benign": 0, "Malicious": 1}
    assert report["target"]["proposed_label_mapping"]["is_valid_for_future_training_readiness"]
    assert not report["official_identity_comparison"]["matches_official_counts"]
    assert report["official_identity_comparison"]["official_reference"]["total_records"] == 10025


def test_unexpected_label_values_stop_training_readiness_mapping():
    mapping = propose_canonical_label_mapping(pd.Series(["Benign", "Malicious", "Unknown"]))
    assert not mapping["is_valid_for_future_training_readiness"]
    assert mapping["unexpected_normalized_values"] == ["unknown"]
    assert mapping["raw_to_canonical_mapping"] == {}


def test_identifier_missing_and_malformed_string_reporting_is_non_destructive():
    report = validate_cic_pdfmal(_frame())
    assert report["column_roles"]["FileName"]["classification"] == "identifier"
    assert report["column_profiles"]["FileName"]["identifier_values_redacted"]
    assert report["column_profiles"]["FileName"]["representative_values"] == [{"value": "<redacted identifier values>", "count": 4}]
    assert "a" * 64 not in json.dumps(report["column_profiles"]["FileName"])
    assert report["column_roles"]["PdfSize"]["classification"] == "candidate_predictive_feature"
    assert report["column_profiles"]["PdfSize"]["negative_value_count"] == 1
    assert report["column_profiles"]["Text"]["negative_value_count"] == 1
    assert report["column_profiles"]["Text"]["numeric_summary_basis"].startswith("lexical_numeric_subset")
    assert report["column_profiles"]["Images"]["string_value_audit"]["non_numeric_or_malformed_examples"] == [{"value": "1(1)", "count": 1}]
    assert report["column_profiles"]["Text"]["string_value_audit"]["textual_boolean_examples"] == [{"value": "No", "count": 1}, {"value": "Yes", "count": 1}]


def test_duplicate_feature_vector_analysis_ignores_identifier_and_finds_conflicting_labels():
    frame = pd.DataFrame(
        {
            "FileName": ["a" * 64, "b" * 64, "c" * 64],
            "PdfSize": [1.0, 1.0, 1.0],
            "Class": pd.Categorical(["Benign", "Benign", "Malicious"]),
        }
    )
    summary = validate_cic_pdfmal(frame)["duplicate_summary"]
    assert summary["exact_duplicate_rows_excluding_first"] == 0
    assert summary["duplicate_predictive_feature_rows_excluding_first"] == 2
    assert summary["duplicate_predictive_feature_groups"] == 1
    assert summary["conflicting_labels_for_identical_predictive_feature_vectors"] == 1


def test_inspection_writes_only_derived_reports_and_never_changes_parquet(tmp_path):
    data_dir = tmp_path / "data" / "external" / "cic"
    data_dir.mkdir(parents=True)
    path = data_dir / EXPECTED_FILENAME
    _frame().to_parquet(path, index=False)
    before = sha256_file(path)
    report = inspect_cic_pdfmal(path)
    outputs = write_cic_audit_outputs(report, tmp_path / "reports")
    assert all(output.is_file() for output in outputs.values())
    assert sha256_file(path) == before
    assert "FileName" in outputs["feature_profile"].read_text(encoding="utf-8")
