"""Synthetic tests for CIC source-fidelity comparison without live samples."""

from __future__ import annotations

import json

import pandas as pd

from malpdf.data.cic_pdfmal import discover_cic_sources
from malpdf.data.cic_source_fidelity import (
    FidelityClassification,
    build_source_fidelity_report,
    classify_source_fidelity,
    compare_cic_sources,
    inspect_cic_sources,
    write_source_fidelity_outputs,
)
from malpdf.data.rit_pdfmal import sha256_file


def _summary(rows: int, benign: int, malicious: int, unexpected: dict[str, int] | None = None) -> dict:
    return {
        "dimensions": {"rows": rows},
        "target_summary": {
            "recognized_class_counts": {"benign": benign, "malicious": malicious},
            "unexpected_raw_label_counts": unexpected or {},
        },
    }


def _csv_frame() -> pd.DataFrame:
    return pd.DataFrame({
        "File name": ["a" * 64, "b" * 64, "c" * 64],
        "PdfSize": ["1", "2", "3"],
        "Class": ["Benign", "Malicious", "Malicious"],
    })


def _parquet_frame() -> pd.DataFrame:
    return pd.DataFrame({
        "FileName": pd.Categorical(["a" * 64, "b" * 64]),
        "PdfSize": [1.0, 9.0],
        "Class": pd.Categorical(["Benign", "Malicious"]),
    })


def test_discovery_includes_multiple_csv_and_parquet_mirrors(tmp_path):
    (tmp_path / "nested").mkdir()
    _csv_frame().to_csv(tmp_path / "copy.csv", index=False)
    _parquet_frame().to_parquet(tmp_path / "nested" / "copy.parquet", index=False)
    assert [path.name for path in discover_cic_sources(tmp_path)] == ["copy.csv", "copy.parquet"]


def test_fidelity_classification_covers_full_subset_and_transformed_cases():
    assert classify_source_fidelity(_summary(10025, 4468, 5557)) is FidelityClassification.FULL_COUNT_MATCH
    assert classify_source_fidelity(_summary(10023, 4468, 5555)) is FidelityClassification.SUBSET_OR_TRUNCATED
    assert classify_source_fidelity(_summary(10026, 4468, 5557, {"nan": 1})) is FidelityClassification.TRANSFORMED


def test_row_comparison_identifies_identifier_subset_and_semantic_value_changes(tmp_path):
    _csv_frame().to_csv(tmp_path / "larger.csv", index=False)
    _parquet_frame().to_parquet(tmp_path / "smaller.parquet", index=False)
    sources = inspect_cic_sources(tmp_path)
    larger, smaller = sources
    comparison = compare_cic_sources(larger, smaller)["rows"]
    assert comparison["comparison_possible"]
    assert comparison["common_identifier_records"] == 2
    assert comparison["larger_only_identifier_records"] == 1
    assert comparison["larger_only_label_counts"] == {"Malicious": 1}
    assert comparison["identifier_set_is_subset"]
    assert comparison["shared_rows_with_any_semantic_feature_difference"] == 1
    assert not comparison["strict_recordwise_subset"]


def test_source_outputs_redact_identifiers_and_never_change_sources(tmp_path):
    csv_path = tmp_path / "larger.csv"
    parquet_path = tmp_path / "smaller.parquet"
    _csv_frame().to_csv(csv_path, index=False)
    _parquet_frame().to_parquet(parquet_path, index=False)
    before = {path.name: sha256_file(path) for path in (csv_path, parquet_path)}
    report = build_source_fidelity_report(inspect_cic_sources(tmp_path))
    smaller = next(source for source in report["sources"] if source["filename"] == "smaller.parquet")
    assert smaller["population_fidelity_classification"] == FidelityClassification.SUBSET_OR_TRUNCATED.value
    assert smaller["fidelity_classification"] == FidelityClassification.TRANSFORMED.value
    outputs = write_source_fidelity_outputs(report, tmp_path / "reports")
    assert all(path.is_file() for path in outputs.values())
    assert before == {path.name: sha256_file(path) for path in (csv_path, parquet_path)}
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in outputs.values())
    assert "a" * 64 not in rendered
    assert "b" * 64 not in rendered
    assert json.loads(json.dumps(report["recommendation"]))["recommendation"]
