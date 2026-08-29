from __future__ import annotations

import csv
from pathlib import Path

import pytest

from malpdf.thesis.evidence import EvidenceError, build_thesis_evidence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_thesis_evidence_builder_is_deterministic_and_uses_explicit_metric_names(tmp_path: Path) -> None:
    first = build_thesis_evidence(REPOSITORY_ROOT, tmp_path / "first")
    second = build_thesis_evidence(REPOSITORY_ROOT, tmp_path / "second")

    assert len(first.table_paths) == 10
    assert [path.name for path in first.table_paths] == [path.name for path in second.table_paths]
    for first_path, second_path in zip(first.table_paths, second.table_paths, strict=True):
        assert first_path.read_bytes() == second_path.read_bytes()
    assert first.results_summary_path.read_bytes() == second.results_summary_path.read_bytes()

    protocol_g = _rows(first.output_directory / "tables" / "protocol_g_models.csv")
    assert len(protocol_g) == 5
    assert set(protocol_g[0]) >= {"precision_malicious", "recall_malicious", "f1_malicious", "f1_macro", "mcc"}
    assert "f1" not in protocol_g[0]
    xgboost = next(row for row in protocol_g if row["model_name"] == "xgboost")
    assert float(xgboost["f1_malicious"]) == pytest.approx(0.9742410303587856)
    assert float(xgboost["mcc"]) == pytest.approx(0.9541605987518564)

    dataset_rows = _rows(first.output_directory / "tables" / "dataset_summary.csv")
    dataset = {row["item"]: row["value"] for row in dataset_rows}
    assert dataset["rows"] == "24337"
    assert dataset["predictive_features"] == "41"
    assert dataset["feature_equivalent_groups"] == "15371"
    assert "identical 41-dimensional feature vectors" in first.results_summary_path.read_text(encoding="utf-8")


def test_thesis_evidence_builder_requires_committed_sources(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="Required thesis evidence source is missing"):
        build_thesis_evidence(tmp_path, tmp_path / "output")
