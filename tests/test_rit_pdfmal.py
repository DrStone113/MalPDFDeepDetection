import json

import numpy as np
import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from malpdf.data.rit_pdfmal import (
    DatasetValidationError,
    inspect_rit_pdfmal,
    load_rit_pdfmal,
    validate_rit_pdfmal,
    write_inspection_reports,
)


def test_loader_preserves_column_names_and_textual_missing_tokens(tmp_path):
    dataset = tmp_path / "fixture.csv"
    dataset.write_text("feature,Label,note\n1,0,NA\n2,1,\n", encoding="utf-8")

    frame = load_rit_pdfmal(dataset)

    assert list(frame.columns) == ["feature", "Label", "note"]
    assert frame["note"].tolist() == ["NA", ""]
    assert frame["note"].isna().sum() == 0


def test_loader_rejects_duplicate_headers_instead_of_renaming_them(tmp_path):
    dataset = tmp_path / "duplicate_headers.csv"
    dataset.write_text("feature,feature,Label\n1,2,0\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError, match="duplicate column names"):
        load_rit_pdfmal(dataset)


def test_validation_identifies_actual_label_and_reports_quality_checks(tmp_path):
    frame = pd.DataFrame(
        {
            "feature": [1, 1, 2, 2],
            "constant": [9, 9, 9, 9],
            "sample_id": ["a", "b", "c", "d"],
            "Resources": [0, 1, 0, 1],
            "status": ["NA", "ok", "ok", "ok"],
            "Label": [0, 0, 1, np.nan],
        }
    )
    original = frame.copy(deep=True)
    dataset = tmp_path / "fixture.csv"
    dataset.write_text("placeholder", encoding="utf-8")

    report = validate_rit_pdfmal(frame, dataset)

    assert report["target"]["candidate_column"] == "Label"
    assert report["target"]["distribution"] == [
        {"raw_value": 0.0, "count": 2, "percentage": 50.0},
        {"raw_value": 1.0, "count": 1, "percentage": 25.0},
        {"raw_value": "<NA>", "count": 1, "percentage": 25.0},
    ]
    assert report["missing_values"]["Label"]["actual_nan_count"] == 1
    assert report["missing_values"]["status"]["textual_placeholder_count"] == 1
    assert report["column_quality"]["constant_columns"] == ["constant"]
    assert report["potential_leakage"]["identifier_and_metadata"]["identifier_like_columns"][0]["column"] == "sample_id"
    assert report["potential_leakage"]["identifier_and_metadata"]["source_or_collection_metadata_columns"] == []
    assert_frame_equal(frame, original)


def test_inspection_writes_markdown_and_json_reports(tmp_path):
    dataset = tmp_path / "fixture.csv"
    dataset.write_text("value,Label\n10,0\n20,1\n", encoding="utf-8")
    report = inspect_rit_pdfmal(dataset)
    markdown_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"

    write_inspection_reports(report, markdown_path, json_path)

    assert "# RIT-PDFMal-2026 dataset inspection" in markdown_path.read_text(encoding="utf-8")
    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["dataset"]["filename"] == "fixture.csv"
    assert persisted["dataset"]["sha256"] == report["dataset"]["sha256"]
