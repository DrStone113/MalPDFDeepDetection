"""Synthetic tests for evidence-qualified RIT-to-CIC schema alignment."""

from __future__ import annotations

import pandas as pd

from malpdf.data.cic_pdfmal import validate_cic_pdfmal
from malpdf.data.cross_dataset_schema import (
    AlignmentStatus,
    build_schema_alignment_report,
    derive_common_feature_sets,
    write_schema_alignment_outputs,
)
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_FEATURE_DICTIONARY


def _rit_frame() -> pd.DataFrame:
    frame = pd.DataFrame({entry["column"]: [0.0, 1.0, 2.0, 3.0] for entry in PAPER_FEATURE_DICTIONARY})
    frame["Label"] = [0, 1, 0, 1]
    return frame


def _cic_frame() -> pd.DataFrame:
    columns = [
        "PdfSize", "MetadataSize", "Pages", "XrefLength", "TitleCharacters", "isEncrypted", "EmbeddedFiles", "Images", "Text", "Header", "Obj", "Endobj", "Stream", "Endstream", "Xref", "Trailer", "StartXref", "PageNo", "Encrypt", "ObjStm", "JS", "Javascript", "AA", "OpenAction", "Acroform", "JBIG2Decode", "RichMedia", "Launch", "EmbeddedFile", "XFA", "Colors",
    ]
    frame = pd.DataFrame({column: [0.0, 1.0, 2.0, 3.0] for column in columns})
    frame.insert(0, "FileName", ["a" * 64, "b" * 64, "c" * 64, "d" * 64])
    frame["Class"] = pd.Categorical(["Benign", "Malicious", "Benign", "Malicious"])
    return frame


def test_alignment_statuses_and_common_strict_order_are_deterministic():
    report = build_schema_alignment_report(validate_cic_pdfmal(_cic_frame()), _cic_frame(), _rit_frame())
    by_rit = {row["rit_column"]: row for row in report["alignment"]}
    assert by_rit["metadata size"]["status"] == AlignmentStatus.EXACT.value
    assert by_rit["pdfsize"]["status"] == AlignmentStatus.AMBIGUOUS.value
    assert by_rit["URI"]["status"] == AlignmentStatus.NO_MATCH.value
    assert [row["canonical_name"] for row in report["common_strict"]] == [
        "metadata_size", "xref_length", "title_length", "embedded_files", "trailer", "objstm",
    ]
    assert report["common_transformable"] == report["common_strict"]
    assert "pdf_size" not in {row["canonical_name"] for row in report["common_transformable"]}
    assert report["status_counts"] == {"EXACT": 6, "COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM": 0, "AMBIGUOUS": 24, "NO_MATCH": 11}
    assert len(report["distribution_comparison"]) == 36
    assert report["class_balance_comparison"] == [
        {"dataset": "RIT-PDFMal-2026", "raw_label": 0, "canonical_label": 0, "count": 2, "percentage": 50.0},
        {"dataset": "RIT-PDFMal-2026", "raw_label": 1, "canonical_label": 1, "count": 2, "percentage": 50.0},
        {"dataset": "CIC-Evasive-PDFMal2022 mirror", "raw_label": "Benign", "canonical_label": 0, "count": 2, "percentage": 50.0},
        {"dataset": "CIC-Evasive-PDFMal2022 mirror", "raw_label": "Malicious", "canonical_label": 1, "count": 2, "percentage": 50.0},
    ]


def test_documented_transform_mappings_are_in_transformable_not_strict():
    exact = {"canonical_name": "exact", "status": AlignmentStatus.EXACT.value}
    transform = {"canonical_name": "transform", "status": AlignmentStatus.COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM.value, "transform_specification": "documented identity"}
    ambiguous = {"canonical_name": "ambiguous", "status": AlignmentStatus.AMBIGUOUS.value}
    strict, transformable = derive_common_feature_sets([exact, transform, ambiguous])
    assert strict == [exact]
    assert transformable == [exact, transform]


def test_alignment_outputs_are_derived_tables_only(tmp_path):
    report = build_schema_alignment_report(validate_cic_pdfmal(_cic_frame()), _cic_frame(), _rit_frame())
    outputs = write_schema_alignment_outputs(report, tmp_path / "reports")
    assert all(path.is_file() for path in outputs.values())
    assert "COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM" not in outputs["common_strict"].read_text(encoding="utf-8")
    assert "metadata_size" in outputs["common_transformable"].read_text(encoding="utf-8")
