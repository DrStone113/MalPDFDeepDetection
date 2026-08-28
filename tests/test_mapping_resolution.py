"""Synthetic tests for conservative v2 RIT-to-CIC mapping decisions."""

from __future__ import annotations

import pandas as pd

from malpdf.data.cic_pdfmal import validate_cic_pdfmal
from malpdf.data.cross_dataset_schema import (
    AlignmentStatus,
    build_mapping_resolution_report,
    resolve_feature_mappings,
    write_mapping_resolution_outputs,
)


def _cic_frame() -> pd.DataFrame:
    columns = [
        "PdfSize", "MetadataSize", "Pages", "XrefLength", "TitleCharacters", "isEncrypted", "EmbeddedFiles", "Images", "Text", "Header", "Obj", "Endobj", "Stream", "Endstream", "Xref", "Trailer", "StartXref", "PageNo", "Encrypt", "ObjStm", "JS", "Javascript", "AA", "OpenAction", "Acroform", "JBIG2Decode", "RichMedia", "Launch", "EmbeddedFile", "XFA", "Colors",
    ]
    frame = pd.DataFrame({column: [0.0, 1.0, 2.0, 3.0] for column in columns})
    frame["JS"] = pd.Categorical(["0", "1(1)", "1", "0"])
    frame.insert(0, "FileName", ["a" * 64, "b" * 64, "c" * 64, "d" * 64])
    frame["Class"] = pd.Categorical(["Benign", "Malicious", "Benign", "Malicious"])
    return frame


def test_v2_resolution_rebuilds_sets_deterministically_and_retains_malformed_ambiguity():
    cic_report = validate_cic_pdfmal(_cic_frame())
    first = build_mapping_resolution_report(cic_report)
    second = build_mapping_resolution_report(cic_report)
    assert first["new_status_counts"] == {
        "EXACT": 6,
        "COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM": 0,
        "AMBIGUOUS": 19,
        "NO_MATCH": 16,
    }
    assert [row["canonical_name"] for row in first["common_strict_v2"]] == [
        "metadata_size", "xref_length", "title_length", "embedded_files", "trailer", "objstm",
    ]
    assert first["common_transformable_v2"] == first["common_strict_v2"]
    assert first["transform_specification_v2"] == []
    assert first["feature_alignment_v2"] == second["feature_alignment_v2"]
    by_rit = {row["rit_column"]: row for row in first["feature_alignment_v2"]}
    assert by_rit["pdf_ver"]["status"] == AlignmentStatus.NO_MATCH.value
    assert by_rit["obj"]["status"] == AlignmentStatus.NO_MATCH.value
    assert by_rit["JS"]["status"] == AlignmentStatus.AMBIGUOUS.value
    assert by_rit["JS"]["cic_malformed_token_examples"] == [{"value": "1(1)", "count": 1}]


def test_v2_outputs_have_explicit_empty_transform_schema_and_no_target_transform(tmp_path):
    report = build_mapping_resolution_report(validate_cic_pdfmal(_cic_frame()))
    outputs = write_mapping_resolution_outputs(report, tmp_path / "reports")
    assert all(path.is_file() for path in outputs.values())
    transform_header = outputs["transform_specification"].read_text(encoding="utf-8").splitlines()[0]
    assert "rit_source_column" in transform_header
    assert "Label" not in outputs["transform_specification"].read_text(encoding="utf-8")
    assert "Class" not in outputs["transform_specification"].read_text(encoding="utf-8")


def test_resolver_only_reclassifies_documented_semantic_mismatches():
    records = resolve_feature_mappings(validate_cic_pdfmal(_cic_frame()))
    changed = {record["rit_column"] for record in records if record["mapping_changed"]}
    assert changed == {"pdf_ver", "obj", "page_command", "Encrypt", "EmbeddedFile"}
