"""Documented, non-training RIT-PDFMal to CIC schema-alignment utilities."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from malpdf.data.cic_pdfmal import OFFICIAL_CIC_URL
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_FEATURE_DICTIONARY, PAPER_SOURCE_URL, TARGET_COLUMN


class AlignmentStatus(str, Enum):
    """Evidence-qualified relationship between one RIT and one CIC feature."""

    EXACT = "EXACT"
    COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM = "COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM"
    AMBIGUOUS = "AMBIGUOUS"
    NO_MATCH = "NO_MATCH"


_EXACT = {
    "metadata size": ("MetadataSize", "metadata_size", "Both dictionaries describe metadata-section size; compatible numeric quantity, with CIC's observed -1 raw sentinel retained and separately audited."),
    "xref length": ("XrefLength", "xref_length", "Both dictionaries describe the Xref length/entry quantity; local maxima and numeric representation are compatible evidence, while CIC -1 remains an unverified raw sentinel."),
    "title length": ("TitleCharacters", "title_length", "Both dictionaries describe the number of title characters; compatible numeric character count, with CIC's raw -1 sentinel retained."),
    "embedded files": ("EmbeddedFiles", "embedded_files", "Both dictionaries describe a count of embedded files and use a numeric local representation; no unit conversion is required."),
    "trailer": ("Trailer", "trailer", "Both dictionaries describe a count of PDF trailers and use numeric local representations."),
    "ObjStm": ("ObjStm", "objstm", "Both dictionaries describe stream objects (ObjStm) as a numeric count."),
}

_AMBIGUOUS = {
    "pdfsize": ("PdfSize", "pdf_size", "Same broad size concept, but the official CIC page does not state its unit and the mirror must not be assumed byte-identical or identically scaled."),
    "pages": ("Pages", "pages", "Same page-count concept, but RIT documents corrupted files as pages=0 while CIC has observed -1 values with no verified CIC sentinel semantics."),
    "isEncrypted": ("isEncrypted", "is_encrypted", "Related encryption indicator, but CIC observed values extend beyond binary 0/1 and its special-value representation is unverified."),
    "images": ("Images", "images", "Same image-count concept, but CIC stores category strings and includes malformed lexical values such as 1(1); no coercion is defensible yet."),
    "contains_text": ("Text", "contains_text", "RIT is a documented >=50-character ternary signal; CIC documents text presence with Yes/No/unclear/-1/0 values. These are not established as equivalent."),
    "pdf_ver": ("Header", "pdf_version_or_header", "CIC documents valid-header presence, whereas RIT stores a numeric extracted PDF version. Header strings must not be treated as a version transform without verification."),
    "obj": ("Obj", "obj", "RIT counts obj string occurrences; CIC documents indirect objects and also has malformed category values. Parser/count equivalence is not established."),
    "endobj": ("Endobj", "endobj", "Related name, but the CIC official page does not separately define Endobj and raw values include non-numeric text."),
    "stream": ("Stream", "stream", "RIT counts stream string occurrences; CIC documents streams as binary-data sequences. Equal parser/count semantics are not established."),
    "endstream": ("Endstream", "endstream", "Related name, but CIC Endstream is not separately defined in the official feature descriptions and raw values are malformed in places."),
    "xref": ("Xref", "xref", "RIT counts xref occurrences while CIC documents Xref tables; count semantics are related but not proven equal."),
    "startxref": ("StartXref", "startxref", "Related startxref keyword count, but CIC includes malformed raw strings and exact parser behavior is not documented."),
    "page_command": ("PageNo", "page_command_or_page_no", "Both appear page-related, but CIC PageNo is not separately defined and is not proven to count the /Page keyword."),
    "Encrypt": ("Encrypt", "encrypt", "Related names, but CIC's Encrypt column is distinct from isEncrypted and is not separately defined on the official page."),
    "JS": ("JS", "js", "Both refer to JS-related keywords/objects, but CIC's category values contain unverified malformed encodings such as 1(1)."),
    "JavaScript": ("Javascript", "javascript", "Both refer to JavaScript-related keywords/objects, but CIC category encodings include malformed values and exact parser semantics are not established."),
    "AA": ("AA", "aa", "Related keyword-count concept, but CIC categorical malformed values prevent a defensible raw representation equivalence."),
    "OpenAction": ("OpenAction", "open_action", "Related keyword-count concept, but CIC categorical malformed values prevent a defensible raw representation equivalence."),
    "Acroform": ("Acroform", "acroform", "Related tag-count concept, but CIC categorical malformed values and RIT's documented zero variance require review before sharing it."),
    "JBIG2Decode": ("JBIG2Decode", "jbig2decode", "RIT counts occurrences while CIC documentation describes presence; a count is not automatically equivalent to an indicator."),
    "RichMedia": ("RichMedia", "rich_media", "Related keyword-count concept, but CIC categorical malformed values prevent a defensible raw representation equivalence."),
    "Launch": ("Launch", "launch", "Related keyword-count concept, but CIC categorical malformed values prevent a defensible raw representation equivalence."),
    "EmbeddedFile": ("EmbeddedFile", "embedded_file", "Related name, but CIC's EmbeddedFile column is not separately defined and contains malformed category values."),
    "XFA": ("XFA", "xfa", "Related XFA concept, but CIC's exact count/indicator semantics and malformed categorical representation require review."),
}

_NO_MATCH = {
    "Colors": ("Colors", "colors", "The RIT feature counts /Colors > 2^24 occurrences, whereas CIC documents different colors used. Same name is not a defensible semantic equivalence."),
    "URI": (None, "uri", "No CIC URI column is present in the actual local schema."),
    "BaseEncoding": (None, "base_encoding", "No CIC BaseEncoding column is present in the actual local schema."),
    "Encoding": (None, "encoding", "No CIC Encoding column is present in the actual local schema."),
    "ProcSet": (None, "proc_set", "No CIC ProcSet column is present in the actual local schema."),
    "Registry": (None, "registry", "No CIC Registry column is present in the actual local schema."),
    "Resources": (None, "resources", "No CIC Resources column is present in the actual local schema."),
    "www": (None, "www", "No CIC www column is present in the actual local schema."),
    "server": (None, "server", "No CIC server column is present in the actual local schema."),
    "Root": (None, "root", "No CIC Root column is present in the actual local schema."),
    "BitsPerComponent": (None, "bits_per_component", "No CIC BitsPerComponent column is present in the actual local schema."),
}


def _rit_dictionary() -> dict[str, dict[str, str]]:
    return {entry["column"]: entry for entry in PAPER_FEATURE_DICTIONARY}


def build_feature_alignment(cic_report: dict[str, Any]) -> list[dict[str, Any]]:
    """Classify every RIT feature against the actual CIC schema in paper order."""
    cic_columns = set(cic_report["candidate_predictive_columns"])
    dictionaries = _rit_dictionary()
    records: list[dict[str, Any]] = []
    for rit in PAPER_FEATURE_DICTIONARY:
        name = rit["column"]
        if name in _EXACT:
            cic_column, canonical, rationale = _EXACT[name]
            status = AlignmentStatus.EXACT
        elif name in _AMBIGUOUS:
            cic_column, canonical, rationale = _AMBIGUOUS[name]
            status = AlignmentStatus.AMBIGUOUS
        elif name in _NO_MATCH:
            cic_column, canonical, rationale = _NO_MATCH[name]
            status = AlignmentStatus.NO_MATCH
        else:  # Defensive so a future RIT dictionary addition cannot silently be aligned.
            cic_column, canonical, rationale, status = None, name, "No alignment rule was reviewed for this RIT feature.", AlignmentStatus.NO_MATCH
        if cic_column is not None and cic_column not in cic_columns:
            status = AlignmentStatus.NO_MATCH
            rationale = f"Expected related CIC column {cic_column!r} is absent from the actual local schema."
            cic_column = None
        records.append({
            "rit_column": name, "rit_meaning": dictionaries[name]["paper_meaning"], "cic_column": cic_column,
            "canonical_name": canonical, "status": status.value, "rationale": rationale,
            "transform_id": None, "transform_specification": None,
            "source_evidence": f"RIT: {PAPER_SOURCE_URL}; CIC: {OFFICIAL_CIC_URL}",
        })
    return records


def derive_common_feature_sets(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Derive deterministic strict and transformable sets without choosing features by labels."""
    all_records = list(records)
    strict = [record for record in all_records if record["status"] == AlignmentStatus.EXACT.value]
    transformable = [
        record for record in all_records
        if record["status"] in {AlignmentStatus.EXACT.value, AlignmentStatus.COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM.value}
    ]
    return strict, transformable


def reverse_cic_alignment(cic_report: dict[str, Any], records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Record every CIC predictor's relation (or lack of one) to a RIT feature."""
    by_cic = {record["cic_column"]: record for record in records if record["cic_column"] is not None}
    reverse: list[dict[str, Any]] = []
    for column in cic_report["candidate_predictive_columns"]:
        match = by_cic.get(column)
        if match is None or match["status"] == AlignmentStatus.NO_MATCH.value:
            reverse.append({"cic_column": column, "rit_column": None, "status": AlignmentStatus.NO_MATCH.value, "note": "No defensible RIT equivalent is established."})
        else:
            reverse.append({"cic_column": column, "rit_column": match["rit_column"], "status": match["status"], "note": match["rationale"]})
    return reverse


def _numeric_distribution(series: pd.Series) -> dict[str, Any]:
    values = pd.to_numeric(series, errors="coerce")
    finite = values.loc[np.isfinite(values)]
    if len(finite) == 0:
        return {"row_count": int(len(series)), "usable_numeric_count": 0, "minimum": None, "maximum": None, "median": None, "q25": None, "q75": None, "zero_fraction": None}
    return {
        "row_count": int(len(series)), "usable_numeric_count": int(len(finite)), "minimum": float(finite.min()),
        "maximum": float(finite.max()), "median": float(finite.median()), "q25": float(finite.quantile(0.25)),
        "q75": float(finite.quantile(0.75)), "zero_fraction": float((finite == 0).mean()),
    }


def distribution_comparison(
    rit_frame: pd.DataFrame, cic_frame: pd.DataFrame, cic_report: dict[str, Any], strict: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Describe only strict-feature distributions; no model or feature selection occurs."""
    cic_target = cic_report["target"]["candidate_column"]
    rows: list[dict[str, Any]] = []
    for record in strict:
        for dataset, source_column, frame, target in (
            ("RIT-PDFMal-2026", record["rit_column"], rit_frame, TARGET_COLUMN),
            ("CIC-Evasive-PDFMal2022 mirror", record["cic_column"], cic_frame, cic_target),
        ):
            for subset, mask in (
                ("all", pd.Series(True, index=frame.index)),
                ("benign", frame[target].astype("string").str.casefold().eq("benign") if dataset.startswith("CIC") else frame[target].eq(0)),
                ("malicious", frame[target].astype("string").str.casefold().eq("malicious") if dataset.startswith("CIC") else frame[target].eq(1)),
            ):
                summary = _numeric_distribution(frame.loc[mask, source_column])
                rows.append({"canonical_name": record["canonical_name"], "dataset": dataset, "source_column": source_column, "subset": subset, **summary})
    return rows


def class_balance_comparison(cic_report: dict[str, Any], rit_frame: pd.DataFrame) -> list[dict[str, Any]]:
    """Describe observed class balance without mutating either dataset's labels."""
    rows: list[dict[str, Any]] = []
    for label in (0, 1):
        count = int(rit_frame[TARGET_COLUMN].eq(label).sum())
        rows.append({
            "dataset": "RIT-PDFMal-2026", "raw_label": label, "canonical_label": label,
            "count": count, "percentage": (100.0 * count / len(rit_frame)) if len(rit_frame) else 0.0,
        })

    mapping = cic_report["target"]["proposed_label_mapping"]["raw_to_canonical_mapping"]
    for item in cic_report["target"]["distribution"]:
        raw_label = item["raw_value"]
        rows.append({
            "dataset": "CIC-Evasive-PDFMal2022 mirror", "raw_label": raw_label,
            "canonical_label": mapping.get(str(raw_label)), "count": item["count"],
            "percentage": item["percentage"],
        })
    return rows


def build_schema_alignment_report(cic_report: dict[str, Any], cic_frame: pd.DataFrame, rit_frame: pd.DataFrame) -> dict[str, Any]:
    """Build schema evidence and descriptive strict-set distribution summaries."""
    records = build_feature_alignment(cic_report)
    strict, transformable = derive_common_feature_sets(records)
    reverse = reverse_cic_alignment(cic_report, records)
    status_counts = {status.value: sum(record["status"] == status.value for record in records) for status in AlignmentStatus}
    return {
        "alignment_version": "1.0",
        "sources": {"rit_paper_alignment": PAPER_SOURCE_URL, "cic_official_documentation": OFFICIAL_CIC_URL},
        "dataset_provenance": {"rit_sha256": "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623", "cic_sha256": cic_report["dataset"]["sha256"], "cic_source_type": "third-party mirror", "cic_source_platform": "Kaggle"},
        "rit_feature_count": len(PAPER_FEATURE_DICTIONARY), "cic_candidate_predictive_feature_count": len(cic_report["candidate_predictive_columns"]),
        "alignment": records, "reverse_cic_alignment": reverse, "status_counts": status_counts,
        "common_strict": strict, "common_transformable": transformable,
        "transform_specification": [record for record in records if record["status"] == AlignmentStatus.COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM.value],
        "class_balance_comparison": class_balance_comparison(cic_report, rit_frame),
        "distribution_comparison": distribution_comparison(rit_frame, cic_frame, cic_report, strict),
        "limitations": [
            "RIT local CSV does not include original per-PDF SHA-256 values, so cross-dataset file identity or overlap cannot be proven.",
            "CIC is a Kaggle third-party mirror and differs from official row/malicious counts; it is not claimed byte-identical to the CIC original.",
            "No model, cross-dataset evaluation, target-based feature selection, learned transform, imputation, normalization, or ambiguous-category encoding is included.",
            "A strict mapping establishes only documented feature comparability, not distributional equivalence or generalization.",
        ],
    }


def _markdown_cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", r"\|").replace("\n", " ")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> list[str]:
    rows = list(rows)
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |", *["| " + " | ".join(_markdown_cell(value) for value in row) + " |" for row in rows]]


def schema_alignment_markdown(report: dict[str, Any]) -> str:
    """Render the thesis-oriented alignment conclusion without overstating it."""
    strict = report["common_strict"]
    transformable = report["common_transformable"]
    lines = [
        "# RIT-PDFMal-2026 and CIC-Evasive-PDFMal2022 schema alignment", "",
        "## Objective and scope", "",
        "This is a read-only semantic/schema audit for a future RIT-trained to CIC-evaluated study. No classifier was trained and no cross-dataset performance was calculated.", "",
        "## Dataset provenance and documentation", "",
        f"- RIT SHA-256: `{report['dataset_provenance']['rit_sha256']}`.",
        f"- CIC mirror SHA-256: `{report['dataset_provenance']['cic_sha256']}`; source type/platform: third-party mirror / Kaggle.",
        "- CIC official documentation reports 10,025 records, while the local mirror audit reports 10,023. The mirror is not claimed to be byte-identical to the official file.",
        "- CIC documentation itself describes both 32 extracted features and 37 static representative features. The actual local 31-feature predictor schema is the implementation ground truth.", "",
        "## Alignment method", "",
        "Every RIT paper-dictionary feature is classified as EXACT, COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM, AMBIGUOUS, or NO_MATCH. Similar names alone are not treated as evidence: count versus presence, parser semantics, units, special values, and malformed local representations are considered.", "",
        "## Alignment results", "",
    ]
    lines.extend(_table(["Status", "RIT feature count"], [[status, count] for status, count in report["status_counts"].items()]))
    lines.extend(["", "### Common strict", "", f"Count: {len(strict)}. These are in RIT paper-dictionary order and require no transform.", ""])
    lines.extend(_table(["Canonical", "RIT column", "CIC column", "Reason"], [[record['canonical_name'], record['rit_column'], record['cic_column'], record['rationale']] for record in strict]))
    lines.extend(["", "### Common transformable", "", f"Count: {len(transformable)}. It contains exact mappings plus only reviewed deterministic transforms; no ambiguous feature is included.", ""])
    lines.extend(_table(["Canonical", "RIT column", "CIC column", "Status"], [[record['canonical_name'], record['rit_column'], record['cic_column'], record['status']] for record in transformable]))
    lines.extend(["", "### Transform specification", "", "No COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM feature is included in this audit. The transform specification is intentionally empty rather than coercing malformed CIC categories or inferring units.", "", "## Descriptive domain-shift evidence", "", "Class balance is reported below and in `reports/tables/rit_cic_alignment/class_balance_comparison.csv`. Only COMMON_STRICT feature summaries are reported in `reports/tables/rit_cic_alignment/distribution_comparison.csv`; range and distribution similarities are descriptive and do not prove semantic equivalence.", ""])
    lines.extend(_table(["Dataset", "Raw label", "Canonical label", "Count", "Percentage"], [[row["dataset"], row["raw_label"], row["canonical_label"], row["count"], row["percentage"]] for row in report["class_balance_comparison"]]))
    lines.extend(["", "## Important exclusions", "", "CIC Text is not equated with RIT contains_text because the latter is a documented 50-character threshold signal. CIC Header is not converted to RIT pdf_ver. CIC Colors is not equated with RIT Colors because their documented meanings differ. CIC category columns containing values such as `1(1)`, `pdfid.py`, or `bytes[endHeader]` are not silently coerced.", "", "## File-identity limitation", "", "RIT's local CSV does not contain the original per-PDF hash field, so overlap of original PDF files between RIT and CIC cannot be established. Feature-vector similarity is not PDF-file identity.", "", "## Conclusion", "", "The strict common space is deliberately small. It is preferable to an artificial larger mapping that assumes categorical parsing, units, sentinels, or keyword-count equivalence not verified by the documentation. CV10 and Protocol G remain distinct prior evaluations; this audit makes no claim about cross-dataset generalization.", ""])
    return "\n".join(lines)


def write_schema_alignment_outputs(report: dict[str, Any], reports_root: str | Path) -> dict[str, Path]:
    """Write derived alignment evidence without changing either raw dataset."""
    root = Path(reports_root)
    analysis = root / "analysis"
    tables = root / "tables" / "rit_cic_alignment"
    analysis.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": analysis / "rit_cic_schema_alignment.md", "json": analysis / "rit_cic_schema_alignment.json",
        "feature_alignment": tables / "feature_alignment.csv", "common_strict": tables / "common_strict.csv",
        "common_transformable": tables / "common_transformable.csv", "transform_specification": tables / "transform_specification.csv",
        "class_balance_comparison": tables / "class_balance_comparison.csv", "distribution_comparison": tables / "distribution_comparison.csv", "reverse_alignment": tables / "cic_reverse_alignment.csv",
    }
    paths["markdown"].write_text(schema_alignment_markdown(report), encoding="utf-8")
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    pd.DataFrame(report["alignment"]).to_csv(paths["feature_alignment"], index=False)
    pd.DataFrame(report["common_strict"]).to_csv(paths["common_strict"], index=False)
    pd.DataFrame(report["common_transformable"]).to_csv(paths["common_transformable"], index=False)
    pd.DataFrame(report["transform_specification"]).to_csv(paths["transform_specification"], index=False)
    pd.DataFrame(report["class_balance_comparison"]).to_csv(paths["class_balance_comparison"], index=False)
    pd.DataFrame(report["distribution_comparison"]).to_csv(paths["distribution_comparison"], index=False)
    pd.DataFrame(report["reverse_cic_alignment"]).to_csv(paths["reverse_alignment"], index=False)
    return paths


# Version 2 keeps the original audit immutable and records only defensible
# reclassifications supported by both documented semantics and local raw values.
_V2_RECLASSIFICATIONS: dict[str, tuple[AlignmentStatus, str]] = {
    "pdf_ver": (
        AlignmentStatus.NO_MATCH,
        "CIC documents Header as presence of a valid PDF header, while RIT pdf_ver is a numeric extracted version. Header validity/version-like strings are not a version measurement and no deterministic conversion is documented.",
    ),
    "obj": (
        AlignmentStatus.NO_MATCH,
        "CIC documents Obj as number of indirect objects, whereas RIT counts occurrences of the raw string obj. These are distinct parser-level quantities; similar names do not establish equality.",
    ),
    "page_command": (
        AlignmentStatus.NO_MATCH,
        "RIT counts the /Page string. CIC PageNo is not described by CIC as a /Page-keyword count, so the local column is not a documented equivalent.",
    ),
    "Encrypt": (
        AlignmentStatus.NO_MATCH,
        "CIC documentation defines document encryption generally through isEncrypted, not the separate local Encrypt field as a /Encrypt occurrence count. Its distinct local semantics remain undocumented.",
    ),
    "EmbeddedFile": (
        AlignmentStatus.NO_MATCH,
        "CIC documentation defines EmbeddedFiles as number of embedded files, but does not define the separate local EmbeddedFile field as a /EmbeddedFile occurrence count.",
    ),
}


def _cic_dictionary_by_column(cic_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["column"]: entry for entry in cic_report.get("feature_dictionary", [])}


def _mapping_value_evidence(cic_report: dict[str, Any], cic_column: str | None) -> dict[str, Any]:
    """Attach safe source-value evidence; no identifiers occur in mapping records."""
    if cic_column is None or cic_column not in cic_report["column_profiles"]:
        return {"cic_column_available": False}
    profile = cic_report["column_profiles"][cic_column]
    string = profile["string_value_audit"]
    return {
        "cic_column_available": True,
        "cic_dtype": profile["dtype"],
        "cic_numeric_summary_basis": profile["numeric_summary_basis"],
        "cic_numeric_summary": profile["numeric_summary"],
        "cic_negative_value_count": profile["negative_value_count"],
        "cic_representative_values": profile["representative_values"],
        "cic_malformed_token_examples": [] if string is None else string["non_numeric_or_malformed_examples"],
        "cic_likely_semantic_type": None if string is None else string["likely_semantic_type"],
    }


def resolve_feature_mappings(cic_report: dict[str, Any]) -> list[dict[str, Any]]:
    """Revisit every original ambiguous mapping without making a feature usable by force."""
    cic_dictionary = _cic_dictionary_by_column(cic_report)
    resolved: list[dict[str, Any]] = []
    for original in build_feature_alignment(cic_report):
        record = dict(original)
        old_status = record["status"]
        new_status = AlignmentStatus(old_status)
        rationale = record["rationale"]
        if record["rit_column"] in _V2_RECLASSIFICATIONS:
            new_status, rationale = _V2_RECLASSIFICATIONS[record["rit_column"]]
        cic_definition = cic_dictionary.get(record["cic_column"], {})
        evidence = _mapping_value_evidence(cic_report, record["cic_column"])
        if old_status == AlignmentStatus.AMBIGUOUS.value and new_status == AlignmentStatus.AMBIGUOUS:
            rationale = (
                rationale
                + " The v2 review retains AMBIGUOUS because documentation/value evidence does not define a total deterministic conversion for every observed raw value."
            )
        record.update({
            "old_status": old_status,
            "status": new_status.value,
            "rationale": rationale,
            "rit_raw_semantics": _rit_dictionary()[record["rit_column"]]["paper_meaning"],
            "cic_documented_semantics": cic_definition.get("documented_meaning", "No verified CIC definition for this local column."),
            "cic_documentation_status": cic_definition.get("verification_status", "unverified"),
            "resolution_evidence": f"RIT: {PAPER_SOURCE_URL}; CIC: {OFFICIAL_CIC_URL}; local CIC dtype/value audit.",
            "mapping_changed": old_status != new_status.value,
            **evidence,
        })
        resolved.append(record)
    return resolved


def _transform_specification(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract only total, deterministic, target-independent transformations."""
    result: list[dict[str, Any]] = []
    for record in records:
        if record["status"] != AlignmentStatus.COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM.value:
            continue
        result.append({
            "rit_source_column": record["rit_column"], "cic_source_column": record["cic_column"],
            "canonical_name": record["canonical_name"], "rit_raw_semantics": record["rit_raw_semantics"],
            "cic_raw_semantics": record["cic_documented_semantics"], "transform_applied_to": record["transform_id"],
            "exact_formula": record["transform_specification"], "evidence": record["resolution_evidence"],
            "information_loss": "Must be explicitly documented for every transform.", "expected_canonical_dtype": "Must be explicitly documented for every transform.",
        })
    return result


def build_mapping_resolution_report(cic_report: dict[str, Any]) -> dict[str, Any]:
    """Build v2 alignment evidence and future-only training-readiness tracks."""
    original = build_feature_alignment(cic_report)
    records = resolve_feature_mappings(cic_report)
    strict, transformable = derive_common_feature_sets(records)
    status_counts = {status.value: sum(record["status"] == status.value for record in records) for status in AlignmentStatus}
    old_status_counts = {status.value: sum(record["status"] == status.value for record in original) for status in AlignmentStatus}
    transform_specification = _transform_specification(records)
    strict_names = [record["canonical_name"] for record in strict]
    transformable_names = [record["canonical_name"] for record in transformable]
    readiness = [
        {
            "track": "S — STRICT", "training_ready": "future design only", "feature_count": len(strict_names),
            "feature_list": strict_names,
            "limitations": "A six-feature conservative baseline can be scientifically valid, but it is a limited representation of a full static PDF detector and requires separate source/protocol authorization.",
        },
        {
            "track": "T — TRANSFORMABLE", "training_ready": "future design only", "feature_count": len(transformable_names),
            "feature_list": transformable_names,
            "limitations": "No additional documented total deterministic transform survived this review, so Track T currently equals Track S.",
        },
        {
            "track": "A — AMBIGUOUS", "training_ready": "not training-ready", "feature_count": status_counts[AlignmentStatus.AMBIGUOUS.value],
            "feature_list": [record["rit_column"] for record in records if record["status"] == AlignmentStatus.AMBIGUOUS.value],
            "limitations": "Ambiguous semantic mappings, units, sentinels, malformed raw tokens, or parser differences remain unresolved. They must not enter a common feature space.",
        },
    ]
    return {
        "resolution_version": "2.0", "cic_source": {"filename": cic_report["dataset"]["filename"], "sha256": cic_report["dataset"]["sha256"], "source_type": cic_report["mirror_provenance"]["source_type"], "source_platform": cic_report["mirror_provenance"]["source_platform"]},
        "old_status_counts": old_status_counts, "new_status_counts": status_counts,
        "feature_alignment_v2": records,
        "mapping_changes": [record for record in records if record["mapping_changed"]],
        "common_strict_v2": strict, "common_transformable_v2": transformable,
        "transform_specification_v2": transform_specification, "training_readiness": readiness,
        "limitations": [
            "This is a semantic/source audit, not a cross-dataset experiment; no model was fit or evaluated.",
            "Distribution similarity is not treated as evidence of semantic equivalence.",
            "Malformed or mixed CIC raw tokens are not cleaned, parsed heuristically, or encoded in this audit.",
            "No transform may use labels, fit data-dependent parameters, or discard unsupported raw values.",
        ],
    }


def mapping_resolution_markdown(report: dict[str, Any]) -> str:
    """Render a conservative mapping-resolution report suitable for thesis review."""
    lines = [
        "# RIT-to-CIC ambiguous feature mapping resolution", "",
        "## Scope", "",
        "This v2 review revisits every mapping that was AMBIGUOUS in the prior alignment using the RIT paper dictionary, CIC documentation, and observed local raw representations. It performs no data cleaning, target transformation, training, or cross-dataset evaluation.", "",
        "## Source under review", "",
        f"- CIC file: `{report['cic_source']['filename']}`; SHA-256: `{report['cic_source']['sha256']}`; {report['cic_source']['source_type']} / {report['cic_source']['source_platform']}.",
        "- This is not an automatic source switch. The separate source-fidelity audit records mirror limitations.", "",
        "## Status counts", "",
    ]
    lines.extend(_table(["Status", "Prior", "v2"], [[status, report["old_status_counts"][status], report["new_status_counts"][status]] for status in report["new_status_counts"]]))
    lines.extend(["", "## Reclassified mappings", ""])
    if report["mapping_changes"]:
        lines.extend(_table(["RIT feature", "CIC feature", "Prior", "v2", "Reason"], [[record["rit_column"], record["cic_column"], record["old_status"], record["status"], record["rationale"]] for record in report["mapping_changes"]]))
    else:
        lines.append("No status changes are defensible from the available evidence.")
    lines.extend(["", "## Common feature spaces", "", f"- COMMON_STRICT v2 ({len(report['common_strict_v2'])}): {', '.join(record['canonical_name'] for record in report['common_strict_v2']) or 'none'}.", f"- COMMON_TRANSFORMABLE v2 ({len(report['common_transformable_v2'])}): {', '.join(record['canonical_name'] for record in report['common_transformable_v2']) or 'none'}.", "- No transform is listed unless it is deterministic, total over observed values, documented, target-independent, and explicit about information loss. None met that bar here.", "", "## Training-readiness assessment", ""])
    lines.extend(_table(["Track", "Readiness", "Feature count", "Features", "Limitation"], [[item["track"], item["training_ready"], item["feature_count"], ", ".join(item["feature_list"]), item["limitations"]] for item in report["training_readiness"]]))
    lines.extend(["", "## Six-feature baseline caution", "", "A future six-feature strict baseline can be scientifically valid because every included feature has a conservative documented alignment. It must be presented as a limited feature-space baseline, not as the full detector capability or an external-generalization conclusion.", "", "## Remaining limitations", "", *[f"- {item}" for item in report["limitations"]], ""])
    return "\n".join(lines)


def write_mapping_resolution_outputs(report: dict[str, Any], reports_root: str | Path) -> dict[str, Path]:
    """Write v2 audit tables without modifying legacy v1 reports or raw data."""
    root = Path(reports_root)
    analysis, tables = root / "analysis", root / "tables" / "rit_cic_alignment_v2"
    analysis.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": analysis / "rit_cic_mapping_resolution.md", "feature_alignment": tables / "feature_alignment_v2.csv",
        "mapping_changes": tables / "mapping_changes.csv", "common_strict": tables / "common_strict_v2.csv",
        "common_transformable": tables / "common_transformable_v2.csv", "transform_specification": tables / "transform_specification_v2.csv",
        "training_readiness": tables / "training_readiness.csv",
    }
    paths["markdown"].write_text(mapping_resolution_markdown(report), encoding="utf-8")
    pd.DataFrame(report["feature_alignment_v2"]).to_csv(paths["feature_alignment"], index=False)
    pd.DataFrame(report["mapping_changes"]).to_csv(paths["mapping_changes"], index=False)
    pd.DataFrame(report["common_strict_v2"]).to_csv(paths["common_strict"], index=False)
    pd.DataFrame(report["common_transformable_v2"]).to_csv(paths["common_transformable"], index=False)
    transform_columns = ["rit_source_column", "cic_source_column", "canonical_name", "rit_raw_semantics", "cic_raw_semantics", "transform_applied_to", "exact_formula", "evidence", "information_loss", "expected_canonical_dtype"]
    pd.DataFrame(report["transform_specification_v2"], columns=transform_columns).to_csv(paths["transform_specification"], index=False)
    pd.DataFrame(report["training_readiness"]).to_csv(paths["training_readiness"], index=False)
    return paths
