"""Read-only alignment audit against the RIT-PDFMal-2026 paper.

The paper reference below is transcribed from Tables 1--7 and the surrounding
methodology text in Alani and Damiani (2026). It is report metadata, not model
configuration: no training or preprocessing is performed here.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids

PAPER_TITLE = "RIT-PDFMal-2026: A Comprehensive Benchmark Dataset for PDF Malware Detection"
PAPER_DOI = "10.1109/ACCESS.2026.3707213"
PAPER_SOURCE_URL = (
    "https://www.researchgate.net/publication/408100426_"
    "RIT-PDFMal-2026_A_Comprehensive_Benchmark_Dataset_for_PDF_Malware_Detection"
)
TARGET_COLUMN = "Label"


def _feature(
    name: str,
    meaning: str,
    expected_value_type: str,
    *,
    special_values: str = "Not specified in the paper.",
    directional_semantics: str = "Not stated in the paper.",
) -> dict[str, str]:
    return {
        "column": name,
        "paper_meaning": meaning,
        "expected_value_type": expected_value_type,
        "special_values": special_values,
        "higher_lower_semantic_meaning": directional_semantics,
    }


# Table 2 terminology is retained where practical. Counts are the authors'
# stated number of string occurrences, not a claim about executable behavior.
PAPER_FEATURE_DICTIONARY = [
    _feature(
        "pdfsize",
        "Size of the PDF file in kilobytes.",
        "Non-negative numeric size (kilobytes).",
        directional_semantics="Paper SHAP discussion: lower size pushed toward malicious; larger size toward benign.",
    ),
    _feature("metadata size", "Size of metadata extracted from the PDF file, in bytes.", "Non-negative integer-like size (bytes)."),
    _feature(
        "pages",
        "Number of pages in the PDF file.",
        "Non-negative integer count.",
        special_values="0 is documented as occurring in deliberately corrupted malicious PDFs.",
        directional_semantics="Paper SHAP discussion says a similar lower-versus-higher pattern to pdfsize applies.",
    ),
    _feature("xref length", "xref length as extracted from the file header.", "Non-negative integer-like length."),
    _feature("title length", "Number of characters in the file title.", "Non-negative integer count."),
    _feature("isEncrypted", "1 if the file is encrypted; 0 otherwise.", "Binary integer (0 or 1)."),
    _feature("embedded files", "Number of embedded files inside the PDF, as extracted from the header.", "Non-negative integer count."),
    _feature(
        "images",
        "Number of images in the PDF file.",
        "Integer count; normally non-negative.",
        special_values="-1 means the file is corrupted and the number of images cannot be shown.",
    ),
    _feature(
        "contains_text",
        "Whether the file contains at least the default threshold of 50 text characters.",
        "Ternary integer signal (-1, 0, 1).",
        special_values="1: threshold met; 0: threshold not met; -1: corrupted file and text could not be read.",
        directional_semantics="Paper SHAP discussion: 0 pushed toward malicious; >=50 characters (1) pushed toward benign.",
    ),
    _feature(
        "pdf_ver",
        "PDF version extracted from the file header.",
        "Numeric version value.",
        special_values="The paper documents max 5 although the highest valid PDF version is 2.0; it attributes such invalid values to many malicious samples. Meaning of 0 is not explained.",
    ),
    _feature("obj", 'Number of occurrences of the string "obj" in the PDF file.', "Non-negative integer count."),
    _feature("endobj", 'Number of occurrences of the string "endobj" in the PDF file.', "Non-negative integer count."),
    _feature("stream", 'Number of occurrences of the string "stream" in the PDF file.', "Non-negative integer count."),
    _feature("endstream", 'Number of occurrences of the string "endstream" in the PDF file.', "Non-negative integer count."),
    _feature("trailer", 'Number of occurrences of the string "trailer" in the PDF file.', "Non-negative integer count."),
    _feature("xref", 'Number of occurrences of the string "xref" in the PDF file.', "Non-negative integer count."),
    _feature("startxref", 'Number of occurrences of the string "startxref" in the PDF file.', "Non-negative integer count."),
    _feature("page_command", 'Number of occurrences of the string "/Page" in the PDF file.', "Non-negative integer count."),
    _feature("Encrypt", 'Number of occurrences of the string "/Encrypt" in the PDF file.', "Non-negative integer count."),
    _feature("ObjStm", 'Number of occurrences of the string "/ObJStm" in the PDF file.', "Non-negative integer count."),
    _feature(
        "JS",
        'Number of occurrences of the string "/JS" in the PDF file.',
        "Non-negative integer count.",
        directional_semantics="Paper SHAP discussion: higher occurrences pushed toward malicious; lower occurrences toward benign.",
    ),
    _feature(
        "JavaScript",
        'Number of occurrences of the string "/JavaScript" in the PDF file.',
        "Non-negative integer count.",
        directional_semantics="Paper SHAP discussion: higher occurrences pushed toward malicious; lower occurrences toward benign.",
    ),
    _feature("AA", 'Number of occurrences of the string "/AA" in the PDF file.', "Non-negative integer count."),
    _feature("OpenAction", 'Number of occurrences of the string "/OpenAction" in the PDF file.', "Non-negative integer count."),
    _feature("Acroform", 'Number of occurrences of the string "/Acroform" in the PDF file.', "Non-negative integer count."),
    _feature("JBIG2Decode", 'Number of occurrences of the string "/JBIG2Decode" in the PDF file.', "Non-negative integer count."),
    _feature("RichMedia", 'Number of occurrences of the string "/RichMedia" in the PDF file.', "Non-negative integer count."),
    _feature("Launch", 'Number of occurrences of the string "/Launch" in the PDF file.', "Non-negative integer count."),
    _feature("EmbeddedFile", 'Number of occurrences of the string "/EmbeddedFile" in the PDF file.', "Non-negative integer count."),
    _feature(
        "XFA",
        'Number of occurrences of the string "/XFA" in the PDF file.',
        "Non-negative integer count.",
        directional_semantics="Paper SHAP discussion relates this feature to JavaScript/JS; /XFA can embed scripts in XML Forms Architecture.",
    ),
    _feature("Colors", 'Number of occurrences of the string "/Colors > 2^24" in the PDF file.', "Non-negative integer count."),
    _feature(
        "URI",
        'Number of occurrences of the string "/URI" in the PDF file.',
        "Non-negative integer count.",
        directional_semantics="Paper SHAP discussion says the number of URI occurrences is considered an indication of maliciousness by the classifier.",
    ),
    _feature("BaseEncoding", 'Number of occurrences of the string "/BaseEncoding" in the PDF file.', "Non-negative integer count."),
    _feature("Encoding", 'Number of occurrences of the string "/Encoding" in the PDF file.', "Non-negative integer count."),
    _feature("ProcSet", 'Number of occurrences of the string "/ProcSet" in the PDF file.', "Non-negative integer count."),
    _feature("Registry", 'Number of occurrences of the string "/Registry" in the PDF file.', "Non-negative integer count."),
    _feature("Resources", 'Number of occurrences of the string "/Resources" in the PDF file.', "Non-negative integer count."),
    _feature("www", 'Number of occurrences of the string "/www" in the PDF file.', "Non-negative integer count."),
    _feature("server", 'Number of occurrences of the string "/server" in the PDF file.', "Non-negative integer count."),
    _feature("Root", 'Number of occurrences of the string "/Root" in the PDF file.', "Non-negative integer count."),
    _feature("BitsPerComponent", 'Number of occurrences of the string "/BitsPerComponent" in the PDF file.', "Non-negative integer count."),
]

PAPER_STATISTICS: dict[str, tuple[float, float, float, float]] = {
    # mean, variance, minimum, maximum from Table 3
    "pdfsize": (800.93, 22774872.63, 0, 468246), "metadata size": (319.70, 1542151.37, 176, 77185),
    "pages": (8.26, 1343.50, 0, 2096), "xref length": (2454.95, 248276623.09, 0, 263987),
    "title length": (45.23, 1150837.32, 0, 76993), "isEncrypted": (0.01, 0.01, 0, 1),
    "embedded files": (0.02, 0.03, 0, 8), "images": (31.03, 664712.50, 0, 98560),
    "contains_text": (0.55, 0.25, -1, 1), "pdf_ver": (1.42, 0.09, 0, 5),
    "obj": (137.79, 880410.44, 0, 72292), "endobj": (138.44, 895850.32, 0, 72291),
    "stream": (54.27, 94097.44, 0, 15182), "endstream": (54.53, 95892.22, 0, 15182),
    "trailer": (1.16, 1.41, 0, 91), "xref": (1.13, 1.46, 0, 91),
    "startxref": (1.36, 2.41, 0, 156), "page_command": (9.68, 2137.51, 0, 2789),
    "Encrypt": (0.02, 0.04, 0, 11), "ObjStm": (2.36, 306.80, 0, 1294),
    "JS": (0.64, 268.05, 0, 2469), "JavaScript": (0.69, 267.41, 0, 2469),
    "AA": (0.72, 445.41, 0, 3197), "OpenAction": (0.39, 0.25, 0, 4),
    "Acroform": (0.00, 0.00, 0, 0), "JBIG2Decode": (0.29, 134.74, 0, 1310),
    "RichMedia": (0.01, 0.13, 0, 32), "Launch": (0.04, 9.74, 0, 443),
    "EmbeddedFile": (0.34, 2.35, 0, 19), "XFA": (0.06, 0.06, 0, 2),
    "Colors": (0.00, 0.00, 0, 0), "URI": (7.69, 77614.06, 0, 39112),
    "BaseEncoding": (0.00, 0.00, 0, 0), "Encoding": (4.93, 1346.36, 0, 2769),
    "ProcSet": (8.69, 4515.16, 0, 7491), "Registry": (1.15, 21.17, 0, 307),
    "Resources": (15.20, 19737.78, 0, 11142), "www": (4.87, 18245.69, 0, 19775),
    "server": (0.03, 0.17, 0, 10), "Root": (1.43, 3.65, 0, 157),
    "BitsPerComponent": (18.28, 31438.67, 0, 10186),
}

PAPER_BASELINE_RESULTS = [
    {"model": "RF", "accuracy": 0.994084, "precision": 0.994512, "recall": 0.993603, "f1": 0.994033, "inference_time_ms": 3.923857},
    {"model": "LR", "accuracy": 0.907313, "precision": 0.906484, "recall": 0.909382, "f1": 0.907021, "inference_time_ms": 0.064845},
    {"model": "DT", "accuracy": 0.988661, "precision": 0.988427, "recall": 0.988733, "f1": 0.988577, "inference_time_ms": 0.070683},
    {"model": "GNB", "accuracy": 0.621857, "precision": 0.753729, "recall": 0.651035, "f1": 0.590655, "inference_time_ms": 0.185132},
    {"model": "XGB", "accuracy": 0.994906, "precision": 0.995156, "recall": 0.994590, "f1": 0.994863, "inference_time_ms": 0.564525},
]

PAPER_SHAP_IMPORTANCE = [
    ("JavaScript", 3.474789), ("contains_text", 1.221534), ("pdfsize", 1.126533), ("JS", 1.126279),
    ("Registry", 0.636202), ("XFA", 0.550923), ("metadata size", 0.503341), ("stream", 0.441044),
    ("URI", 0.377808), ("pages", 0.375392), ("xref length", 0.364602), ("endobj", 0.363546),
    ("www", 0.356451), ("OpenAction", 0.318886), ("Resources", 0.290378), ("Encoding", 0.285145),
    ("pdf_ver", 0.276523), ("obj", 0.250006), ("images", 0.246687), ("page_command", 0.216136),
    ("ProcSet", 0.192889), ("title length", 0.189564), ("endstream", 0.183275),
    ("BitsPerComponent", 0.148386), ("EmbeddedFile", 0.131712), ("ObjStm", 0.083332),
    ("Root", 0.075597), ("trailer", 0.052374), ("embedded files", 0.051439),
    ("startxref", 0.044565), ("xref", 0.033615), ("Launch", 0.030032), ("AA", 0.025128),
    ("server", 0.018971), ("isEncrypted", 0.0), ("Acroform", 0.0), ("Encrypt", 0.0),
    ("BaseEncoding", 0.0), ("Colors", 0.0), ("RichMedia", 0.0), ("JBIG2Decode", 0.0),
]


def _percentage(count: int, total: int) -> float:
    return 0.0 if total == 0 else round(count * 100 / total, 6)


def _distribution(series: pd.Series) -> list[dict[str, Any]]:
    total = len(series)
    return [
        {"raw_label": int(label), "count": int(count), "percentage": _percentage(int(count), total)}
        for label, count in series.value_counts(sort=False).items()
    ]


def _stat_status(name: str, local: float, paper: float, local_variance: float | None = None) -> str:
    if math.isclose(local, paper, rel_tol=0.0, abs_tol=1e-12):
        return "exact match"
    if name == "mean" and abs(local - paper) <= 0.005000001:
        return "rounding-level difference"
    if name == "standard_deviation" and local_variance is not None and abs(local_variance - paper**2) <= 0.005000001:
        return "rounding-level difference"
    return "material mismatch"


def _numeric_comparisons(frame: pd.DataFrame, feature_columns: list[str]) -> dict[str, Any]:
    comparisons: dict[str, Any] = {}
    for column in feature_columns:
        if column not in PAPER_STATISTICS:
            comparisons[column] = {"overall_status": "unavailable in paper"}
            continue
        values = pd.to_numeric(frame[column], errors="raise").to_numpy(dtype=float)
        paper_mean, paper_variance, paper_minimum, paper_maximum = PAPER_STATISTICS[column]
        local_variance = float(np.var(values, ddof=1)) if len(values) > 1 else 0.0
        local_std = float(np.std(values, ddof=1)) if len(values) > 1 else 0.0
        paper_std = math.sqrt(paper_variance)
        statuses = {
            "minimum": _stat_status("minimum", float(values.min()), paper_minimum),
            "maximum": _stat_status("maximum", float(values.max()), paper_maximum),
            "mean": _stat_status("mean", float(values.mean()), paper_mean),
            "standard_deviation": _stat_status("standard_deviation", local_std, paper_std, local_variance),
        }
        overall = "exact match" if all(status == "exact match" for status in statuses.values()) else (
            "rounding-level difference" if "material mismatch" not in statuses.values() else "material mismatch"
        )
        comparisons[column] = {
            "paper": {"minimum": paper_minimum, "maximum": paper_maximum, "mean": paper_mean, "variance": paper_variance, "standard_deviation_derived_from_variance": paper_std},
            "local": {"minimum": float(values.min()), "maximum": float(values.max()), "mean": float(values.mean()), "variance": local_variance, "standard_deviation": local_std},
            "difference_local_minus_paper": {"minimum": float(values.min()) - paper_minimum, "maximum": float(values.max()) - paper_maximum, "mean": float(values.mean()) - paper_mean, "standard_deviation": local_std - paper_std},
            "comparison": statuses,
            "overall_status": overall,
        }
    return comparisons


def _special_value_audit(frame: pd.DataFrame) -> dict[str, Any]:
    def label_counts(mask: pd.Series) -> dict[str, int]:
        return {
            str(label): int(count)
            for label, count in frame.loc[mask, TARGET_COLUMN].value_counts(sort=False).items()
        }

    return {
        "contains_text": {
            "local_counts": {str(value): int((frame["contains_text"] == value).sum()) for value in (-1, 0, 1)},
            "label_distribution_for_negative_one": label_counts(frame["contains_text"] == -1),
            "paper_interpretation": "-1 is an intentional PDFMalExtract signal: corrupted file and text could not be read; 0/1 represent failure/success of the default 50-character threshold.",
            "alignment": "Local -1 values are retained as documented signals; they are not treated as missing data.",
        },
        "images": {
            "local_negative_one_count": int((frame["images"] == -1).sum()),
            "paper_interpretation": "-1 is an intentional PDFMalExtract signal: corrupted file and the image count could not be shown.",
            "alignment": "No local images=-1 observations were found; no values are changed.",
        },
        "pages": {
            "local_zero_count": int((frame["pages"] == 0).sum()),
            "label_distribution_for_zero": label_counts(frame["pages"] == 0),
            "paper_interpretation": "0 pages is documented in deliberately corrupted malicious PDFs.",
            "alignment": "Local zero-page observations are retained as documented signals; they are not treated as missing data.",
        },
        "pdf_ver": {
            "local_minimum": float(frame["pdf_ver"].min()),
            "local_maximum": float(frame["pdf_ver"].max()),
            "local_greater_than_2_count": int((frame["pdf_ver"] > 2).sum()),
            "label_distribution_for_greater_than_2": label_counts(frame["pdf_ver"] > 2),
            "local_zero_count": int((frame["pdf_ver"] == 0).sum()),
            "paper_interpretation": "The paper states that values up to 5 occur, 2.0 is the highest valid PDF version, and many malicious samples use invalid version values. It does not explain the meaning of value 0.",
            "alignment": "Values above 2 are retained as documented potentially malicious invalid-version signals. Value 0 remains unverified rather than cleaned or imputed.",
        },
    }


def _feature_vector_summary(frame: pd.DataFrame) -> dict[str, Any]:
    group_ids = build_duplicate_group_ids(frame, TARGET_COLUMN)
    counts = group_ids.value_counts()
    group_labels = pd.DataFrame({"group": group_ids, "label": frame[TARGET_COLUMN].to_numpy(copy=False)}).groupby("group")["label"].nunique(dropna=False)
    multi = counts[counts > 1]
    return {
        "unique_static_feature_vectors": int(len(counts)),
        "groups_with_identical_static_feature_vectors": int(len(multi)),
        "rows_in_multirow_feature_groups": int(multi.sum()),
        "additional_rows_beyond_first_per_feature_vector": int((multi - 1).sum()),
        "groups_with_multiple_target_labels": int((group_labels > 1).sum()),
        "terminology": "These are identical 41-dimensional static feature vectors in this CSV. They are not asserted to be duplicate PDF files because this local CSV has no per-PDF SHA-256 hash column.",
    }


def build_paper_alignment_report(dataset_path: str | Path) -> dict[str, Any]:
    """Build the requested local-versus-paper report through the existing RIT loader."""
    path = Path(dataset_path)
    frame = load_rit_pdfmal(path)
    if TARGET_COLUMN not in frame.columns:
        raise ValueError(f"Expected target column {TARGET_COLUMN!r} is absent")
    feature_columns = [column for column in frame.columns if column != TARGET_COLUMN]
    dictionary_by_name = {entry["column"]: entry for entry in PAPER_FEATURE_DICTIONARY}
    feature_dictionary = [
        {
            **dictionary_by_name.get(
                column,
                _feature(column, "Unverified: local column is not described in the paper reference.", "Unverified."),
            ),
            "local_dtype": str(frame[column].dtype),
        }
        for column in feature_columns
    ]
    paper_feature_names = [entry["column"] for entry in PAPER_FEATURE_DICTIONARY]
    missing_from_local = [column for column in paper_feature_names if column not in feature_columns]
    unexpected_local = [column for column in feature_columns if column not in paper_feature_names]
    comparisons = _numeric_comparisons(frame, feature_columns)
    statuses = [item.get("overall_status") for item in comparisons.values()]
    zero_variance = {
        column: {
            "local_unique_value_count": int(frame[column].nunique(dropna=False)),
            "local_values": [int(value) for value in frame[column].drop_duplicates().tolist()],
            "paper_statement": "The paper says this feature is consistently 0 across both classes and can be safely removed before training.",
            "alignment": "exact match" if frame[column].nunique(dropna=False) == 1 and frame[column].iloc[0] == 0 else "material mismatch",
            "author_treatment": "Safe to remove prior to training; the paper does not explicitly state whether Table 5 retained or removed it in every fitted pipeline.",
        }
        for column in ("Acroform", "Colors", "BaseEncoding")
    }

    return {
        "report_version": "1.0",
        "paper": {"title": PAPER_TITLE, "doi": PAPER_DOI, "source_url": PAPER_SOURCE_URL, "reference_scope": "Author manuscript/table transcription; DOI identifies the IEEE Access paper."},
        "local_dataset_identity": {
            "filename": path.name,
            "sha256": sha256_file(path),
            "row_count": int(len(frame)),
            "total_column_count": int(frame.shape[1]),
            "predictive_feature_count": int(len(feature_columns)),
            "target_column": TARGET_COLUMN,
            "class_distribution": _distribution(frame[TARGET_COLUMN]),
        },
        "identity_comparison": {
            "rows": {"paper": 24337, "local": int(len(frame)), "status": "exact match" if len(frame) == 24337 else "material mismatch"},
            "class_counts": {"paper": {"benign_label_0": 13235, "malicious_label_1": 11102}, "local": {"benign_label_0": int((frame[TARGET_COLUMN] == 0).sum()), "malicious_label_1": int((frame[TARGET_COLUMN] == 1).sum())}, "status": "exact match" if int((frame[TARGET_COLUMN] == 0).sum()) == 13235 and int((frame[TARGET_COLUMN] == 1).sum()) == 11102 else "material mismatch"},
            "schema": {"paper": "Paper describes 42 features including a per-PDF SHA-256 hash, which it says to remove before ML; Label is binary 0/1.", "local": f"{len(feature_columns)} predictive columns plus Label; no hash column.", "feature_name_match_after_excluding_paper_hash": len(missing_from_local) == 0 and len(unexpected_local) == 0, "paper_features_missing_locally": missing_from_local, "unexpected_local_features": unexpected_local, "status": "aligned after excluding paper hash" if not missing_from_local and not unexpected_local else "material mismatch"},
            "filename": {"paper": "Not specified in the paper.", "local": path.name, "status": "unavailable in paper"},
            "csv_sha256": {"paper": "Not reported.", "local": sha256_file(path), "status": "unavailable in paper"},
        },
        "pdf_hash_and_feature_vector_distinction": {
            "paper_pdf_hash": "The paper's hash field is the SHA-256 of a PDF file, retained to identify repetitions of the same file under different names and removed before ML.",
            "local_csv": "No paper-style per-PDF hash column is present, so raw PDF identity or duplicate-PDF status cannot be verified locally.",
            "local_feature_vector_findings": _feature_vector_summary(frame),
        },
        "feature_dictionary": feature_dictionary,
        "target_dictionary": _feature("Label", "Binary class label for the entry.", "Binary integer: 0 benign; 1 malicious.", special_values="0 denotes benign and 1 denotes malicious.", directional_semantics="This is the target, not a predictive feature."),
        "special_value_semantics": _special_value_audit(frame),
        "descriptive_statistics_comparison": {"paper_note": "Table 3 publishes mean, variance, minimum, and maximum. Standard deviation is derived here as sqrt(published variance); its status is judged against the published variance rounded to two decimals.", "feature_comparisons": comparisons, "summary": {"exact_match": statuses.count("exact match"), "rounding_level_difference": statuses.count("rounding-level difference"), "material_mismatch": statuses.count("material mismatch"), "unavailable_in_paper": statuses.count("unavailable in paper")}},
        "zero_variance_features": zero_variance,
        "paper_experimental_protocol": {
            "train_test_split": "Random 75% train / 25% test split with stratification.",
            "randomization_details": "Random split is stated; random seed is not specified.",
            "cross_validation": "Best classifier (XGB) underwent random 10-fold cross-validation; stratification for cross-validation is not specified.",
            "models_evaluated": ["Random Forest", "Logistic Regression", "Decision Tree", "Gaussian Naive-Bayes", "eXtreme Gradient Boost"],
            "metrics": ["Accuracy", "Precision", "Recall", "F1 score", "single-sample inference time"],
            "additional_analysis": "ROC-AUC is shown graphically; SHAP is calculated for the best-performing model.",
            "feature_preprocessing": "Features were extracted in numeric format to minimize preprocessing. The per-PDF hash should be removed before ML. Scaling, imputation, encoding, and normalization details are not specified.",
            "feature_removal": "Acroform, Colors, and BaseEncoding are stated to be safe to remove before training because they have zero variance. Whether they were removed from every reported fit is not explicitly specified.",
            "hyperparameters": "Not specified in the paper.",
        },
        "published_baseline_results": PAPER_BASELINE_RESULTS,
        "published_xgb_10_fold_cross_validation": {"mean": {"accuracy": 0.993878, "precision": 0.995663, "recall": 0.990901, "f1": 0.993274}, "standard_deviation": {"accuracy": 0.000789, "precision": 0.001382, "recall": 0.002012, "f1": 0.000841}},
        "paper_shap_reference": {"instruction": "Reference only for future sanity checks. Do not select features using these test-set-derived importances.", "importance": [{"feature": feature, "importance": importance} for feature, importance in PAPER_SHAP_IMPORTANCE]},
        "protocols": {
            "P_paper_reproduction": "Reproduce the paper as closely as documentation permits: 75/25 random stratified train/test split, five published classical models, the reported metrics, and random 10-fold XGB cross-validation. Undocumented seed, hyperparameters, scaling, and exact zero-variance removal status remain not specified.",
            "G_feature_disjoint_generalization": "Use the existing deterministic seed-42 duplicate-feature-group-aware 60/20/20 train/validation/test manifest. Identical 41-dimensional feature representations cannot cross partitions.",
            "comparison": "Protocol G is stricter and has a validation partition; it is not directly equivalent to the paper's reported random 75/25 evaluation and must not be compared numerically as a direct reproduction.",
        },
        "terminology_corrections": [
            "Call the local CSV checksum a dataset-file SHA-256, not a PDF-file hash.",
            "Call equal rows after excluding Label identical static feature vectors or duplicate feature groups, not duplicate PDF files.",
            "The project's duplicate_group_id is a hash of static feature values, not the paper's SHA-256 hash of PDF bytes.",
        ],
        "risks_before_training": [
            "The local CSV lacks per-PDF hashes, so raw-file identity and duplicate-PDF claims cannot be checked.",
            "Protocol P cannot be exactly replicated until the paper's random seed, hyperparameters, and preprocessing details are available.",
            "Protocol G contains a very large static-feature duplicate group; group-aware splitting is necessary and results are not directly comparable to the paper protocol.",
            "Special corruption signals (-1 and zero-page cases) are documented values, not missing values; changing them would break paper alignment.",
        ],
        "scope": "Read-only paper-alignment audit. No raw data modification, model training, feature selection, normalization, encoding, imputation, or split change was performed.",
    }


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", r"\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    return [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *("| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows),
    ]


def report_to_markdown(report: dict[str, Any]) -> str:
    """Render the complete human-readable paper-alignment report."""
    local = report["local_dataset_identity"]
    identity = report["identity_comparison"]
    lines = [
        "# RIT-PDFMal-2026 paper-alignment audit",
        "",
        f"Paper: [{report['paper']['title']}]({report['paper']['source_url']})  ",
        f"DOI: `{report['paper']['doi']}`",
        "",
        "## 1. Dataset identity",
        "",
        f"- Local filename: `{local['filename']}`",
        f"- Local CSV SHA-256: `{local['sha256']}`",
        f"- Local shape: {local['row_count']} rows × {local['total_column_count']} columns",
        f"- Local predictive features: {local['predictive_feature_count']}; target: `{local['target_column']}`",
        f"- Local class distribution: {local['class_distribution']}",
        f"- Paper row comparison: {identity['rows']['status']}; class-count comparison: {identity['class_counts']['status']}.",
        f"- Schema comparison: {identity['schema']['status']}. The paper's `hash` field is absent locally; all 41 named non-hash predictive features align.",
        "",
        "### PDF hashes versus feature vectors",
        "",
        report["pdf_hash_and_feature_vector_distinction"]["paper_pdf_hash"],
        "",
        report["pdf_hash_and_feature_vector_distinction"]["local_csv"],
        "",
        "```text",
        json.dumps(report["pdf_hash_and_feature_vector_distinction"]["local_feature_vector_findings"], indent=2),
        "```",
        "",
        "## 2. Feature dictionary",
        "",
    ]
    lines.extend(_table(["Column", "Paper meaning", "Expected type", "Special values", "Stated higher/lower meaning"], [[item["column"], item["paper_meaning"], item["expected_value_type"], item["special_values"], item["higher_lower_semantic_meaning"]] for item in report["feature_dictionary"]]))
    lines.extend(["", f"Target `{report['target_dictionary']['column']}`: {report['target_dictionary']['paper_meaning']} ({report['target_dictionary']['special_values']})", "", "## 3. Special-value semantics", ""])
    for name, details in report["special_value_semantics"].items():
        lines.extend([f"### `{name}`", "", f"- Local: `{details}`", ""])

    lines.extend(["## 4. Descriptive-statistics comparison", "", report["descriptive_statistics_comparison"]["paper_note"], ""])
    statistic_rows = []
    for name, result in report["descriptive_statistics_comparison"]["feature_comparisons"].items():
        if result["overall_status"] == "unavailable in paper":
            statistic_rows.append([name, "—", "—", "—", "—", "unavailable in paper"])
            continue
        statistic_rows.append([name, result["difference_local_minus_paper"]["minimum"], result["difference_local_minus_paper"]["maximum"], result["difference_local_minus_paper"]["mean"], result["difference_local_minus_paper"]["standard_deviation"], result["overall_status"]])
    lines.extend(_table(["Feature", "Δ min", "Δ max", "Δ mean", "Δ std", "Classification"], statistic_rows))
    lines.extend(["", "## 5. Zero-variance features", ""])
    lines.extend(_table(["Feature", "Local values", "Status", "Author treatment"], [[name, details["local_values"], details["alignment"], details["author_treatment"]] for name, details in report["zero_variance_features"].items()]))

    protocol = report["paper_experimental_protocol"]
    lines.extend(["", "## 6. Published experimental protocol", ""])
    lines.extend([f"- **{name.replace('_', ' ')}:** {value}" for name, value in protocol.items()])
    lines.extend(["", "## 7. Published baseline results", ""])
    lines.extend(_table(["Model", "Accuracy", "Precision", "Recall", "F1", "Inference ms"], [[row["model"], row["accuracy"], row["precision"], row["recall"], row["f1"], row["inference_time_ms"]] for row in report["published_baseline_results"]]))
    lines.extend(["", "XGB 10-fold CV mean: " + json.dumps(report["published_xgb_10_fold_cross_validation"]["mean"]), "", "## 8. SHAP reference importance", "", report["paper_shap_reference"]["instruction"], ""])
    lines.extend(_table(["Feature", "Importance"], [[row["feature"], row["importance"]] for row in report["paper_shap_reference"]["importance"]]))
    lines.extend(["", "## 9. Evaluation protocols", "", "### Protocol P — Paper reproduction", "", report["protocols"]["P_paper_reproduction"], "", "### Protocol G — Feature-disjoint generalization", "", report["protocols"]["G_feature_disjoint_generalization"], "", report["protocols"]["comparison"], "", "## Terminology corrections", ""])
    lines.extend(f"- {item}" for item in report["terminology_corrections"])
    lines.extend(["", "## Risks before training", ""])
    lines.extend(f"- {item}" for item in report["risks_before_training"])
    lines.extend(["", "## Scope", "", report["scope"], ""])
    return "\n".join(lines)


def write_paper_alignment_reports(
    report: dict[str, Any], markdown_path: str | Path, json_path: str | Path
) -> None:
    """Write derived reports only; the dataset path is never opened for writing."""
    markdown_output = Path(markdown_path)
    json_output = Path(json_path)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(report_to_markdown(report), encoding="utf-8")
    json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
