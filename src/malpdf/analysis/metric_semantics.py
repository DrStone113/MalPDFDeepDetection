"""Report-only correction audit for paper macro versus malicious-class metrics.

The completed Protocol P/G result files keep their historical ``precision``,
``recall``, and ``f1`` fields. Those fields use Label=1 (malicious) as the
positive class. This module derives explicitly named macro metrics from their
saved confusion matrices without fitting a model or generating predictions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from malpdf.analysis.protocol_p_vs_g import (
    DATASET_SHA256,
    REQUIRED_SOURCE_FILES,
    ProtocolComparisonError,
    ProtocolResults,
    load_protocol_baseline_reports,
    verify_committed_baseline_sources,
)
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_BASELINE_RESULTS
from malpdf.evaluation.binary import classification_metrics_from_confusion_counts


PAPER_GNB_TEST_COUNTS = {"benign_label_0": 3309, "malicious_label_1": 2776}
PAPER_GNB_CONFUSION_COUNTS = {"tn": 1052, "fp": 2257, "fn": 44, "tp": 2732}
PAPER_GNB_REPORTED_MALICIOUS_TPR = 0.9841
PAPER_GNB_REPORTED_BENIGN_TNR = 0.3179
PAPER_ROUNDING_TOLERANCE = 1e-6
PAPER_MODEL_NAMES = {
    "logistic_regression": "LR",
    "random_forest": "RF",
    "decision_tree": "DT",
    "gaussian_naive_bayes": "GNB",
    "xgboost": "XGB",
}
PAPER_COMPARISON_FIELDS = ("accuracy", "precision", "recall", "f1")


class MetricSemanticsError(ProtocolComparisonError):
    """Raised when metric-semantics evidence or inputs are inconsistent."""


@dataclass(frozen=True)
class MetricSemanticsPaths:
    """Dedicated output paths that cannot overwrite Protocol P/G baselines."""

    tables_directory: Path
    markdown_analysis: Path


def _paper_result(model: str) -> dict[str, float | str]:
    for row in PAPER_BASELINE_RESULTS:
        if row["model"] == model:
            return row
    raise MetricSemanticsError(f"Verified paper baseline is missing {model}")


def reconstruct_paper_gnb_metrics() -> dict[str, Any]:
    """Reconstruct Table 5 GNB semantics from reported counts and class rates."""
    counts = dict(PAPER_GNB_CONFUSION_COUNTS)
    if counts["tn"] + counts["fp"] != PAPER_GNB_TEST_COUNTS["benign_label_0"]:
        raise MetricSemanticsError("Paper GNB benign reconstruction does not match the reported test count")
    if counts["fn"] + counts["tp"] != PAPER_GNB_TEST_COUNTS["malicious_label_1"]:
        raise MetricSemanticsError("Paper GNB malicious reconstruction does not match the reported test count")
    metrics = classification_metrics_from_confusion_counts(**counts)
    paper = _paper_result("GNB")
    table5 = {metric: float(paper[metric]) for metric in PAPER_COMPARISON_FIELDS}
    malicious = {
        "precision": metrics["precision_malicious"],
        "recall": metrics["recall_malicious"],
        "f1": metrics["f1_malicious"],
    }
    macro = {
        "precision": metrics["precision_macro"],
        "recall": metrics["recall_macro"],
        "f1": metrics["f1_macro"],
    }
    macro_matches = {
        metric: abs(macro[metric] - table5[metric]) <= PAPER_ROUNDING_TOLERANCE
        for metric in macro
    }
    malicious_matches = {
        metric: abs(malicious[metric] - table5[metric]) <= PAPER_ROUNDING_TOLERANCE
        for metric in malicious
    }
    if not all(macro_matches.values()) or any(malicious_matches.values()):
        raise MetricSemanticsError("Paper GNB reconstruction does not support the documented metric distinction")
    if abs(metrics["accuracy"] - table5["accuracy"]) > PAPER_ROUNDING_TOLERANCE:
        raise MetricSemanticsError("Paper GNB reconstruction does not reproduce Table 5 accuracy")
    return {
        "test_class_counts": dict(PAPER_GNB_TEST_COUNTS),
        "confusion_counts": counts,
        "metrics": metrics,
        "paper_table5": table5,
        "reported_rates": {
            "malicious_true_positive_rate": PAPER_GNB_REPORTED_MALICIOUS_TPR,
            "benign_true_negative_rate": PAPER_GNB_REPORTED_BENIGN_TNR,
        },
        "derived_rates": {
            "malicious_true_positive_rate": metrics["recall_malicious"],
            "benign_true_negative_rate": metrics["recall_benign"],
        },
        "macro_matches_table5": macro_matches,
        "malicious_matches_table5": malicious_matches,
    }


def derive_named_metrics_from_results(
    frame: pd.DataFrame, *, protocol: str, partition: str
) -> pd.DataFrame:
    """Add explicit class/macro fields from saved confusion counts only."""
    rows: list[dict[str, Any]] = []
    for _, record in frame.iterrows():
        counts = {name: int(record[name]) for name in ("tn", "fp", "fn", "tp")}
        derived = classification_metrics_from_confusion_counts(**counts)
        for historical_name, explicit_name in (
            ("precision", "precision_malicious"),
            ("recall", "recall_malicious"),
            ("f1", "f1_malicious"),
            ("accuracy", "accuracy"),
        ):
            if not np.isclose(float(record[historical_name]), derived[explicit_name], atol=1e-12, rtol=0):
                raise MetricSemanticsError(
                    f"Saved {protocol} {partition} {historical_name} does not match its confusion matrix"
                )
        rows.append(
            {
                "protocol": protocol,
                "partition": partition,
                "model_name": record["model_name"],
                "feature_variant": record["feature_variant"],
                "accuracy": derived["accuracy"],
                "precision_malicious": derived["precision_malicious"],
                "recall_malicious": derived["recall_malicious"],
                "f1_malicious": derived["f1_malicious"],
                "precision_macro": derived["precision_macro"],
                "recall_macro": derived["recall_macro"],
                "f1_macro": derived["f1_macro"],
                "roc_auc": record["roc_auc"],
                "pr_auc": record["pr_auc"],
                "mcc": record["mcc"],
                **counts,
            }
        )
    return pd.DataFrame(rows)


def paper_metric_semantics_evidence_table() -> pd.DataFrame:
    """Create an auditable numeric demonstration of the GNB macro evidence."""
    reconstruction = reconstruct_paper_gnb_metrics()
    metrics = reconstruction["metrics"]
    paper = reconstruction["paper_table5"]
    rows: list[dict[str, Any]] = []
    for metric in PAPER_COMPARISON_FIELDS:
        malicious_value = None if metric == "accuracy" else metrics[f"{metric}_malicious"]
        macro_value = metrics["accuracy"] if metric == "accuracy" else metrics[f"{metric}_macro"]
        rows.append(
            {
                "evidence_type": "Table 5 reconstruction",
                "metric": metric,
                "paper_table5_value": paper[metric],
                "reconstructed_malicious_positive_value": malicious_value,
                "reconstructed_macro_value": macro_value,
                "macro_minus_paper": macro_value - paper[metric],
                "macro_matches_within_tolerance": abs(macro_value - paper[metric]) <= PAPER_ROUNDING_TOLERANCE,
                "malicious_matches_within_tolerance": (
                    None
                    if malicious_value is None
                    else abs(malicious_value - paper[metric]) <= PAPER_ROUNDING_TOLERANCE
                ),
            }
        )
    rows.extend(
        [
            {
                "evidence_type": "Paper class-rate reconstruction",
                "metric": "malicious_true_positive_rate",
                "paper_table5_value": PAPER_GNB_REPORTED_MALICIOUS_TPR,
                "reconstructed_malicious_positive_value": metrics["recall_malicious"],
                "reconstructed_macro_value": None,
                "macro_minus_paper": metrics["recall_malicious"] - PAPER_GNB_REPORTED_MALICIOUS_TPR,
                "macro_matches_within_tolerance": None,
                "malicious_matches_within_tolerance": (
                    abs(metrics["recall_malicious"] - PAPER_GNB_REPORTED_MALICIOUS_TPR) <= 0.0001
                ),
            },
            {
                "evidence_type": "Paper class-rate reconstruction",
                "metric": "benign_true_negative_rate",
                "paper_table5_value": PAPER_GNB_REPORTED_BENIGN_TNR,
                "reconstructed_malicious_positive_value": metrics["recall_benign"],
                "reconstructed_macro_value": None,
                "macro_minus_paper": metrics["recall_benign"] - PAPER_GNB_REPORTED_BENIGN_TNR,
                "macro_matches_within_tolerance": None,
                "malicious_matches_within_tolerance": (
                    abs(metrics["recall_benign"] - PAPER_GNB_REPORTED_BENIGN_TNR) <= 0.0001
                ),
            },
        ]
    )
    return pd.DataFrame(rows)


def metric_definition_map() -> pd.DataFrame:
    """Describe non-destructive historical aliases and corrected paper mapping."""
    return pd.DataFrame(
        [
            {
                "paper_table5_metric": "accuracy",
                "local_historical_field": "accuracy",
                "local_corrected_comparison_field": "accuracy",
                "local_operational_field": "accuracy",
                "semantics": "Overall correct classifications.",
            },
            {
                "paper_table5_metric": "precision",
                "local_historical_field": "precision",
                "local_corrected_comparison_field": "precision_macro",
                "local_operational_field": "precision_malicious",
                "semantics": "Paper Table 5 is compared to macro precision; historical precision remains Label=1 malicious-positive.",
            },
            {
                "paper_table5_metric": "recall",
                "local_historical_field": "recall",
                "local_corrected_comparison_field": "recall_macro",
                "local_operational_field": "recall_malicious",
                "semantics": "Paper Table 5 is compared to macro recall; historical recall remains Label=1 malicious-positive.",
            },
            {
                "paper_table5_metric": "f1",
                "local_historical_field": "f1",
                "local_corrected_comparison_field": "f1_macro",
                "local_operational_field": "f1_malicious",
                "semantics": "Paper Table 5 is compared to macro F1; historical F1 remains Label=1 malicious-positive.",
            },
            {
                "paper_table5_metric": "not reported in Table 5",
                "local_historical_field": "roc_auc / pr_auc / mcc",
                "local_corrected_comparison_field": "unchanged",
                "local_operational_field": "roc_auc / pr_auc / mcc",
                "semantics": "ROC-AUC and PR-AUC retain Label=1 score semantics; MCC remains binary and unchanged.",
            },
        ]
    )


def corrected_paper_comparison(protocol_p_macro_metrics: pd.DataFrame) -> pd.DataFrame:
    """Compare Table 5 to Protocol P test with equivalent macro P/R/F semantics."""
    paper_by_model = {row["model"]: row for row in PAPER_BASELINE_RESULTS}
    rows: list[dict[str, Any]] = []
    for _, local in protocol_p_macro_metrics.iterrows():
        paper_model = PAPER_MODEL_NAMES[local["model_name"]]
        paper = paper_by_model[paper_model]
        row: dict[str, Any] = {
            "protocol": "P",
            "partition": "test",
            "model": local["model_name"],
            "paper_model": paper_model,
            "feature_variant": local["feature_variant"],
            "paper_accuracy": paper["accuracy"],
            "local_accuracy": local["accuracy"],
            "accuracy_delta_local_minus_paper": local["accuracy"] - paper["accuracy"],
            "paper_precision_macro": paper["precision"],
            "local_precision_macro": local["precision_macro"],
            "precision_macro_delta_local_minus_paper": local["precision_macro"] - paper["precision"],
            "paper_recall_macro": paper["recall"],
            "local_recall_macro": local["recall_macro"],
            "recall_macro_delta_local_minus_paper": local["recall_macro"] - paper["recall"],
            "paper_f1_macro": paper["f1"],
            "local_f1_macro": local["f1_macro"],
            "f1_macro_delta_local_minus_paper": local["f1_macro"] - paper["f1"],
            "local_precision_malicious": local["precision_malicious"],
            "local_recall_malicious": local["recall_malicious"],
            "local_f1_malicious": local["f1_malicious"],
        }
        rows.append(row)
    return pd.DataFrame(rows)


def build_metric_semantics_tables(results: ProtocolResults) -> dict[str, pd.DataFrame]:
    """Derive every corrected table only from saved P/G confusion matrices."""
    p_metrics = derive_named_metrics_from_results(
        results.protocol_p_test, protocol="P", partition="test"
    )
    g_validation = derive_named_metrics_from_results(
        results.protocol_g_validation, protocol="G", partition="validation"
    )
    g_test = derive_named_metrics_from_results(results.protocol_g_test, protocol="G", partition="test")
    g_metrics = pd.concat([g_validation, g_test], ignore_index=True)
    return {
        "paper_metric_semantics_evidence": paper_metric_semantics_evidence_table(),
        "protocol_p_macro_metrics": p_metrics,
        "protocol_g_macro_metrics": g_metrics,
        "paper_comparison_corrected": corrected_paper_comparison(p_metrics),
        "metric_definition_map": metric_definition_map(),
    }


def metric_semantics_output_paths(repository_root: str | Path) -> MetricSemanticsPaths:
    """Return separate, tracked outputs for the methodology correction."""
    root = Path(repository_root).resolve()
    return MetricSemanticsPaths(
        tables_directory=root / "reports" / "tables" / "metric_semantics",
        markdown_analysis=root / "reports" / "analysis" / "paper_metric_semantics_correction.md",
    )


def _format(value: float) -> str:
    return f"{float(value):.6f}"


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    return "\n".join(
        [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
            *("| " + " | ".join(row) + " |" for row in rows),
        ]
    )


def build_metric_semantics_markdown(tables: dict[str, pd.DataFrame]) -> str:
    """Render the thesis correction note from computed evidence/tables."""
    evidence = tables["paper_metric_semantics_evidence"]
    corrected = tables["paper_comparison_corrected"]
    p_macro = tables["protocol_p_macro_metrics"]
    gnb = corrected.loc[
        (corrected["model"] == "gaussian_naive_bayes")
        & (corrected["feature_variant"] == "P-all41")
    ].iloc[0]
    gnb_operational_precision_gap = gnb["local_precision_malicious"] - gnb["paper_precision_macro"]
    gnb_operational_recall_gap = gnb["local_recall_malicious"] - gnb["paper_recall_macro"]
    gnb_operational_f1_gap = gnb["local_f1_malicious"] - gnb["paper_f1_macro"]
    gnb_rows = [
        [
            "Accuracy",
            _format(gnb["paper_accuracy"]),
            _format(gnb["local_accuracy"]),
            _format(gnb["accuracy_delta_local_minus_paper"]),
        ],
        [
            "Precision (macro)",
            _format(gnb["paper_precision_macro"]),
            _format(gnb["local_precision_macro"]),
            _format(gnb["precision_macro_delta_local_minus_paper"]),
        ],
        [
            "Recall (macro)",
            _format(gnb["paper_recall_macro"]),
            _format(gnb["local_recall_macro"]),
            _format(gnb["recall_macro_delta_local_minus_paper"]),
        ],
        [
            "F1 (macro)",
            _format(gnb["paper_f1_macro"]),
            _format(gnb["local_f1_macro"]),
            _format(gnb["f1_macro_delta_local_minus_paper"]),
        ],
    ]
    evidence_rows = []
    for _, row in evidence.loc[evidence["evidence_type"] == "Table 5 reconstruction"].iterrows():
        evidence_rows.append(
            [
                row["metric"],
                _format(row["paper_table5_value"]),
                "n/a" if pd.isna(row["reconstructed_malicious_positive_value"]) else _format(row["reconstructed_malicious_positive_value"]),
                _format(row["reconstructed_macro_value"]),
                str(row["macro_matches_within_tolerance"]),
            ]
        )
    all_model_rows = []
    for _, row in corrected.iterrows():
        all_model_rows.append(
            [
                row["paper_model"],
                row["feature_variant"],
                _format(row["accuracy_delta_local_minus_paper"]),
                _format(row["precision_macro_delta_local_minus_paper"]),
                _format(row["recall_macro_delta_local_minus_paper"]),
                _format(row["f1_macro_delta_local_minus_paper"]),
            ]
        )
    p_g_semantics = (
        "The Protocol P-versus-G comparison remains unchanged: both completed local baselines used "
        "Label=1 malicious-positive Precision, Recall, and F1, so their direct local-to-local deltas "
        "retain one consistent definition. The correction applies to comparisons with paper Table 5."
    )
    return "\n".join(
        [
            "# Paper metric-semantics correction",
            "",
            "## 1. Background",
            "",
            "The completed RIT-PDFMal-2026 baselines preserve their original operational reporting convention: Label=1 (malicious) is the positive class. This audit adds a non-destructive macro-metric view for paper comparison; it does not change stored predictions, split assignments, or historical baseline result files.",
            "",
            "## 2. Metric definitions used locally",
            "",
            "- `precision_malicious`, `recall_malicious`, and `f1_malicious` refer to Label=1. Historical `precision`, `recall`, and `f1` remain backward-compatible aliases for those malicious-positive values.",
            "- `precision_macro`, `recall_macro`, and `f1_macro` average the benign and malicious class metrics with equal class weight.",
            "- Accuracy is unchanged. ROC-AUC and PR-AUC retain Label=1 score semantics; MCC remains a binary metric and is unchanged.",
            "",
            "## 3. Metric definitions stated in the paper",
            "",
            "The paper's metric-definition section presents binary formulas, while its Table 5 GNB numerical values do not equal the malicious-class values reconstructed from the reported class rates and confusion information. The available evidence is therefore insufficient to treat Table 5 Precision, Recall, and F1 as malicious-positive metrics.",
            "",
            "## 4. Numerical inconsistency observed",
            "",
            "The reconstructed GNB malicious true-positive rate is approximately 98.41% and benign true-negative rate approximately 31.79%. These class-specific rates are compatible with the paper's reported behavior but not with Table 5 Precision, Recall, and F1 when those columns are read as malicious-positive metrics.",
            "",
            "## 5. GNB confusion-matrix reconstruction",
            "",
            "The paper test class counts are 3,309 benign and 2,776 malicious. The reported confusion-matrix information reconstructs as TN=1,052, FP=2,257, FN=44, TP=2,732. The following computation uses only these counts:",
            "",
            _markdown_table(
                ["Metric", "Paper Table 5", "Malicious-positive", "Macro", "Macro matches Table 5"],
                evidence_rows,
            ),
            "",
            "## 6. Evidence for macro averaging",
            "",
            "For GNB, macro Precision, Recall, and F1 reconstructed from the paper counts match the Table 5 values within a 1e-6 rounding tolerance, while the malicious-positive values do not. This is numerical evidence for macro averaging in Table 5; it does not establish why the paper's narrative formulas and reported table differ.",
            "",
            "## 7. Corrected paper-comparison methodology",
            "",
            "Paper Accuracy is compared with local Accuracy. Paper Precision, Recall, and F1 are compared with local macro Precision, Recall, and F1, respectively. Local malicious-positive metrics remain separately reported because they are operational malware-detection metrics. The full mapping is in `reports/tables/metric_semantics/metric_definition_map.csv`.",
            "",
            "## 8. Impact on previous conclusions",
            "",
            p_g_semantics,
            "",
            "The prior P-vs-G analysis now explicitly records this distinction. Its local P-versus-G conclusions do not change, because both sides use the same malicious-positive convention.",
            "",
            "## 9. Residual GNB discrepancy",
            "",
            _markdown_table(["Metric", "Paper", "Local P macro", "Local minus paper"], gnb_rows),
            "",
            f"Before semantic alignment, the Local P GNB malicious-positive Precision/Recall/F1 differences from the paper values were {_format(gnb_operational_precision_gap)}, {_format(gnb_operational_recall_gap)}, and {_format(gnb_operational_f1_gap)}. After macro-to-macro comparison, the residual differences are {_format(gnb['precision_macro_delta_local_minus_paper'])}, {_format(gnb['recall_macro_delta_local_minus_paper'])}, and {_format(gnb['f1_macro_delta_local_minus_paper'])}. Thus much of the previous P/R/F discrepancy is metric-definition mismatch, while residual differences remain and cannot be assigned to one cause from these results alone.",
            "",
            "## 10. All-model corrected comparison",
            "",
            _markdown_table(
                ["Model", "Variant", "Accuracy delta", "Macro precision delta", "Macro recall delta", "Macro F1 delta"],
                all_model_rows,
            ),
            "",
            "## 11. Implications for future experiments",
            "",
            "Future result schemas expose both malicious-positive and macro metrics. Future paper-comparison tables must map Table 5 P/R/F to macro fields, preserve malicious-positive fields for security operations, and retain the metric-definition note. Remaining differences may reflect the unreported paper split seed, hyperparameters, preprocessing, software behavior, or other undocumented methodology; no tuning was performed in this audit.",
            "",
        ]
    )


def _outputs_exist(paths: MetricSemanticsPaths) -> bool:
    return paths.markdown_analysis.exists() or (
        paths.tables_directory.is_dir() and any(paths.tables_directory.iterdir())
    )


def write_metric_semantics_outputs(
    tables: dict[str, pd.DataFrame], paths: MetricSemanticsPaths, *, overwrite: bool = False
) -> list[Path]:
    """Write supplementary tables/analysis only, never baseline metric files."""
    if _outputs_exist(paths) and not overwrite:
        raise FileExistsError("Metric-semantics output already exists; use explicit overwrite for analysis outputs")
    paths.tables_directory.mkdir(parents=True, exist_ok=True)
    paths.markdown_analysis.parent.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for name, table in tables.items():
        path = paths.tables_directory / f"{name}.csv"
        table.to_csv(path, index=False, float_format="%.12g")
        outputs.append(path)
    paths.markdown_analysis.write_text(build_metric_semantics_markdown(tables), encoding="utf-8")
    outputs.append(paths.markdown_analysis)
    return outputs


def run_metric_semantics_audit(
    repository_root: str | Path, *, overwrite: bool = False
) -> tuple[MetricSemanticsPaths, dict[str, pd.DataFrame], dict[str, str]]:
    """Verify committed P/G sources and write a report-only semantics correction."""
    root = Path(repository_root).resolve()
    p_directory = root / "reports" / "experiments" / "protocol_p" / "seed42"
    g_directory = root / "reports" / "experiments" / "protocol_g" / "seed42"
    provenance = verify_committed_baseline_sources(root)
    source_paths = [
        *(p_directory / name for name in REQUIRED_SOURCE_FILES["P"]),
        *(g_directory / name for name in REQUIRED_SOURCE_FILES["G"]),
    ]
    source_bytes = {path: path.read_bytes() for path in source_paths}
    results = load_protocol_baseline_reports(p_directory, g_directory)
    if results.provenance["dataset_sha256"] != DATASET_SHA256:
        raise MetricSemanticsError("Metric-semantics audit dataset provenance does not match")
    tables = build_metric_semantics_tables(results)
    paths = metric_semantics_output_paths(root)
    write_metric_semantics_outputs(tables, paths, overwrite=overwrite)
    changed = [path for path, content in source_bytes.items() if path.read_bytes() != content]
    if changed:
        raise MetricSemanticsError(f"Historical Protocol P/G result files were modified: {changed}")
    return paths, tables, provenance
