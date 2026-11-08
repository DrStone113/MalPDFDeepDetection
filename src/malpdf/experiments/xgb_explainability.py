"""Native XGBoost TreeSHAP analysis for the established Protocol G detector.

The official execution is deliberately narrow: it retrains only the frozen
seed-42 XGBoost G-drop3constant model on the saved Protocol G train partition,
verifies its test result against the committed baseline, and explains test rows
only.  SHAP output is descriptive and never feeds model or feature selection.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import PAPER_FEATURE_DICTIONARY, PAPER_SHAP_IMPORTANCE, TARGET_COLUMN
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids
from malpdf.evaluation.binary import classification_metrics_from_confusion_counts, evaluate_binary_predictions
from malpdf.experiments.protocol_g_benchmark import (
    G_DROP3CONSTANT, ProtocolGBenchmarkError, load_saved_protocol_g_split,
    protocol_g_feature_columns, protocol_g_feature_view, split_frame_from_protocol_g_manifest,
)
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import create_model, model_configurations
from malpdf.reproducibility import set_random_seed

EXPERIMENT_NAME = "xgb_protocol_g_seed42_explainability"
RUN_ID = "protocol-g-seed42"
REPORT_DIRECTORY_NAME = "xgb_protocol_g_seed42"
DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
SPLIT_MANIFEST_SHA256 = "802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21"
MODEL_NAME = "xgboost"
MODEL_RANDOM_STATE = 42
TOP_FEATURE_COUNT = 10
PROBABILITY_BANDS = ((0.0, 0.1), (0.1, 0.3), (0.3, 0.5), (0.5, 0.7), (0.7, 0.9), (0.9, 1.0))


class ExplainabilityError(RuntimeError):
    """Raised when a reproducibility or TreeSHAP invariant is not satisfied."""


@dataclass(frozen=True)
class ExplainabilityPaths:
    reports_directory: Path
    figures_directory: Path
    run_metadata_json: Path
    model_config_json: Path
    dataset_provenance_json: Path
    metric_verification_json: Path
    global_importance_csv: Path
    class_conditional_csv: Path
    confusion_groups_csv: Path
    probability_bands_csv: Path
    paper_comparison_csv: Path
    analysis_markdown: Path
    bar_figure: Path
    distribution_figure: Path
    class_figure: Path
    errors_figure: Path


@dataclass(frozen=True)
class ExplainabilityPreflight:
    repository_root: Path
    dataset_path: Path
    frame: pd.DataFrame
    partitions: dict[str, pd.DataFrame]
    split_summary: dict[str, Any]
    historical_record: dict[str, Any]
    feature_columns: tuple[str, ...]
    environment: dict[str, Any]
    code_commit: str
    paths: ExplainabilityPaths


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def explainability_paths(repository_root: str | Path, run_id: str = RUN_ID) -> ExplainabilityPaths:
    """Return isolated paths; only the canonical official run ID is accepted."""
    if run_id != RUN_ID:
        raise ExplainabilityError(f"Only immutable run_id {RUN_ID!r} is permitted for this official analysis")
    root = Path(repository_root).resolve()
    reports = root / "reports" / "experiments" / "explainability" / REPORT_DIRECTORY_NAME
    figures = root / "reports" / "figures" / "explainability"
    return ExplainabilityPaths(
        reports_directory=reports, figures_directory=figures,
        run_metadata_json=reports / "run_metadata.json", model_config_json=reports / "model_config.json",
        dataset_provenance_json=reports / "dataset_provenance.json", metric_verification_json=reports / "metric_verification.json",
        global_importance_csv=reports / "shap_global_importance.csv", class_conditional_csv=reports / "shap_class_conditional.csv",
        confusion_groups_csv=reports / "shap_confusion_groups.csv", probability_bands_csv=reports / "shap_probability_bands.csv",
        paper_comparison_csv=reports / "paper_shap_comparison.csv",
        analysis_markdown=root / "reports" / "analysis" / "xgb_protocol_g_explainability.md",
        bar_figure=figures / "xgb_protocol_g_shap_bar.png", distribution_figure=figures / "xgb_protocol_g_shap_distribution.png",
        class_figure=figures / "xgb_protocol_g_shap_by_class.png", errors_figure=figures / "xgb_protocol_g_shap_errors.png",
    )


def _historical_xgb_record(repository_root: Path) -> dict[str, Any]:
    path = repository_root / "reports" / "experiments" / "protocol_g" / "seed42" / "metrics.json"
    if not path.is_file():
        raise FileNotFoundError(f"Committed Protocol G metrics are unavailable: {path}")
    records = json.loads(path.read_text(encoding="utf-8")).get("runs", [])
    matching = [record for record in records if record.get("model_name") == MODEL_NAME and record.get("feature_variant") == G_DROP3CONSTANT and record.get("status") == "completed"]
    if len(matching) != 1:
        raise ExplainabilityError("Expected exactly one completed historical Protocol G XGBoost G-drop3constant record")
    return matching[0]


def _assert_output_available(paths: ExplainabilityPaths) -> None:
    protected = {"protocol_p", "protocol_g", "multiseed", "xgb_cv10"}
    if set(part.casefold() for part in paths.reports_directory.parts) & protected:
        raise ExplainabilityError("Explainability outputs must not overlap historical experiment directories")
    if paths.reports_directory.exists() or paths.analysis_markdown.exists() or any(path.exists() for path in (paths.bar_figure, paths.distribution_figure, paths.class_figure, paths.errors_figure)):
        raise FileExistsError("Explainability output path already exists; refusing to overwrite official results")


def preflight_xgb_explainability(
    repository_root: str | Path, dataset_path: str | Path, *, run_id: str = RUN_ID, require_clean_git: bool = True
) -> ExplainabilityPreflight:
    """Load and validate the historical split/model identity without fitting anything."""
    root, data_path = Path(repository_root).resolve(), Path(dataset_path).resolve()
    state = repository_git_state(root)
    if require_clean_git and state.get("status") != "clean":
        raise ExplainabilityError("Refusing explainability execution because the repository is not clean")
    paths = explainability_paths(root, run_id)
    _assert_output_available(paths)
    frame = load_rit_pdfmal(data_path)
    if sha256_file(data_path) != DATASET_SHA256 or len(frame) != 24_337:
        raise ExplainabilityError("RIT dataset identity does not match the established Protocol G baseline")
    manifest_path, manifest, split_summary = load_saved_protocol_g_split(frame, DATASET_SHA256, root, seed=42)
    if split_summary["split_manifest_sha256"] != SPLIT_MANIFEST_SHA256 or sha256_file(manifest_path) != SPLIT_MANIFEST_SHA256:
        raise ExplainabilityError("Saved Protocol G split manifest checksum does not match the established baseline")
    partitions = split_frame_from_protocol_g_manifest(frame, manifest)
    features = tuple(protocol_g_feature_columns(frame, G_DROP3CONSTANT))
    if len(features) != 38 or {"Acroform", "Colors", "BaseEncoding"}.intersection(features):
        raise ExplainabilityError("Explainability feature variant must be exactly G-drop3constant with 38 features")
    historical = _historical_xgb_record(root)
    if historical["model_configuration"] != model_configurations(MODEL_RANDOM_STATE)[MODEL_NAME]:
        raise ExplainabilityError("Current XGBoost configuration differs from the committed historical Protocol G record")
    environment = collect_environment_metadata(data_path, root)
    environment["git_working_tree"] = state
    code_commit = str(environment["git_commit_sha"])
    if require_clean_git and (code_commit == "unavailable" or len(code_commit) != 40):
        raise ExplainabilityError("A full clean explainability code commit is required")
    return ExplainabilityPreflight(root, data_path, frame, partitions, split_summary, historical, features, environment, code_commit, paths)


def native_treeshap_contributions(estimator: Any, features: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Return feature contributions, bias, raw margin, and malicious probability from native XGBoost."""
    try:
        import xgboost as xgb
    except ImportError as error:
        raise ExplainabilityError("XGBoost dependency is unavailable") from error
    booster = estimator.get_booster()
    matrix = xgb.DMatrix(features, feature_names=list(features.columns))
    contributions = np.asarray(booster.predict(matrix, pred_contribs=True, validate_features=True), dtype=float)
    margins = np.asarray(booster.predict(matrix, output_margin=True, validate_features=True), dtype=float)
    probabilities = np.asarray(estimator.predict_proba(features)[:, 1], dtype=float)
    if contributions.ndim != 2 or contributions.shape != (len(features), features.shape[1] + 1):
        raise ExplainabilityError("Native XGBoost pred_contribs shape is not N x (features + bias)")
    return contributions[:, :-1], contributions[:, -1], margins, probabilities


def verify_treeshap_identity(feature_contributions: np.ndarray, bias: np.ndarray, margins: np.ndarray, probabilities: np.ndarray, *, tolerance: float = 2e-5) -> dict[str, Any]:
    """Prove native contribution sums reconstruct margin and sigmoid reconstructs probability.

    Native XGBoost prediction arrays are float precision; the fixed absolute
    tolerance accommodates observed contribution-summation rounding without
    weakening the separate probability identity check.
    """
    reconstructed = feature_contributions.sum(axis=1) + bias
    sigmoid = 1.0 / (1.0 + np.exp(-np.clip(margins, -709, 709)))
    margin_error = np.abs(reconstructed - margins)
    probability_error = np.abs(sigmoid - probabilities)
    result = {
        "contribution_shape": [int(size) for size in feature_contributions.shape], "bias_shape": [int(size) for size in bias.shape],
        "maximum_abs_margin_reconstruction_error": float(margin_error.max()), "maximum_abs_probability_reconstruction_error": float(probability_error.max()),
        "tolerance": tolerance,
        "sum_feature_contributions_plus_bias_matches_raw_margin": bool(np.allclose(reconstructed, margins, rtol=tolerance, atol=tolerance)),
        "sigmoid_raw_margin_matches_malicious_probability": bool(np.allclose(sigmoid, probabilities, rtol=tolerance, atol=tolerance)),
    }
    if not result["sum_feature_contributions_plus_bias_matches_raw_margin"] or not result["sigmoid_raw_margin_matches_malicious_probability"]:
        raise ExplainabilityError(f"TreeSHAP mathematical verification failed: {result}")
    return result


def _value_summary(values: pd.Series) -> dict[str, float]:
    return {"min": float(values.min()), "max": float(values.max()), "mean": float(values.mean()), "median": float(values.median()), "std": float(values.std(ddof=1)), "zero_fraction": float((values == 0).mean())}


def global_importance(features: pd.DataFrame, contributions: np.ndarray, labels: pd.Series) -> pd.DataFrame:
    """Rank every feature by mean absolute TreeSHAP with deterministic feature-name tiebreaking."""
    rows = []
    for index, feature in enumerate(features.columns):
        values, shap = features[feature], contributions[:, index]
        row = {"feature": feature, "mean_abs_shap": float(np.mean(np.abs(shap))), "mean_shap": float(np.mean(shap)), "std_shap": float(np.std(shap, ddof=1)), "median_abs_shap": float(np.median(np.abs(shap))), **{f"overall_value_{name}": value for name, value in _value_summary(values).items()}}
        for label, name in ((0, "benign"), (1, "malicious")):
            mask = labels.to_numpy() == label
            row.update({f"{name}_value_{key}": value for key, value in _value_summary(values.loc[mask]).items()})
        rows.append(row)
    result = pd.DataFrame(rows).sort_values(["mean_abs_shap", "feature"], ascending=[False, True], kind="mergesort").reset_index(drop=True)
    result.insert(0, "rank", np.arange(1, len(result) + 1))
    return result


def class_conditional_importance(features: Sequence[str], contributions: np.ndarray, labels: pd.Series, overall: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for index, feature in enumerate(features):
        benign, malicious = contributions[labels.to_numpy() == 0, index], contributions[labels.to_numpy() == 1, index]
        rows.append({"feature": feature, "overall_mean_abs_shap": float(overall.loc[overall.feature == feature, "mean_abs_shap"].iloc[0]), "benign_mean_abs_shap": float(np.mean(np.abs(benign))), "malicious_mean_abs_shap": float(np.mean(np.abs(malicious))), "benign_mean_shap": float(np.mean(benign)), "malicious_mean_shap": float(np.mean(malicious)), "overall_rank": int(overall.loc[overall.feature == feature, "rank"].iloc[0])})
    return pd.DataFrame(rows).sort_values("overall_rank").reset_index(drop=True)


def confusion_group_importance(features: Sequence[str], contributions: np.ndarray, values: pd.DataFrame, truth: pd.Series, predicted: np.ndarray, probabilities: np.ndarray) -> pd.DataFrame:
    groups = {"true_negative": (truth.to_numpy() == 0) & (predicted == 0), "false_positive": (truth.to_numpy() == 0) & (predicted == 1), "false_negative": (truth.to_numpy() == 1) & (predicted == 0), "true_positive": (truth.to_numpy() == 1) & (predicted == 1)}
    rows = []
    for group, mask in groups.items():
        for index, feature in enumerate(features):
            shap = contributions[mask, index]
            rows.append({"group": group, "count": int(mask.sum()), "average_predicted_malicious_probability": float(np.mean(probabilities[mask])), "feature": feature, "mean_abs_shap": float(np.mean(np.abs(shap))), "mean_shap": float(np.mean(shap)), "feature_mean": float(values.loc[mask, feature].mean()), "feature_median": float(values.loc[mask, feature].median())})
    return pd.DataFrame(rows).sort_values(["group", "mean_abs_shap", "feature"], ascending=[True, False, True], kind="mergesort").reset_index(drop=True)


def probability_band_importance(features: Sequence[str], contributions: np.ndarray, probabilities: np.ndarray) -> pd.DataFrame:
    rows = []
    for lower, upper in PROBABILITY_BANDS:
        mask = (probabilities >= lower) & ((probabilities < upper) if upper < 1 else (probabilities <= upper))
        for index, feature in enumerate(features):
            rows.append({"band": f"{lower:.2f}-{upper:.2f}", "lower": lower, "upper": upper, "count": int(mask.sum()), "feature": feature, "mean_abs_shap": None if not mask.any() else float(np.mean(np.abs(contributions[mask, index])),), "mean_shap": None if not mask.any() else float(np.mean(contributions[mask, index]))})
    return pd.DataFrame(rows)


def verify_historical_result(metrics: dict[str, Any], historical_record: dict[str, Any], *, tolerance: float = 1e-12) -> dict[str, Any]:
    """Compare new held-out results against the authoritative committed G record."""
    expected = historical_record["test"]["metrics"]
    expected_counts = historical_record["test"]["confusion_counts"]
    observed_counts = {"tn": int(metrics["confusion_matrix"][0][0]), "fp": int(metrics["confusion_matrix"][0][1]), "fn": int(metrics["confusion_matrix"][1][0]), "tp": int(metrics["confusion_matrix"][1][1])}
    historical_macro = classification_metrics_from_confusion_counts(**expected_counts)["f1_macro"]
    checks = {name: math.isclose(float(metrics[name]), float(expected[name]), rel_tol=tolerance, abs_tol=tolerance) for name in ("accuracy", "f1", "mcc")}
    checks["f1_macro"] = math.isclose(float(metrics["f1_macro"]), float(historical_macro), rel_tol=tolerance, abs_tol=tolerance)
    checks["confusion_counts"] = observed_counts == expected_counts
    checks["test_row_count"] = sum(observed_counts.values()) == sum(expected_counts.values()) == 4867
    result = {"tolerance": tolerance, "historical_metrics": {**{name: expected[name] for name in ("accuracy", "f1", "mcc")}, "f1_macro": historical_macro}, "local_metrics": {name: metrics[name] for name in ("accuracy", "f1", "mcc", "f1_macro")}, "historical_confusion_counts": expected_counts, "local_confusion_counts": observed_counts, "checks": checks, "matches": all(checks.values())}
    if not result["matches"]:
        raise ExplainabilityError(f"Retrained model does not reproduce committed Protocol G XGBoost result: {result}")
    return result


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _make_figures(paths: ExplainabilityPaths, features: pd.DataFrame, contributions: np.ndarray, overall: pd.DataFrame, conditional: pd.DataFrame, groups: pd.DataFrame) -> None:
    paths.figures_directory.mkdir(parents=True, exist_ok=True)
    top = overall.head(15).iloc[::-1]
    fig, axis = plt.subplots(figsize=(8, 6)); axis.barh(top["feature"], top["mean_abs_shap"], color="#1f77b4"); axis.set_xlabel("Mean absolute TreeSHAP contribution to malicious margin"); axis.set_title("XGBoost Protocol G: global feature importance"); fig.tight_layout(); fig.savefig(paths.bar_figure, dpi=180); plt.close(fig)
    shown = overall.head(10)["feature"].tolist(); fig, axes = plt.subplots(2, 5, figsize=(15, 6), squeeze=False)
    for axis, feature in zip(axes.flat, shown, strict=True):
        index = features.columns.get_loc(feature); axis.scatter(features[feature], contributions[:, index], s=4, alpha=.22, color="#1f77b4", linewidths=0); axis.axhline(0, color="black", linewidth=.5); axis.set_title(feature); axis.set_xlabel("Raw value"); axis.set_ylabel("SHAP")
    fig.suptitle("TreeSHAP contribution distributions on Protocol G test rows", y=1.02); fig.tight_layout(); fig.savefig(paths.distribution_figure, dpi=180, bbox_inches="tight"); plt.close(fig)
    class_top = conditional.head(12).iloc[::-1]; fig, axis = plt.subplots(figsize=(9, 6)); y = np.arange(len(class_top)); axis.barh(y - .18, class_top["benign_mean_abs_shap"], .36, label="True benign", color="#4c78a8"); axis.barh(y + .18, class_top["malicious_mean_abs_shap"], .36, label="True malicious", color="#e45756"); axis.set_yticks(y, class_top["feature"]); axis.set_xlabel("Mean absolute TreeSHAP"); axis.set_title("Class-conditional model contributions"); axis.legend(); fig.tight_layout(); fig.savefig(paths.class_figure, dpi=180); plt.close(fig)
    errors = groups.loc[groups.group.isin(["false_positive", "false_negative"])].copy(); ranks = errors.groupby("feature", sort=False)["mean_abs_shap"].mean().sort_values(ascending=False).head(12).index; matrix = errors.loc[errors.feature.isin(ranks)].pivot(index="group", columns="feature", values="mean_abs_shap").reindex(index=["false_positive", "false_negative"], columns=ranks); fig, axis = plt.subplots(figsize=(10, 3)); image = axis.imshow(matrix.to_numpy(), aspect="auto", cmap="Blues"); axis.set_xticks(np.arange(len(ranks)), ranks, rotation=45, ha="right"); axis.set_yticks([0, 1], ["False positive", "False negative"]); axis.set_title("Error-group mean absolute TreeSHAP"); fig.colorbar(image, ax=axis, label="Mean absolute SHAP"); fig.tight_layout(); fig.savefig(paths.errors_figure, dpi=180); plt.close(fig)


def _paper_comparison(overall: pd.DataFrame) -> pd.DataFrame:
    paper = {feature: importance for feature, importance in PAPER_SHAP_IMPORTANCE}
    rows = []
    for _, row in overall.iterrows():
        ordered_paper = [feature for feature, _ in PAPER_SHAP_IMPORTANCE]
        feature = str(row["feature"])
        rows.append({"feature": feature, "local_rank": int(row["rank"]), "local_mean_abs_shap": float(row["mean_abs_shap"]), "paper_shap_importance": paper.get(feature), "paper_rank_if_available": None if feature not in paper else ordered_paper.index(feature) + 1, "comparison_note": "Descriptive reference only; Protocol G and the local fixed configuration are not expected to reproduce the paper ranking exactly."})
    return pd.DataFrame(rows)


def _report(preflight: ExplainabilityPreflight, overall: pd.DataFrame, conditional: pd.DataFrame, groups: pd.DataFrame, verification: dict[str, Any], shap_check: dict[str, Any], paper: pd.DataFrame) -> str:
    meanings = {item["column"]: item["paper_meaning"] for item in PAPER_FEATURE_DICTIONARY}
    top = overall.head(TOP_FEATURE_COUNT)
    lines = ["# Protocol G XGBoost TreeSHAP explainability", "", "## 1. Objective", "", "This analysis describes feature contributions to the established seed-42 Protocol G XGBoost malicious-class margin. It does not tune, select features, or change the benchmark.", "", "## 2. Model and evaluation protocol", "", "- Protocol G reuses the saved feature-vector-disjoint split; equal 41-dimensional static vectors cannot cross partitions. This is not a proof of PDF-file identity or real-world generalization.", f"- XGBoost uses `{G_DROP3CONSTANT}`: 38 features, with only Acroform, Colors, and BaseEncoding absent.", f"- Train rows: {len(preflight.partitions['train'])}; explained test rows: {len(preflight.partitions['test'])}. Test rows are never used for fitting.", "", "## 3. TreeSHAP methodology and verification", "", "Native `Booster.predict(DMatrix, pred_contribs=True)` was used. The final contribution column is bias/base value, not a feature.", f"- Contribution shape: {shap_check['contribution_shape']} plus one bias per row.", f"- Max |sum(SHAP)+bias−margin|: {shap_check['maximum_abs_margin_reconstruction_error']:.3g}.", f"- Max |sigmoid(margin)−probability|: {shap_check['maximum_abs_probability_reconstruction_error']:.3g}.", f"- Historical Protocol G reproduction verification: `{verification['matches']}`.", "", "## 4. Global feature importance", "", "Mean absolute TreeSHAP is the primary global model-importance measure. Positive contributions increase the raw malicious-class margin; negative contributions decrease it. Contributions are associative, not causal.", "", "| Rank | Feature | Mean |SHAP| | Mean SHAP | Paper meaning |", "| --- | --- | --- | --- | --- |"]
    lines.extend(f"| {int(row['rank'])} | {row['feature']} | {row['mean_abs_shap']:.6g} | {row['mean_shap']:.6g} | {meanings.get(row['feature'], 'Unverified')} |" for _, row in top.iterrows())
    lines.extend(["", "## 5. Direction, class-conditional behavior, and errors", "", "Feature-value/SHAP plots are descriptive because tree relationships can be non-monotonic. Higher values are not asserted to be universal malware rules.", "", "| Feature | Benign mean |SHAP| | Malicious mean |SHAP| |", "| --- | --- | --- |"])
    lines.extend(f"| {row.feature} | {row.benign_mean_abs_shap:.6g} | {row.malicious_mean_abs_shap:.6g} |" for _, row in conditional.head(10).iterrows())
    for group in ("false_negative", "false_positive"):
        subset = groups.loc[groups.group == group].head(5)
        count = int(subset["count"].iloc[0])
        probability = float(subset["average_predicted_malicious_probability"].iloc[0])
        lines.extend(["", f"### {group.replace('_', ' ').title()}", "", f"Count: {count}; average predicted malicious probability: {probability:.6g}. Top aggregate model contributions:", "", "| Feature | Mean |SHAP| | Mean SHAP | Feature mean |", "| --- | --- | --- | --- |"])
        lines.extend(f"| {row.feature} | {row.mean_abs_shap:.6g} | {row.mean_shap:.6g} | {row.feature_mean:.6g} |" for _, row in subset.iterrows())
    overlap = paper.loc[(paper.local_rank <= 10) & paper.paper_rank_if_available.notna(), "feature"].tolist()
    lines.extend(["", "## 6. Paper comparison", "", f"Local top-ten overlap with the paper's published SHAP reference: {', '.join(overlap) if overlap else 'none'}. This is descriptive only; differences can arise from Protocol G, seed/split, project configurations, and library versions.", "", "## 7. Static-scanner implication", "", "The top model-contribution features should receive early extraction-validation attention in the future static scanner. This does not reduce the deployment schema: the scanner must reproduce the complete 38-feature model input, preserving documented semantic values such as `contains_text=-1`, `pages=0`, and out-of-spec `pdf_ver` values.", "", "## 8. Threats to validity and conclusion", "", "TreeSHAP explains this retrained benchmark model on one saved test partition; it does not establish causality, temporal robustness, PDF-file disjointness, or deployment performance. No feature/model changes were made from these results.", ""])
    return "\n".join(lines)


def execute_xgb_explainability(preflight: ExplainabilityPreflight, *, model_factory: Callable[[str, int], Any] = create_model) -> dict[str, Any]:
    """Perform the one official retrain-verify-explain run after clean preflight."""
    _assert_output_available(preflight.paths)
    set_random_seed(MODEL_RANDOM_STATE)
    train, test = preflight.partitions["train"], preflight.partitions["test"]
    train_features, test_features = protocol_g_feature_view(train, G_DROP3CONSTANT), protocol_g_feature_view(test, G_DROP3CONSTANT)
    estimator = model_factory(MODEL_NAME, MODEL_RANDOM_STATE)
    estimator.fit(train_features, train[TARGET_COLUMN])
    predictions = np.asarray(estimator.predict(test_features), dtype=int)
    contributions, bias, margins, probabilities = native_treeshap_contributions(estimator, test_features)
    metrics = evaluate_binary_predictions(test[TARGET_COLUMN], predictions, probabilities)
    historical = verify_historical_result(metrics, preflight.historical_record)
    shap_check = verify_treeshap_identity(contributions, bias, margins, probabilities)
    overall = global_importance(test_features, contributions, test[TARGET_COLUMN].reset_index(drop=True))
    conditional = class_conditional_importance(test_features.columns, contributions, test[TARGET_COLUMN].reset_index(drop=True), overall)
    groups = confusion_group_importance(test_features.columns, contributions, test_features.reset_index(drop=True), test[TARGET_COLUMN].reset_index(drop=True), predictions, probabilities)
    bands = probability_band_importance(test_features.columns, contributions, probabilities)
    paper = _paper_comparison(overall)
    paths = preflight.paths; paths.reports_directory.mkdir(parents=True, exist_ok=False)
    _make_figures(paths, test_features.reset_index(drop=True), contributions, overall, conditional, groups)
    overall.to_csv(paths.global_importance_csv, index=False); conditional.to_csv(paths.class_conditional_csv, index=False); groups.to_csv(paths.confusion_groups_csv, index=False); bands.to_csv(paths.probability_bands_csv, index=False); paper.to_csv(paths.paper_comparison_csv, index=False)
    _write_json(paths.model_config_json, {"model_name": MODEL_NAME, "model_random_state": MODEL_RANDOM_STATE, "feature_variant": G_DROP3CONSTANT, "feature_order": list(preflight.feature_columns), "model_configuration": model_configurations(MODEL_RANDOM_STATE)[MODEL_NAME]})
    _write_json(paths.dataset_provenance_json, {"dataset_filename": preflight.dataset_path.name, "dataset_sha256": DATASET_SHA256, "split_manifest_sha256": SPLIT_MANIFEST_SHA256, "split": preflight.split_summary, "explained_partition": "test", "explained_test_rows": len(test), "safe_identifier_policy": "No raw source identifiers exist in the RIT CSV or are serialized by this analysis."})
    _write_json(paths.metric_verification_json, {"historical_reproduction": historical, "test_metrics": metrics, "treeshap_mathematical_verification": shap_check})
    _write_json(paths.run_metadata_json, {"experiment": EXPERIMENT_NAME, "timestamp_utc": _timestamp(), "explainability_code_commit": preflight.code_commit, "environment": preflight.environment, "command": f".\\.venv\\Scripts\\python.exe scripts\\run_xgb_explainability.py --execute --run-id {RUN_ID}", "scope": "One fixed retrain for explanation after historical metric reproduction; no tuning, feature selection, threshold change, or historical-result modification."})
    paths.analysis_markdown.parent.mkdir(parents=True, exist_ok=True); paths.analysis_markdown.write_text(_report(preflight, overall, conditional, groups, historical, shap_check, paper), encoding="utf-8")
    return {"metrics": metrics, "historical_verification": historical, "shap_verification": shap_check, "global_importance": overall, "class_conditional": conditional, "confusion_groups": groups, "paths": paths}


def run_xgb_explainability(repository_root: str | Path, dataset_path: str | Path, *, run_id: str = RUN_ID, execute: bool = False) -> tuple[ExplainabilityPreflight, dict[str, Any] | None]:
    """Preflight by default; fitting and native TreeSHAP require explicit execution."""
    preflight = preflight_xgb_explainability(repository_root, dataset_path, run_id=run_id)
    return preflight, execute_xgb_explainability(preflight) if execute else None
