"""Synthetic tests for native XGBoost TreeSHAP explainability invariants."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from xgboost import XGBClassifier

from malpdf.experiments.xgb_explainability import (
    ExplainabilityError, _assert_output_available, class_conditional_importance,
    confusion_group_importance, explainability_paths, global_importance,
    native_treeshap_contributions, probability_band_importance,
    verify_historical_result, verify_treeshap_identity,
)


def _features() -> tuple[pd.DataFrame, pd.Series]:
    values = pd.DataFrame({"feature_a": [0, 0, 1, 1, 0, 1, 0, 1], "feature_b": [0, 1, 0, 1, 0, 1, 1, 0], "feature_c": list(range(8))})
    return values, pd.Series([0, 0, 1, 1, 0, 1, 0, 1])


def test_native_contributions_have_feature_plus_bias_shape_and_reconstruct_model_outputs():
    features, labels = _features()
    model = XGBClassifier(n_estimators=4, max_depth=2, learning_rate=.3, objective="binary:logistic", eval_metric="logloss", random_state=42, n_jobs=1, tree_method="hist")
    model.fit(features, labels)
    contributions, bias, margins, probabilities = native_treeshap_contributions(model, features)
    assert contributions.shape == (len(features), features.shape[1])
    assert bias.shape == margins.shape == probabilities.shape == (len(features),)
    verification = verify_treeshap_identity(contributions, bias, margins, probabilities)
    assert verification["sum_feature_contributions_plus_bias_matches_raw_margin"]
    assert verification["sigmoid_raw_margin_matches_malicious_probability"]


def test_global_ranking_is_deterministic_uses_mean_absolute_shap_and_includes_all_features():
    features, labels = _features()
    contributions = np.array([[1., -1., .1]] * len(features))
    ranking = global_importance(features, contributions, labels)
    assert ranking["feature"].tolist() == ["feature_a", "feature_b", "feature_c"]
    assert ranking["rank"].tolist() == [1, 2, 3]
    assert ranking.loc[0, "mean_abs_shap"] == 1.
    assert "benign_value_mean" in ranking.columns and "malicious_value_mean" in ranking.columns


def test_class_confusion_and_probability_aggregations_keep_all_groups_and_no_individual_ids():
    features, labels = _features()
    contributions = np.arange(24, dtype=float).reshape(8, 3) / 10
    overall = global_importance(features, contributions, labels)
    conditional = class_conditional_importance(features.columns, contributions, labels, overall)
    assert len(conditional) == 3 and set(conditional["overall_rank"]) == {1, 2, 3}
    predicted = np.array([0, 1, 0, 1, 0, 1, 1, 0])
    probabilities = np.array([.05, .9, .4, .8, .1, .9, .7, .2])
    groups = confusion_group_importance(features.columns, contributions, features, labels, predicted, probabilities)
    assert set(groups["group"]) == {"true_negative", "false_positive", "false_negative", "true_positive"}
    assert len(groups) == 12 and "sample_id" not in groups.columns
    bands = probability_band_importance(features.columns, contributions, probabilities)
    assert len(bands) == 18 and bands["count"].sum() == len(features) * len(features.columns)


def test_historical_result_verification_requires_exact_confusion_and_key_metrics():
    counts = {"tn": 2637, "fp": 10, "fn": 102, "tp": 2118}
    historical = {"test": {"metrics": {"accuracy": .75, "f1": .8, "mcc": .5}, "confusion_counts": counts}}
    from malpdf.evaluation.binary import classification_metrics_from_confusion_counts
    macro = classification_metrics_from_confusion_counts(**counts)["f1_macro"]
    metrics = {"accuracy": .75, "f1": .8, "mcc": .5, "f1_macro": macro, "confusion_matrix": [[2637, 10], [102, 2118]]}
    assert verify_historical_result(metrics, historical, tolerance=1e-12)["matches"]
    metrics["confusion_matrix"] = [[2636, 11], [102, 2118]]
    with pytest.raises(ExplainabilityError, match="does not reproduce"):
        verify_historical_result(metrics, historical)


def test_explainability_paths_are_isolated_and_immutable(tmp_path):
    paths = explainability_paths(tmp_path)
    _assert_output_available(paths)
    paths.reports_directory.mkdir(parents=True)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        _assert_output_available(paths)
