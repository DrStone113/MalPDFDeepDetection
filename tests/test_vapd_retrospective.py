import numpy as np

from scripts.lab.run_vapd_retrospective import deduplicate_development, operating_point


def test_graph_comparison_preserves_test_when_numeric_vectors_repeat():
    values = np.array([[1, 0], [2, 0], [3, 0], [2, 0], [4, 0], [1, 0], [4, 0]])
    roles = np.array([0, 0, 0, 1, 1, 2, 2])
    train, validation, test = deduplicate_development(values, roles)
    assert train.tolist() == [2]
    assert validation.tolist() == [3]
    assert test.tolist() == [5, 6]


def test_validation_fpr_budget_never_breaks_score_ties():
    labels = np.array([0, 0, 0, 0, 1, 1, 1])
    scores = np.array([0.9, 0.5, 0.5, 0.1, 0.95, 0.85, 0.6])
    result = operating_point(labels, scores, 0.25)
    assert result["fpr"] == 0.25
    assert result["recall"] == 1.0
    assert 0.5 < result["threshold"] <= 0.6


def test_operating_point_prefers_higher_threshold_at_equal_tpr_and_fpr():
    labels = np.array([0, 0, 1, 1])
    scores = np.array([0.5, 0.4, 0.95, 0.6])
    assert operating_point(labels, scores, 0.0)["threshold"] == 0.6
