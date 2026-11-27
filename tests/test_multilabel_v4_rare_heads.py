from __future__ import annotations

import json
from types import SimpleNamespace

import numpy as np
import pytest
from scripts.lab import train_multilabel_threat_v4 as trainer


def test_reviewed_labels_preserve_unknowns_and_corpus_identity(tmp_path):
    corpus = SimpleNamespace(shas=("a" * 64, "b" * 64, "c" * 64), labels=np.array([1, 0, -1]))
    targets = np.zeros((3, 8), dtype=np.float32)
    masks = np.zeros_like(targets)
    path = tmp_path / "reviewed.jsonl"
    rows = [
        {"sha256": corpus.shas[0], "labels": {"buffer_loop_staging": True, "suspicious_uri_redirect": None}},
        {"sha256": corpus.shas[1], "labels": {"buffer_loop_staging": False}},
    ]
    masks[0, 6] = 1
    targets[0, 6] = 1
    path.write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")

    reviewed = trainer._apply_reviewed_behavior_labels(path, corpus, targets, masks)

    assert reviewed.tolist() == [True, True, False]
    assert targets[:, 3].tolist() == [1, 0, 0]
    assert masks[:, 3].tolist() == [1, 1, 0]
    assert targets[0, 6] == masks[0, 6] == 0

    aux = np.zeros((2, trainer.AUX_TELEMETRY_V4_DIM), dtype=np.float32)
    raw = np.zeros((2, len(trainer.IDX)), dtype=np.float32)
    augmented = trainer._augment_live_runtime_telemetry_batch(
        aux, targets[:2], masks[:2], corpus.labels[:2], raw, np.random.default_rng(42), reviewed[:2]
    )
    for result, expected in zip(augmented, (aux, targets[:2], masks[:2]), strict=True):
        np.testing.assert_array_equal(result, expected)

    rows[0]["sha256"] = corpus.shas[2]
    path.write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")
    with pytest.raises(ValueError, match="unlabeled PDF"):
        trainer._apply_reviewed_behavior_labels(path, corpus, targets, masks)


@pytest.mark.parametrize(
    ("positive_mask", "positive_score", "reason"),
    [(0, 0.99, "no_calibration_positives"), (1, 0.5, "no_positives_detected_within_fpr_budget")],
)
def test_calibration_disables_head_without_supported_positive(positive_mask, positive_score, reason):
    record = trainer._calibrate_head_threshold(
        np.array([0.7, 0.8, positive_score]),
        np.array([0, 0, 1]),
        np.array([1, 1, positive_mask]),
        np.array([0, 0, 1]),
    )

    assert record["model_flag_enabled"] is False
    assert record["disable_reason"] == reason


def test_calibration_enables_head_that_detects_positive_within_budget():
    record = trainer._calibrate_head_threshold(
        np.array([0.7, 0.8, 0.9]), np.array([0, 0, 1]), np.ones(3), np.array([0, 0, 1])
    )

    assert record["model_flag_enabled"] is True
    assert record["val_calib_benign_fpr"] == 0
    assert record["val_calib_f1"] == 1


def test_calibration_finds_narrow_threshold_for_rare_behavior():
    benign = np.r_[np.zeros(999), 0.95008, 0.99]
    scores = np.r_[benign, np.full(97, 0.99), 0.9501]
    labels = np.r_[np.zeros(len(scores) - 1), 1]
    binary = np.r_[np.zeros(len(benign)), np.ones(len(scores) - len(benign))]

    record = trainer._calibrate_head_threshold(scores, labels, np.ones(len(scores)), binary)

    assert record["model_flag_enabled"] is True
    assert record["threshold"] == 0.9501
    assert record["val_calib_benign_fpr"] == 0.000999
