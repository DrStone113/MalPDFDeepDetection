from __future__ import annotations

import numpy as np

from malpdf.evaluation.binary import classification_metrics_from_confusion_counts


def midpoint_macro_f1(labels, probabilities, *, max_threshold: float = 1.0, f1_tolerance: float = 0.0):
    truth = np.asarray(labels)
    scores = np.asarray(probabilities, dtype=np.float64)
    if (
        truth.ndim != 1
        or truth.shape != scores.shape
        or set(truth.tolist()) != {0, 1}
        or not np.isfinite(scores).all()
        or not ((0 <= scores) & (scores <= 1)).all()
    ):
        raise ValueError("invalid_binary_calibration_inputs")
    if not np.isfinite(max_threshold) or not (0.0 < float(max_threshold) <= 1.0):
        raise ValueError("invalid_max_threshold")
    if not np.isfinite(f1_tolerance) or float(f1_tolerance) < 0.0:
        raise ValueError("invalid_f1_tolerance")
    cap = float(max_threshold)
    tol = max(1e-12, float(f1_tolerance))
    order = np.argsort(scores, kind="stable")
    unique, first = np.unique(scores[order], return_index=True)
    positives = np.concatenate(([0], np.cumsum(truth[order], dtype=np.int64)))
    boundaries = np.concatenate(([0.0], unique, [1.0]))
    cuts = np.concatenate((first, [len(order)]))
    scored = []
    for i, cut in enumerate(cuts):
        low, high = map(float, boundaries[i : i + 2])
        if i and low == high:
            continue
        eff_high = min(high, cap)
        if not (low < eff_high):
            continue
        fn = int(positives[cut])
        tn = int(cut) - fn
        fp = len(order) - int(positives[-1]) - tn
        tp = int(positives[-1]) - fn
        f1 = classification_metrics_from_confusion_counts(tn=tn, fp=fp, fn=fn, tp=tp)["f1_macro"]
        scored.append((low, eff_high, f1))

    peak = max(f1 for _, _, f1 in scored)
    plateaus = []
    for low, high, f1 in scored:
        if (peak - f1) > tol:
            continue
        if plateaus and plateaus[-1][1] == low:
            plateaus[-1] = (plateaus[-1][0], high)
        else:
            plateaus.append((low, high))
    low, high = max(plateaus, key=lambda span: (span[1] - span[0], span[1]))
    threshold = (low + high) / 2
    if threshold == low and low < high:
        threshold = float(np.nextafter(low, high))
    return {"threshold": threshold, "interval": [low, high], "f1_macro": peak}
