"""End-to-end PDF-TransGraph v3 SSL + anti-shortcut + hybrid stacking pipeline."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import sys
from typing import Any

import lightgbm as lgb
import numpy as np
from scipy.optimize import minimize, minimize_scalar
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedGroupKFold
import torch
import torch.nn as nn
import torch.nn.functional as F
import xgboost as xgb

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from malpdf.evaluation.selective import calibration_metrics  # noqa: E402
from malpdf.features.contract_v3 import (  # noqa: E402
    ACTIONS,
    AST_CALLS,
    AST_SUMMARY,
    AST_TYPES,
    DERIVED,
    EMBEDDED,
    FEATURES,
    LEXICAL,
    RAW,
    RobustTransform,
)
from malpdf.models.pdf_transgraph_v3 import (  # noqa: E402
    GRAPH_SUMMARY_DIM,
    PDFTransGraphV3,
    TransGraphV3Config,
    extract_graph_summary_features,
    load_v3_weights_npz,
    save_v3_weights_npz,
)

IDX = {name: i for i, name in enumerate(FEATURES)}
REGIME_B_NAMES = tuple(
    [f for f in LEXICAL if f != "lexical_AcroForm"]
    + list(RAW[:3])
    + list(DERIVED[:4])
)
REGIME_A_NAMES = tuple(
    [f for f in LEXICAL if f != "lexical_AcroForm"]
    + list(RAW)
    + list(ACTIONS)
    + list(EMBEDDED)
    + list(DERIVED[:4])
)
AST_NAMES = tuple(list(AST_SUMMARY) + list(AST_TYPES) + list(AST_CALLS) + list(DERIVED[4:]))
REGIME_B_INDICES = np.asarray([IDX[n] for n in REGIME_B_NAMES], dtype=np.int64)
REGIME_A_INDICES = np.asarray([IDX[n] for n in REGIME_A_NAMES], dtype=np.int64)
AST_INDICES = np.asarray([IDX[n] for n in AST_NAMES], dtype=np.int64)
ROLES = ("train", "val_select", "val_calib", "test_internal")


def set_all_seeds(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


SUPPLEMENT_PUBLISHER_SOURCES = frozenset({"arxiv", "irs", "nasa", "nist", "rfc", "fr", "court"})
SUPPLEMENT_HARD_SOURCES = frozenset({"verapdf", "pdfjs"})
SUPPLEMENT_PREFIX = "verified_benign_supplement:"


def compute_debiased_weights(
    labels: np.ndarray,
    is_bc: np.ndarray,
    label_sources: np.ndarray | None = None,
) -> np.ndarray:
    """Balance class mass 1:1 while countering VAPD D1 skew and balancing benign supplements."""
    labels_i = np.asarray(labels, dtype=np.int64)
    bc = np.asarray(is_bc, dtype=bool)
    n = len(labels_i)
    w = np.zeros(n, dtype=np.float64)

    pos = labels_i == 1
    neg = labels_i == 0
    pos_bc = pos & bc
    pos_deg = pos & (~bc)
    if pos_bc.any() and pos_deg.any():
        w[pos_bc] = 0.5 / float(pos_bc.sum())
        w[pos_deg] = 0.5 / float(pos_deg.sum())
    elif pos.any():
        w[pos] = 1.0 / float(pos.sum())

    def _fill_base_neg(mask: np.ndarray) -> np.ndarray:
        out = np.zeros(n, dtype=np.float64)
        neg_bc = mask & bc
        neg_deg = mask & (~bc)
        if neg_bc.any() and neg_deg.any():
            deg_mult = min(5.0, float(neg_bc.sum()) / float(neg_deg.sum()))
            raw = np.where(neg_bc, 1.0, np.where(neg_deg, deg_mult, 0.0))
            out[mask] = raw[mask] / float(raw[mask].sum())
        elif mask.any():
            out[mask] = 1.0 / float(mask.sum())
        return out

    srcs = None if label_sources is None else np.asarray(["" if s is None else str(s) for s in label_sources])
    has_supp = srcs is not None and any(s.startswith(SUPPLEMENT_PREFIX) for s in srcs[neg])
    if has_supp and srcs is not None:
        is_supp = np.array([s.startswith(SUPPLEMENT_PREFIX) for s in srcs], dtype=bool)
        is_pub = np.array([s[len(SUPPLEMENT_PREFIX):] in SUPPLEMENT_PUBLISHER_SOURCES if s.startswith(SUPPLEMENT_PREFIX) else False for s in srcs], dtype=bool)
        is_hard = np.array([s[len(SUPPLEMENT_PREFIX):] in SUPPLEMENT_HARD_SOURCES if s.startswith(SUPPLEMENT_PREFIX) else False for s in srcs], dtype=bool)
        # Fallback for any other verified benign supplement source joins publisher share.
        is_pub = is_pub | (is_supp & (~is_hard))
        groups = [
            (0.60, neg & (~is_supp), _fill_base_neg(neg & (~is_supp))),
            (0.20, neg & is_pub, np.where(neg & is_pub, 1.0 / max(1, int((neg & is_pub).sum())), 0.0)),
            (0.20, neg & is_hard, np.where(neg & is_hard, 1.0 / max(1, int((neg & is_hard).sum())), 0.0)),
        ]
        active = [(mass, mask, vec) for mass, mask, vec in groups if mask.any()]
        tot_mass = sum(mass for mass, _, _ in active)
        for mass, mask, vec in active:
            w[mask] = vec[mask] * (mass / tot_mass)
    else:
        w[neg] = _fill_base_neg(neg)[neg]

    w = w * (float(n) / 2.0)
    return w.astype(np.float32)


def _recompute_derived(raw_73: np.ndarray) -> None:
    obj = raw_73[:, IDX["lexical_obj"]]
    endobj = raw_73[:, IDX["lexical_endobj"]]
    stream = raw_73[:, IDX["lexical_stream"]]
    endstream = raw_73[:, IDX["lexical_endstream"]]
    js = raw_73[:, IDX["lexical_JS"]]
    javascript = raw_73[:, IDX["lexical_JavaScript"]]

    denom = np.maximum(obj, 1.0)
    valid_js = np.isfinite(js) & np.isfinite(javascript) & np.isfinite(obj)
    raw_73[valid_js, IDX["js_per_obj"]] = (js[valid_js] + javascript[valid_js]) / denom[valid_js]
    valid_st = np.isfinite(stream) & np.isfinite(obj)
    raw_73[valid_st, IDX["stream_per_obj"]] = stream[valid_st] / denom[valid_st]
    valid_eo = np.isfinite(obj) & np.isfinite(endobj)
    raw_73[valid_eo, IDX["obj_endobj_diff"]] = np.abs(obj[valid_eo] - endobj[valid_eo])
    valid_es = np.isfinite(stream) & np.isfinite(endstream)
    raw_73[valid_es, IDX["stream_endstream_diff"]] = np.abs(stream[valid_es] - endstream[valid_es])


OBJSTM_MASKED_LEXICAL = (
    "lexical_JS",
    "lexical_JavaScript",
    "lexical_OpenAction",
    "lexical_AA",
    "lexical_Launch",
    "lexical_URI",
    "lexical_EmbeddedFile",
    "lexical_XFA",
    "lexical_RichMedia",
    "lexical_JBIG2Decode",
    "lexical_page_command",
    "lexical_trailer",
    "lexical_xref",
)


def perturb_raw_format(
    raw_73: np.ndarray,
    can_linearize: np.ndarray,
    rng: np.random.Generator,
    *,
    enable_padding: bool = False,
) -> np.ndarray:
    """Apply format-preserving PDF serialization shifts without mutating trigger keywords."""
    out = np.array(raw_73, dtype=np.float32, copy=True)
    n = len(out)
    lin_draw = (rng.random(n) < 0.35) & np.asarray(can_linearize, dtype=bool)
    if lin_draw.any():
        k = int(lin_draw.sum())
        for name in ("lexical_trailer", "lexical_xref", "lexical_startxref"):
            valid = lin_draw & np.isfinite(out[:, IDX[name]])
            out[valid, IDX[name]] += 1.0
        d_obj = rng.integers(1, 6, size=k, dtype=np.int32).astype(np.float32)
        d_st = rng.integers(0, 3, size=k, dtype=np.int32).astype(np.float32)
        for name, delta in (
            ("lexical_obj", d_obj),
            ("lexical_endobj", d_obj),
            ("lexical_stream", d_st),
            ("lexical_endstream", d_st),
        ):
            idx_col = IDX[name]
            valid = lin_draw & np.isfinite(out[:, idx_col])
            out[valid, idx_col] += delta[valid[lin_draw]]
        valid_sz = lin_draw & np.isfinite(out[:, IDX["raw_size_bytes"]])
        out[valid_sz, IDX["raw_size_bytes"]] += rng.integers(256, 4097, size=int(valid_sz.sum())).astype(np.float32)
        valid_en = lin_draw & np.isfinite(out[:, IDX["raw_entropy"]])
        out[valid_en, IDX["raw_entropy"]] = np.clip(
            out[valid_en, IDX["raw_entropy"]] + rng.uniform(-0.02, 0.02, size=int(valid_en.sum())).astype(np.float32),
            0.0,
            8.0,
        )

    rep_draw = rng.random(n) < 0.35
    if rep_draw.any():
        valid_sz = rep_draw & np.isfinite(out[:, IDX["raw_size_bytes"]])
        out[valid_sz, IDX["raw_size_bytes"]] = np.maximum(
            1.0,
            out[valid_sz, IDX["raw_size_bytes"]] + rng.integers(-256, 2049, size=int(valid_sz.sum())).astype(np.float32),
        )
        valid_en = rep_draw & np.isfinite(out[:, IDX["raw_entropy"]])
        out[valid_en, IDX["raw_entropy"]] = np.clip(
            out[valid_en, IDX["raw_entropy"]] + rng.uniform(-0.05, 0.05, size=int(valid_en.sum())).astype(np.float32),
            0.0,
            8.0,
        )

    if enable_padding:
        u_pad = rng.random(n)
        light_draw = u_pad < 0.20
        if light_draw.any():
            pk = int(light_draw.sum())
            d_pad_obj = rng.integers(10, 201, size=pk, dtype=np.int32).astype(np.float32)
            d_pad_st = rng.integers(5, 81, size=pk, dtype=np.int32).astype(np.float32)
            for name, delta in (
                ("lexical_obj", d_pad_obj),
                ("lexical_endobj", d_pad_obj),
                ("lexical_stream", d_pad_st),
                ("lexical_endstream", d_pad_st),
            ):
                idx_col = IDX[name]
                valid = light_draw & np.isfinite(out[:, idx_col])
                out[valid, idx_col] += delta[valid[light_draw]]
            valid_sz = light_draw & np.isfinite(out[:, IDX["raw_size_bytes"]])
            out[valid_sz, IDX["raw_size_bytes"]] += rng.integers(5000, 100001, size=int(valid_sz.sum())).astype(np.float32)

        heavy_draw = (u_pad >= 0.20) & (u_pad < 0.35)
        if heavy_draw.any():
            hk = int(heavy_draw.sum())
            d_pages = rng.integers(10, 81, size=hk, dtype=np.int32)
            d_h_obj = (d_pages * rng.integers(20, 65, size=hk, dtype=np.int32)).astype(np.float32)
            d_h_st = np.minimum(d_h_obj - 1.0, np.maximum(1.0, np.floor(d_h_obj * rng.uniform(0.25, 0.55, size=hk)))).astype(np.float32)
            d_h_res = (d_pages * rng.integers(1, 5, size=hk, dtype=np.int32)).astype(np.float32)
            d_h_uri = rng.integers(0, 181, size=hk, dtype=np.int32).astype(np.float32)
            d_h_sz = (d_pages.astype(np.int64) * rng.integers(40_000, 220_000, size=hk, dtype=np.int64)).astype(np.float32)
            for name, delta in (
                ("lexical_obj", d_h_obj),
                ("lexical_endobj", d_h_obj),
                ("lexical_stream", d_h_st),
                ("lexical_endstream", d_h_st),
                ("lexical_page_command", d_pages.astype(np.float32)),
                ("lexical_Resources", d_h_res),
                ("lexical_URI", d_h_uri),
                ("raw_size_bytes", d_h_sz),
            ):
                idx_col = IDX[name]
                valid = heavy_draw & np.isfinite(out[:, idx_col])
                out[valid, idx_col] += delta[valid[heavy_draw]]

    _recompute_derived(out)
    return out


def simulate_objstm_tabular_mask(
    raw_73: np.ndarray,
    has_graph: np.ndarray,
    rng: np.random.Generator,
    prob: float = 0.20,
) -> np.ndarray:
    """Mask raw lexical counts moved into /ObjStm when decompressed graph remains available."""
    out = np.array(raw_73, dtype=np.float32, copy=True)
    mask = (rng.random(len(out)) < prob) & np.asarray(has_graph, dtype=bool)
    if not mask.any():
        return out
    valid_ostm = mask & np.isfinite(out[:, IDX["lexical_ObjStm"]])
    out[valid_ostm, IDX["lexical_ObjStm"]] += 1.0
    for name in OBJSTM_MASKED_LEXICAL:
        idx_col = IDX[name]
        valid = mask & np.isfinite(out[:, idx_col])
        out[valid, idx_col] = 0.0
    st = np.where(np.isfinite(out[:, IDX["lexical_stream"]]), out[:, IDX["lexical_stream"]], 0.0)
    for name in ("lexical_obj", "lexical_endobj"):
        idx_col = IDX[name]
        valid = mask & np.isfinite(out[:, idx_col])
        out[valid, idx_col] = np.maximum(st[valid] + 1.0, np.floor(out[valid, idx_col] * 0.5))
    untouched = out[~mask].copy()
    _recompute_derived(out)
    out[~mask] = untouched
    return out


def apply_stress_transform(raw_73: np.ndarray, mode: str) -> np.ndarray:
    """Deterministic test-time format/padding stress transforms matching observed pikepdf shifts."""
    out = np.array(raw_73, dtype=np.float32, copy=True)
    if mode == "linearize":
        for name in ("lexical_trailer", "lexical_xref", "lexical_startxref"):
            out[:, IDX[name]] += 1.0
        out[:, IDX["lexical_obj"]] += 2.0
        out[:, IDX["lexical_endobj"]] += 2.0
        out[:, IDX["lexical_stream"]] += 1.0
        out[:, IDX["lexical_endstream"]] += 1.0
        out[:, IDX["raw_size_bytes"]] += 692.0
        out[:, IDX["raw_entropy"]] = np.clip(out[:, IDX["raw_entropy"]] - 0.0012, 0.0, 8.0)
    elif mode == "pad_dilute":
        out[:, IDX["lexical_obj"]] += 100.0
        out[:, IDX["lexical_endobj"]] += 100.0
        out[:, IDX["lexical_stream"]] += 40.0
        out[:, IDX["lexical_endstream"]] += 40.0
        out[:, IDX["raw_size_bytes"]] += 50000.0
    else:
        raise ValueError(f"Unknown stress mode: {mode}")
    _recompute_derived(out)
    return out


def slice_regime_inputs(
    scaled_73: np.ndarray,
    missing_73: np.ndarray,
    regime: str,
) -> tuple[np.ndarray, np.ndarray | None, np.ndarray, np.ndarray]:
    if regime == "regime_b":
        if missing_73[:, REGIME_B_INDICES].any():
            raise ValueError("Regime B encountered missing values")
        tab_x = scaled_73[:, REGIME_B_INDICES]
        tab_miss = None
    elif regime == "regime_a":
        tab_x = scaled_73[:, REGIME_A_INDICES]
        tab_miss = missing_73[:, REGIME_A_INDICES].astype(np.float32)
    else:
        raise ValueError(f"Unknown regime: {regime}")
    ast_x = scaled_73[:, AST_INDICES]
    ast_miss = missing_73[:, AST_INDICES].astype(np.float32)
    return tab_x, tab_miss, ast_x, ast_miss


def prob_to_logits(probs: np.ndarray) -> np.ndarray:
    clipped = np.clip(np.asarray(probs, dtype=np.float64), 1e-6, 1.0 - 1e-6)
    return np.log(clipped / (1.0 - clipped)).astype(np.float64)


def apply_temperature(logits: np.ndarray, temp: float) -> np.ndarray:
    scaled = np.clip(np.asarray(logits, dtype=np.float64) / max(float(temp), 1e-4), -40.0, 40.0)
    return (1.0 / (1.0 + np.exp(-scaled))).astype(np.float64)


def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
    z = np.asarray(logits, dtype=np.float64)
    y = np.asarray(labels, dtype=np.float64)

    def nll(log_t: float) -> float:
        t = math.exp(log_t)
        s = np.clip(z / t, -40.0, 40.0)
        loss = np.logaddexp(0.0, s) - y * s
        return float(np.mean(loss))

    res = minimize_scalar(nll, bounds=(math.log(0.1), math.log(10.0)), method="bounded")
    return float(math.exp(float(res.x)))


def _solve_simplex_temp(z_mat: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, float]:
    k = z_mat.shape[1]

    def nll(params: np.ndarray) -> float:
        w = params[:k]
        temp = params[k]
        comb = np.clip((z_mat @ w) / temp, -40.0, 40.0)
        return float(np.mean(np.logaddexp(0.0, comb) - y * comb))

    x0 = np.asarray([1.0 / k] * k + [1.0], dtype=np.float64)
    bounds = [(0.0, 1.0)] * k + [(0.1, 10.0)]
    cons = {"type": "eq", "fun": lambda p: float(np.sum(p[:k]) - 1.0)}
    res = minimize(nll, x0=x0, method="SLSQP", bounds=bounds, constraints=cons, options={"maxiter": 300, "ftol": 1e-9})
    w = np.clip(res.x[:k], 0.0, 1.0)
    w = w / max(float(w.sum()), 1e-12)
    return w.astype(np.float64), float(np.clip(res.x[k], 0.1, 10.0))


def fit_constrained_stacker(
    logit_matrix: np.ndarray,
    labels: np.ndarray,
    groups: np.ndarray,
    *,
    seed: int = 42,
) -> dict[str, Any]:
    """Fit non-negative simplex ensemble + scalar temperature with grouped OOF on Val_Calib."""
    z = np.asarray(logit_matrix, dtype=np.float64)
    y = np.asarray(labels, dtype=np.int64)
    g = np.asarray(groups)

    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    oof = np.zeros(len(y), dtype=np.float64)
    for tr_pos, va_pos in cv.split(z, y, g):
        w_f, t_f = _solve_simplex_temp(z[tr_pos], y[tr_pos].astype(np.float64))
        oof[va_pos] = apply_temperature(z[va_pos] @ w_f, t_f)

    weights, temp = _solve_simplex_temp(z, y.astype(np.float64))
    return {"weights": weights, "temperature": temp, "oof_probs": oof}


def select_thresholds(labels: np.ndarray, probs: np.ndarray, is_bc: np.ndarray) -> dict[str, float]:
    y = np.asarray(labels, dtype=np.int64)
    p = np.asarray(probs, dtype=np.float64)
    bc = np.asarray(is_bc, dtype=bool)

    candidates = np.unique(np.concatenate(([0.05, 0.50, 0.95], np.quantile(p, np.linspace(0.01, 0.99, 199)))))
    best_f1 = -1.0
    thr_f1 = 0.50
    for thr in candidates:
        pred = (p >= thr).astype(np.int64)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        f1_mal = 0.0 if (2 * tp + fp + fn) == 0 else (2.0 * tp) / (2 * tp + fp + fn)
        f1_ben = 0.0 if (2 * tn + fn + fp) == 0 else (2.0 * tn) / (2 * tn + fn + fp)
        f1_macro = 0.5 * (f1_mal + f1_ben)
        if f1_macro > best_f1:
            best_f1 = f1_macro
            thr_f1 = float(thr)

    neg_scores = p[bc & (y == 0)] if (bc & (y == 0)).any() else p[y == 0]
    thr_fpr1 = float(np.quantile(neg_scores, 0.99)) + 1e-6
    thr_fpr1 = float(min(max(thr_fpr1, 1e-4), 0.9999))
    return {"thr_f1_macro": float(thr_f1), "thr_fpr1": thr_fpr1}


def _recall_at_fpr_target(y: np.ndarray, p: np.ndarray, target_fpr: float = 0.01) -> float | None:
    if len(np.unique(y)) < 2:
        return None
    fpr, tpr, _ = roc_curve(y, p, pos_label=1)
    valid = tpr[fpr <= target_fpr]
    return float(valid.max()) if len(valid) else 0.0


def compute_slice_metrics(
    labels: np.ndarray,
    probs: np.ndarray,
    thr_f1: float,
    thr_fpr1: float,
) -> dict[str, Any]:
    y = np.asarray(labels, dtype=np.int64)
    p = np.asarray(probs, dtype=np.float64)
    if len(y) == 0:
        return {"count": 0}
    m_f1 = calibration_metrics(y, p, n_bins=10, threshold=thr_f1)
    m_fpr1 = calibration_metrics(y, p, n_bins=10, threshold=thr_fpr1)
    tn, fp, fn, tp = (
        m_f1["confusion_matrix"][0][0],
        m_f1["confusion_matrix"][0][1],
        m_f1["confusion_matrix"][1][0],
        m_f1["confusion_matrix"][1][1],
    )
    _, fp1, fn1, tp1 = (
        m_fpr1["confusion_matrix"][0][0],
        m_fpr1["confusion_matrix"][0][1],
        m_fpr1["confusion_matrix"][1][0],
        m_fpr1["confusion_matrix"][1][1],
    )
    tn1 = m_fpr1["confusion_matrix"][0][0]
    return {
        "count": int(len(y)),
        "positive": int((y == 1).sum()),
        "negative": int((y == 0).sum()),
        "roc_auc": m_f1["roc_auc"],
        "pr_auc": m_f1["pr_auc"],
        "brier": m_f1["brier"],
        "log_loss": m_f1["log_loss"],
        "ece": m_f1["ece"],
        "recall_at_1pct_fpr": _recall_at_fpr_target(y, p, 0.01),
        "thr_f1_macro": {
            "threshold": float(thr_f1),
            "accuracy": m_f1["accuracy"],
            "f1_macro": m_f1["f1_macro"],
            "f1_malicious": m_f1["f1_malicious"],
            "recall_malicious": m_f1["recall_malicious"],
            "precision_malicious": m_f1["precision_malicious"],
            "fpr": 0.0 if (tn + fp) == 0 else float(fp / (tn + fp)),
            "mcc": m_f1["mcc"],
            "confusion_matrix": m_f1["confusion_matrix"],
        },
        "thr_fpr1": {
            "threshold": float(thr_fpr1),
            "accuracy": m_fpr1["accuracy"],
            "f1_macro": m_fpr1["f1_macro"],
            "recall_malicious": m_fpr1["recall_malicious"],
            "precision_malicious": m_fpr1["precision_malicious"],
            "fpr": 0.0 if (tn1 + fp1) == 0 else float(fp1 / (tn1 + fp1)),
            "confusion_matrix": m_fpr1["confusion_matrix"],
        },
    }


@dataclass
class CSRGraphCorpus:
    shas: tuple[str, ...]
    roles: np.ndarray
    groups: np.ndarray
    labels: np.ndarray  # -1 for unlabeled
    label_sources: np.ndarray
    is_bc: np.ndarray
    raw_73: np.ndarray
    node_x: np.ndarray
    node_type: np.ndarray
    edge_src: np.ndarray
    edge_dst: np.ndarray
    edge_rel: np.ndarray
    node_ptr: np.ndarray
    edge_ptr: np.ndarray
    graph_present: np.ndarray
    graph_summary_12: np.ndarray


def load_pooled_corpus(
    *,
    pool_path: Path,
    tabular_path: Path,
    label_view_path: Path,
    split_view_path: Path,
    benign_supplement_path: Path | None = None,
) -> CSRGraphCorpus:
    split_map: dict[str, tuple[str, str]] = {}
    with split_view_path.open("r", encoding="utf-8") as handle:
        handle.readline()
        for line in handle:
            rec = json.loads(line)
            if rec["role"] in ROLES:
                split_map[rec["sha256"]] = (rec["role"], rec["group"])

    ordered_shas = sorted(split_map.keys())
    sha_to_row = {sha: i for i, sha in enumerate(ordered_shas)}
    m = len(ordered_shas)

    roles = np.asarray([split_map[s][0] for s in ordered_shas])
    groups = np.asarray([split_map[s][1] for s in ordered_shas])
    labels = np.full(m, -1, dtype=np.int64)
    label_sources = np.empty(m, dtype=object)
    is_bc = np.zeros(m, dtype=bool)

    with label_view_path.open("r", encoding="utf-8") as handle:
        handle.readline()
        for line in handle:
            rec = json.loads(line)
            idx = sha_to_row.get(rec["sha256"])
            if idx is None:
                continue
            labels[idx] = -1 if rec["label"] is None else int(rec["label"])
            label_sources[idx] = rec["label_source"]
            is_bc[idx] = rec["status"] == "bounded_complete"

    raw_73 = np.full((m, len(FEATURES)), np.nan, dtype=np.float32)
    with gzip.open(tabular_path, "rt", encoding="ascii") as handle:
        handle.readline()
        for line in handle:
            row = json.loads(line)
            if not isinstance(row, list):
                continue
            idx = sha_to_row.get(row[0])
            if idx is None:
                continue
            raw_73[idx] = np.asarray([np.nan if v is None else float(v) for v in row[1]], dtype=np.float32)

    graph_blobs: list[Any] = [None] * m
    with gzip.open(pool_path, "rt", encoding="utf-8") as handle:
        handle.readline()
        for line in handle:
            row = json.loads(line)
            idx = sha_to_row.get(row[0])
            if idx is not None:
                graph_blobs[idx] = row[5]

    node_x_parts, node_t_parts = [], []
    edge_s_parts, edge_d_parts, edge_r_parts = [], [], []
    node_ptr = np.zeros(m + 1, dtype=np.int64)
    edge_ptr = np.zeros(m + 1, dtype=np.int64)
    graph_present = np.zeros(m, dtype=bool)
    graph_summary_12 = np.zeros((m, GRAPH_SUMMARY_DIM), dtype=np.float32)

    n_acc = 0
    e_acc = 0
    for i, g in enumerate(graph_blobs):
        if g is not None and len(g[0]) > 0:
            nx = np.asarray(g[0], dtype=np.float32)
            nt = np.asarray(g[1], dtype=np.int64)
            es = np.asarray(g[2], dtype=np.int64)
            ed = np.asarray(g[3], dtype=np.int64)
            er = np.asarray(g[4], dtype=np.int64)
            n_cur = len(nx)
            e_cur = len(es)
            node_x_parts.append(nx)
            node_t_parts.append(nt)
            if e_cur > 0:
                edge_s_parts.append(es)
                edge_d_parts.append(ed)
                edge_r_parts.append(er)

            summary = extract_graph_summary_features(
                torch.from_numpy(nt),
                torch.stack((torch.from_numpy(es), torch.from_numpy(ed)), dim=0) if e_cur > 0 else None,
                torch.zeros(n_cur, dtype=torch.long),
                batch_size=1,
            )[0].numpy()
            graph_summary_12[i] = summary
            graph_present[i] = True
            n_acc += n_cur
            e_acc += e_cur
        node_ptr[i + 1] = n_acc
        edge_ptr[i + 1] = e_acc
    del graph_blobs

    if benign_supplement_path is not None:
        supp_doc = json.loads(benign_supplement_path.read_text(encoding="utf-8"))
        supp_rows = supp_doc["rows"] if isinstance(supp_doc, dict) else supp_doc
        seen_shas = set(ordered_shas)
        s_shas, s_roles, s_groups, s_srcs, s_bc, s_raw, s_nx, s_nt, s_es, s_ed, s_er, s_gp, s_gs = (
            [], [], [], [], [], [], [], [], [], [], [], [], [],
        )
        for row in supp_rows:
            role = row["role"]
            if role == "test_internal" or role not in {"train", "val_select", "val_calib"}:
                raise ValueError(f"forbidden_supplement_role:{role}")
            sha = row["sha256"]
            if sha in seen_shas:
                raise ValueError(f"duplicate_supplement_sha256:{sha}")
            seen_shas.add(sha)
            s_shas.append(sha)
            s_roles.append(role)
            s_groups.append(row["group"])
            s_srcs.append(f"{SUPPLEMENT_PREFIX}{row['source']}")
            s_bc.append(row["status"] == "bounded_complete")
            s_raw.append([np.nan if v is None else float(v) for v in row["features"]])
            g = row["graph"]
            if g is not None and len(g[0]) > 0:
                nx = np.asarray(g[0], dtype=np.float32)
                nt = np.asarray(g[1], dtype=np.int64)
                es = np.asarray(g[2], dtype=np.int64)
                ed = np.asarray(g[3], dtype=np.int64)
                er = np.asarray(g[4], dtype=np.int64)
                n_cur = len(nx)
                e_cur = len(es)
                s_nx.append(nx)
                s_nt.append(nt)
                if e_cur > 0:
                    s_es.append(es)
                    s_ed.append(ed)
                    s_er.append(er)
                summary = extract_graph_summary_features(
                    torch.from_numpy(nt),
                    torch.stack((torch.from_numpy(es), torch.from_numpy(ed)), dim=0) if e_cur > 0 else None,
                    torch.zeros(n_cur, dtype=torch.long),
                    batch_size=1,
                )[0].numpy()
                s_gs.append(summary)
                s_gp.append(True)
                n_acc += n_cur
                e_acc += e_cur
            else:
                s_gs.append(np.zeros((GRAPH_SUMMARY_DIM,), dtype=np.float32))
                s_gp.append(False)
            node_ptr = np.append(node_ptr, n_acc)
            edge_ptr = np.append(edge_ptr, e_acc)

        if s_shas:
            ordered_shas.extend(s_shas)
            roles = np.concatenate((roles, np.asarray(s_roles)))
            groups = np.concatenate((groups, np.asarray(s_groups)))
            labels = np.concatenate((labels, np.zeros(len(s_shas), dtype=np.int64)))
            label_sources = np.concatenate((label_sources, np.asarray(s_srcs, dtype=object)))
            is_bc = np.concatenate((is_bc, np.asarray(s_bc, dtype=bool)))
            raw_73 = np.concatenate((raw_73, np.asarray(s_raw, dtype=np.float32)), axis=0)
            node_x_parts.extend(s_nx)
            node_t_parts.extend(s_nt)
            edge_s_parts.extend(s_es)
            edge_d_parts.extend(s_ed)
            edge_r_parts.extend(s_er)
            graph_present = np.concatenate((graph_present, np.asarray(s_gp, dtype=bool)))
            graph_summary_12 = np.concatenate((graph_summary_12, np.asarray(s_gs, dtype=np.float32)), axis=0)

    return CSRGraphCorpus(
        shas=tuple(ordered_shas),
        roles=roles,
        groups=groups,
        labels=labels,
        label_sources=label_sources,
        is_bc=is_bc,
        raw_73=raw_73,
        node_x=np.concatenate(node_x_parts, axis=0) if node_x_parts else np.zeros((0, 23), dtype=np.float32),
        node_type=np.concatenate(node_t_parts, axis=0) if node_t_parts else np.zeros((0,), dtype=np.int64),
        edge_src=np.concatenate(edge_s_parts, axis=0) if edge_s_parts else np.zeros((0,), dtype=np.int64),
        edge_dst=np.concatenate(edge_d_parts, axis=0) if edge_d_parts else np.zeros((0,), dtype=np.int64),
        edge_rel=np.concatenate(edge_r_parts, axis=0) if edge_r_parts else np.zeros((0,), dtype=np.int64),
        node_ptr=node_ptr,
        edge_ptr=edge_ptr,
        graph_present=graph_present,
        graph_summary_12=graph_summary_12,
    )


def gather_graph_batch(
    corpus: CSRGraphCorpus,
    indices: np.ndarray,
    device: torch.device,
    *,
    node_noise_std: float = 0.0,
    edge_drop_prob: float = 0.0,
    rng: np.random.Generator | None = None,
) -> tuple[torch.Tensor | None, torch.Tensor | None, torch.Tensor | None, torch.Tensor | None, torch.Tensor | None]:
    nx_list, nt_list, gb_list = [], [], []
    es_list, ed_list, er_list = [], [], []
    node_offset = 0
    for b_idx, row_idx in enumerate(indices):
        n0, n1 = int(corpus.node_ptr[row_idx]), int(corpus.node_ptr[row_idx + 1])
        if n1 <= n0:
            continue
        nx_list.append(corpus.node_x[n0:n1])
        nt_list.append(corpus.node_type[n0:n1])
        gb_list.append(np.full(n1 - n0, b_idx, dtype=np.int64))
        e0, e1 = int(corpus.edge_ptr[row_idx]), int(corpus.edge_ptr[row_idx + 1])
        if e1 > e0:
            es = corpus.edge_src[e0:e1]
            ed = corpus.edge_dst[e0:e1]
            er = corpus.edge_rel[e0:e1]
            if edge_drop_prob > 0.0 and rng is not None and (e1 - e0) > 1:
                keep = rng.random(e1 - e0) >= edge_drop_prob
                if keep.any():
                    es, ed, er = es[keep], ed[keep], er[keep]
            es_list.append(es + node_offset)
            ed_list.append(ed + node_offset)
            er_list.append(er)
        node_offset += n1 - n0

    if not nx_list:
        return None, None, None, None, None
    nx_t = torch.from_numpy(np.concatenate(nx_list, axis=0)).to(device=device, dtype=torch.float32)
    if node_noise_std > 0.0:
        nx_t = nx_t + torch.randn_like(nx_t) * node_noise_std
    nt_t = torch.from_numpy(np.concatenate(nt_list, axis=0)).to(device=device, dtype=torch.long)
    gb_t = torch.from_numpy(np.concatenate(gb_list, axis=0)).to(device=device, dtype=torch.long)
    if es_list:
        ei_t = torch.stack(
            (
                torch.from_numpy(np.concatenate(es_list, axis=0)),
                torch.from_numpy(np.concatenate(ed_list, axis=0)),
            ),
            dim=0,
        ).to(device=device, dtype=torch.long)
        er_t = torch.from_numpy(np.concatenate(er_list, axis=0)).to(device=device, dtype=torch.long)
    else:
        ei_t = None
        er_t = None
    return nx_t, nt_t, ei_t, er_t, gb_t


def gather_graph_list_batch(
    graphs: list[Any],
    device: torch.device,
) -> tuple[torch.Tensor | None, torch.Tensor | None, torch.Tensor | None, torch.Tensor | None, torch.Tensor | None]:
    nx_list, nt_list, gb_list = [], [], []
    es_list, ed_list, er_list = [], [], []
    node_offset = 0
    for b_idx, g in enumerate(graphs):
        if g is None or len(g[0]) == 0:
            continue
        n_cur = len(g[0])
        nx_list.append(np.asarray(g[0], dtype=np.float32))
        nt_list.append(np.asarray(g[1], dtype=np.int64))
        gb_list.append(np.full(n_cur, b_idx, dtype=np.int64))
        if len(g[2]) > 0:
            es_list.append(np.asarray(g[2], dtype=np.int64) + node_offset)
            ed_list.append(np.asarray(g[3], dtype=np.int64) + node_offset)
            er_list.append(np.asarray(g[4], dtype=np.int64))
        node_offset += n_cur
    if not nx_list:
        return None, None, None, None, None
    nx_t = torch.from_numpy(np.concatenate(nx_list, axis=0)).to(device=device, dtype=torch.float32)
    nt_t = torch.from_numpy(np.concatenate(nt_list, axis=0)).to(device=device, dtype=torch.long)
    gb_t = torch.from_numpy(np.concatenate(gb_list, axis=0)).to(device=device, dtype=torch.long)
    if es_list:
        ei_t = torch.stack(
            (torch.from_numpy(np.concatenate(es_list)), torch.from_numpy(np.concatenate(ed_list))),
            dim=0,
        ).to(device=device, dtype=torch.long)
        er_t = torch.from_numpy(np.concatenate(er_list)).to(device=device, dtype=torch.long)
    else:
        ei_t, er_t = None, None
    return nx_t, nt_t, ei_t, er_t, gb_t


@torch.no_grad()
def predict_neural_logits(
    model: PDFTransGraphV3,
    corpus: CSRGraphCorpus,
    indices: np.ndarray,
    tab_x: np.ndarray,
    tab_miss: np.ndarray | None,
    ast_x: np.ndarray,
    ast_miss: np.ndarray,
    device: torch.device,
    *,
    batch_size: int = 512,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    logits_parts = []
    weights_parts = []
    for start in range(0, len(indices), batch_size):
        b_pos = indices[start : start + batch_size]
        nx, nt, ei, er, gb = gather_graph_batch(corpus, b_pos, device)
        tx = torch.from_numpy(tab_x[b_pos]).to(device=device, dtype=torch.float32)
        tm = torch.from_numpy(tab_miss[b_pos]).to(device=device, dtype=torch.float32) if tab_miss is not None else None
        ax = torch.from_numpy(ast_x[b_pos]).to(device=device, dtype=torch.float32)
        am = torch.from_numpy(ast_miss[b_pos]).to(device=device, dtype=torch.float32)
        out = model(tx, tm, ax, am, nx, nt, ei, er, gb)
        logits_parts.append(out["logits"].detach().cpu().numpy())
        weights_parts.append(out["weights"].detach().cpu().numpy())
    return np.concatenate(logits_parts, axis=0), np.concatenate(weights_parts, axis=0)


def _update_ema(teacher: nn.Module, student: nn.Module, step: int, max_decay: float = 0.99) -> None:
    alpha = min(max_decay, 1.0 - 1.0 / float(step + 2))
    with torch.no_grad():
        for tp, sp in zip(teacher.parameters(), student.parameters(), strict=True):
            tp.data.mul_(alpha).add_(sp.data, alpha=1.0 - alpha)


def _pretrain_ssl(
    config: TransGraphV3Config,
    corpus: CSRGraphCorpus,
    train_all_idx: np.ndarray,
    regime: str,
    transform: RobustTransform,
    seed: int,
    device: torch.device,
    *,
    epochs: int = 10,
    batch_size: int = 256,
) -> tuple[dict[str, torch.Tensor], list[dict[str, float]]]:
    set_all_seeds(seed)
    model = PDFTransGraphV3(config).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(1, epochs))
    rng = np.random.default_rng(seed + 101)
    history: list[dict[str, float]] = []

    for epoch in range(epochs):
        model.train()
        perm = rng.permutation(train_all_idx)
        tot_sum = 0.0
        steps = 0
        for start in range(0, len(perm), batch_size):
            b_idx = perm[start : start + batch_size]
            if len(b_idx) < 4:
                continue
            pert_raw = perturb_raw_format(corpus.raw_73[b_idx], np.ones(len(b_idx), dtype=bool), rng, enable_padding=True)
            sc_73, ms_73 = transform.transform(pert_raw)
            # Pass real tabular missingness to ssl_loss so TabMAE masks only observed entries.
            tab_x = sc_73[:, REGIME_B_INDICES if regime == "regime_b" else REGIME_A_INDICES]
            tab_obs_miss = ms_73[:, REGIME_B_INDICES if regime == "regime_b" else REGIME_A_INDICES]
            tx = torch.from_numpy(tab_x).to(device=device, dtype=torch.float32)
            tm = torch.from_numpy(tab_obs_miss).to(device=device, dtype=torch.float32)
            nx, nt, ei, er, gb = gather_graph_batch(corpus, b_idx, device, node_noise_std=0.02, edge_drop_prob=0.05, rng=rng)
            losses = model.ssl_loss(tx, tm, nx, nt, ei, er, gb)
            opt.zero_grad(set_to_none=True)
            losses["total"].backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            tot_sum += float(losses["total"].detach())
            steps += 1
        sched.step()
        history.append({"epoch": epoch + 1, "ssl_loss": tot_sum / max(1, steps)})
    cpu_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    return cpu_state, history


def _train_neural_variant(
    name: str,
    config: TransGraphV3Config,
    init_state: dict[str, torch.Tensor] | None,
    corpus: CSRGraphCorpus,
    train_lab_idx: np.ndarray,
    train_all_idx: np.ndarray,
    regime: str,
    transform: RobustTransform,
    scaled_all: np.ndarray,
    miss_all: np.ndarray,
    val_select_idx: np.ndarray,
    *,
    use_inv_loss: bool,
    seed: int,
    device: torch.device,
    epochs: int = 25,
    batch_size: int = 256,
) -> dict[str, Any]:
    set_all_seeds(seed)
    if name == "v3_graph_only":
        train_lab_idx = train_lab_idx[corpus.graph_present[train_lab_idx]]
    w_lab = compute_debiased_weights(corpus.labels[train_lab_idx], corpus.is_bc[train_lab_idx], corpus.label_sources[train_lab_idx])

    student = PDFTransGraphV3(config).to(device)
    if init_state is not None:
        student.load_state_dict(init_state, strict=True)
    teacher = deepcopy(student).to(device).eval() if use_inv_loss else None
    if teacher is not None:
        for p in teacher.parameters():
            p.requires_grad_(False)

    opt = torch.optim.AdamW(student.parameters(), lr=8e-4, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(1, epochs))
    rng = np.random.default_rng(seed + 202)

    tab_all, tab_miss_all, ast_all, ast_miss_all = slice_regime_inputs(scaled_all, miss_all, regime)
    best_score = -1.0
    best_state = {k: v.detach().cpu().clone() for k, v in student.state_dict().items()}
    best_epoch = 0
    global_step = 0

    for epoch in range(epochs):
        student.train()
        perm_pos = rng.permutation(len(train_lab_idx))
        for start in range(0, len(perm_pos), batch_size):
            sel = perm_pos[start : start + batch_size]
            b_idx = train_lab_idx[sel]
            b_w = torch.from_numpy(w_lab[sel]).to(device=device, dtype=torch.float32)
            b_y = torch.from_numpy(corpus.labels[b_idx]).to(device=device, dtype=torch.float32)

            if use_inv_loss:
                pert_raw = perturb_raw_format(corpus.raw_73[b_idx], np.ones(len(b_idx), dtype=bool), rng, enable_padding=True)
                pert_raw = simulate_objstm_tabular_mask(pert_raw, corpus.graph_present[b_idx], rng, prob=0.20)
                sc_b, ms_b = transform.transform(pert_raw)
                tx_b, tm_b, ax_b, am_b = slice_regime_inputs(sc_b, ms_b, regime)
                nx, nt, ei, er, gb = gather_graph_batch(corpus, b_idx, device, node_noise_std=0.02, edge_drop_prob=0.05, rng=rng)
            else:
                tx_b, tm_b = tab_all[b_idx], (tab_miss_all[b_idx] if tab_miss_all is not None else None)
                ax_b, am_b = ast_all[b_idx], ast_miss_all[b_idx]
                nx, nt, ei, er, gb = gather_graph_batch(corpus, b_idx, device)

            tx = torch.from_numpy(tx_b).to(device=device, dtype=torch.float32)
            tm = torch.from_numpy(tm_b).to(device=device, dtype=torch.float32) if tm_b is not None else None
            ax = torch.from_numpy(ax_b).to(device=device, dtype=torch.float32)
            am = torch.from_numpy(am_b).to(device=device, dtype=torch.float32)

            out = student(tx, tm, ax, am, nx, nt, ei, er, gb)
            sup = F.binary_cross_entropy_with_logits(out["logits"], b_y, reduction="none")
            loss = (sup * b_w).mean()

            if config.enable_tab and config.enable_graph:
                aux_loss = torch.zeros((), device=device)
                if config.enable_tab:
                    aux_loss = aux_loss + (F.binary_cross_entropy_with_logits(out["tab_aux_logits"], b_y, reduction="none") * b_w).mean()
                g_mask = out["modality_mask"][:, 1]
                if g_mask.any():
                    aux_loss = aux_loss + (
                        F.binary_cross_entropy_with_logits(out["graph_aux_logits"][g_mask], b_y[g_mask], reduction="none") * b_w[g_mask]
                    ).mean()
                loss = loss + 0.35 * aux_loss

            if use_inv_loss and teacher is not None:
                u_idx = rng.choice(train_all_idx, size=len(b_idx), replace=len(train_all_idx) < len(b_idx))
                # Clean teacher view on unlabeled/labeled samples vs format-perturbed student view.
                tx_c = torch.from_numpy(tab_all[u_idx]).to(device=device, dtype=torch.float32)
                tm_c = torch.from_numpy(tab_miss_all[u_idx]).to(device=device, dtype=torch.float32) if tab_miss_all is not None else None
                ax_c = torch.from_numpy(ast_all[u_idx]).to(device=device, dtype=torch.float32)
                am_c = torch.from_numpy(ast_miss_all[u_idx]).to(device=device, dtype=torch.float32)
                nx_c, nt_c, ei_c, er_c, gb_c = gather_graph_batch(corpus, u_idx, device)
                with torch.no_grad():
                    t_prob = torch.sigmoid(teacher(tx_c, tm_c, ax_c, am_c, nx_c, nt_c, ei_c, er_c, gb_c)["logits"])

                pert_u = perturb_raw_format(corpus.raw_73[u_idx], np.ones(len(u_idx), dtype=bool), rng, enable_padding=True)
                pert_u = simulate_objstm_tabular_mask(pert_u, corpus.graph_present[u_idx], rng, prob=0.20)
                sc_u, ms_u = transform.transform(pert_u)
                tx_u, tm_u, ax_u, am_u = slice_regime_inputs(sc_u, ms_u, regime)
                nx_u, nt_u, ei_u, er_u, gb_u = gather_graph_batch(corpus, u_idx, device, node_noise_std=0.02, edge_drop_prob=0.05, rng=rng)
                s_prob = torch.sigmoid(
                    student(
                        torch.from_numpy(tx_u).to(device=device, dtype=torch.float32),
                        torch.from_numpy(tm_u).to(device=device, dtype=torch.float32) if tm_u is not None else None,
                        torch.from_numpy(ax_u).to(device=device, dtype=torch.float32),
                        torch.from_numpy(am_u).to(device=device, dtype=torch.float32),
                        nx_u,
                        nt_u,
                        ei_u,
                        er_u,
                        gb_u,
                    )["logits"]
                )
                loss = loss + 0.50 * F.mse_loss(s_prob, t_prob)

            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(student.parameters(), 1.0)
            opt.step()
            if teacher is not None:
                _update_ema(teacher, student, global_step, 0.99)
            global_step += 1
        sched.step()

        eval_model = teacher if teacher is not None else student
        val_logits, _ = predict_neural_logits(
            eval_model, corpus, val_select_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device
        )
        val_probs = apply_temperature(val_logits, 1.0)
        val_y = corpus.labels[val_select_idx]
        val_bc = corpus.is_bc[val_select_idx]
        all_ap = float(average_precision_score(val_y, val_probs))
        bc_ap = float(average_precision_score(val_y[val_bc], val_probs[val_bc])) if len(np.unique(val_y[val_bc])) == 2 else all_ap
        sel_score = 0.60 * bc_ap + 0.40 * all_ap
        if sel_score > best_score:
            best_score = sel_score
            best_epoch = epoch + 1
            best_state = {k: v.detach().cpu().clone() for k, v in eval_model.state_dict().items()}

    best_model = PDFTransGraphV3(config).to(device)
    best_model.load_state_dict(best_state, strict=True)
    return {
        "model": best_model,
        "state_dict": best_state,
        "best_epoch": best_epoch,
        "val_select_composite_ap": best_score,
    }


def _train_gbdt_variants(
    regime: str,
    corpus: CSRGraphCorpus,
    train_lab_idx: np.ndarray,
    val_select_idx: np.ndarray,
    seed: int,
) -> dict[str, Any]:
    feat_idx = REGIME_B_INDICES if regime == "regime_b" else REGIME_A_INDICES
    x_raw = corpus.raw_73[:, feat_idx].astype(np.float32)
    x_gbdt = np.concatenate((x_raw, corpus.graph_summary_12), axis=1)
    if regime == "regime_b" and np.isnan(x_gbdt).any():
        raise ValueError("Regime B GBDT input contains NaNs")

    w_train = compute_debiased_weights(corpus.labels[train_lab_idx], corpus.is_bc[train_lab_idx], corpus.label_sources[train_lab_idx])
    y_train = corpus.labels[train_lab_idx]
    y_val = corpus.labels[val_select_idx]

    xgb_clf = xgb.XGBClassifier(
        n_estimators=600,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=2.0,
        eval_metric="aucpr",
        early_stopping_rounds=40,
        tree_method="hist",
        random_state=seed,
        n_jobs=4,
    )
    xgb_clf.fit(
        x_gbdt[train_lab_idx],
        y_train,
        sample_weight=w_train,
        eval_set=[(x_gbdt[val_select_idx], y_val)],
        verbose=False,
    )

    lgb_clf = lgb.LGBMClassifier(
        n_estimators=600,
        num_leaves=31,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=2.0,
        random_state=seed,
        n_jobs=4,
        verbosity=-1,
    )
    lgb_clf.fit(
        x_gbdt[train_lab_idx],
        y_train,
        sample_weight=w_train,
        eval_set=[(x_gbdt[val_select_idx], y_val)],
        callbacks=[lgb.early_stopping(40, verbose=False)],
    )
    return {"x_gbdt": x_gbdt, "xgboost_v3": xgb_clf, "lightgbm_v3": lgb_clf}


def _evaluate_model_splits(
    name: str,
    calib_logits: np.ndarray,
    test_logits: np.ndarray,
    calib_y: np.ndarray,
    calib_bc: np.ndarray,
    test_y: np.ndarray,
    test_bc: np.ndarray,
    test_gp: np.ndarray,
    test_sources: np.ndarray,
    ctrl_logits: np.ndarray,
    ctrl_names: list[str],
    *,
    external_temp: float | None = None,
    external_thrs: dict[str, float] | None = None,
) -> dict[str, Any]:
    temp = float(external_temp) if external_temp is not None else fit_temperature(calib_logits, calib_y)
    calib_p = apply_temperature(calib_logits, temp)
    thrs = external_thrs if external_thrs is not None else select_thresholds(calib_y, calib_p, calib_bc)
    t_f1, t_fpr1 = thrs["thr_f1_macro"], thrs["thr_fpr1"]

    test_p = apply_temperature(test_logits, temp)
    slices = {
        "all": compute_slice_metrics(test_y, test_p, t_f1, t_fpr1),
        "bounded_complete": compute_slice_metrics(test_y[test_bc], test_p[test_bc], t_f1, t_fpr1),
        "degraded_or_unsupported": compute_slice_metrics(test_y[~test_bc], test_p[~test_bc], t_f1, t_fpr1),
        "graph_available": compute_slice_metrics(test_y[test_gp], test_p[test_gp], t_f1, t_fpr1),
    }
    per_source: dict[str, Any] = {}
    for src in sorted({str(s) for s in test_sources}):
        mask = test_sources == src
        per_source[src] = {
            "count": int(mask.sum()),
            "mean_prob": float(np.mean(test_p[mask])),
            "min_prob": float(np.min(test_p[mask])),
            "max_prob": float(np.max(test_p[mask])),
            "positive_rate_050": float(np.mean(test_p[mask] >= 0.50)),
            "positive_rate_thr_f1": float(np.mean(test_p[mask] >= t_f1)),
            "positive_rate_thr_fpr1": float(np.mean(test_p[mask] >= t_fpr1)),
        }

    ctrl_p = apply_temperature(ctrl_logits, temp)
    controls = {
        "probs": {cname: float(cp) for cname, cp in zip(ctrl_names, ctrl_p, strict=True)},
        "spread": float(np.max(ctrl_p) - np.min(ctrl_p)),
        "alerts_at_050": int(np.sum(ctrl_p >= 0.50)),
        "alerts_at_thr_f1": int(np.sum(ctrl_p >= t_f1)),
        "alerts_at_thr_fpr1": int(np.sum(ctrl_p >= t_fpr1)),
    }
    return {
        "temperature": temp,
        "thresholds": thrs,
        "val_calib": compute_slice_metrics(calib_y, calib_p, t_f1, t_fpr1),
        "test_internal": {"slices": slices, "per_source": per_source},
        "reviewed_controls": controls,
        "_test_probs": test_p,
    }


def _load_controls(path: Path) -> tuple[list[str], np.ndarray, list[Any], np.ndarray]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    names = ["original", "repacked", "title_extended", "linearized"]
    raw_vecs = []
    graphs = []
    for name in names:
        rec = payload["controls"][name]
        raw_vecs.append([np.nan if v is None else float(v) for v in rec["vector_v3"]])
        graphs.append(rec["graph"])
    raw_73 = np.asarray(raw_vecs, dtype=np.float32)
    nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs, torch.device("cpu"))
    summary_12 = extract_graph_summary_features(nt_t, ei_t, gb_t, batch_size=len(names)).numpy()
    return names, raw_73, graphs, summary_12


def run_regime(
    regime: str,
    corpus: CSRGraphCorpus,
    ctrl_names: list[str],
    ctrl_raw_73: np.ndarray,
    ctrl_graphs: list[Any],
    ctrl_summary_12: np.ndarray,
    transform: RobustTransform,
    scaled_all: np.ndarray,
    miss_all: np.ndarray,
    *,
    seed: int,
    device: torch.device,
    run_ablations: bool,
    save_dir: Path | None,
    lock_dir: Path | None,
) -> dict[str, Any]:
    train_all_idx = np.flatnonzero(corpus.roles == "train")
    train_lab_idx = np.flatnonzero((corpus.roles == "train") & (corpus.labels >= 0))
    val_sel_idx = np.flatnonzero(corpus.roles == "val_select")
    val_cal_idx = np.flatnonzero(corpus.roles == "val_calib")
    test_idx = np.flatnonzero(corpus.roles == "test_internal")

    tab_dim = len(REGIME_B_INDICES) if regime == "regime_b" else len(REGIME_A_INDICES)
    use_miss = regime == "regime_a"
    tab_all, tab_miss_all, ast_all, ast_miss_all = slice_regime_inputs(scaled_all, miss_all, regime)
    ctrl_sc, ctrl_ms = transform.transform(ctrl_raw_73)
    ctrl_tx, ctrl_tm, ctrl_ax, ctrl_am = slice_regime_inputs(ctrl_sc, ctrl_ms, regime)

    base_cfg = TransGraphV3Config(tab_dim=tab_dim, use_missing_mask=use_miss)
    ssl_inv_cfg = TransGraphV3Config(tab_dim=tab_dim, use_missing_mask=use_miss, modality_drop_prob=0.15)
    ssl_state, ssl_hist = _pretrain_ssl(ssl_inv_cfg, corpus, train_all_idx, regime, transform, seed, device)

    neural_specs: list[tuple[str, TransGraphV3Config, dict[str, torch.Tensor] | None, bool]] = []
    if run_ablations:
        neural_specs.extend(
            [
                ("v3_graph_only", TransGraphV3Config(tab_dim=tab_dim, use_missing_mask=use_miss, enable_tab=False, enable_ast=False), None, False),
                ("v3_tab_only", TransGraphV3Config(tab_dim=tab_dim, use_missing_mask=use_miss, enable_graph=False, enable_ast=False), None, False),
                ("v3_tab_graph_supervised", base_cfg, None, False),
            ]
        )
    else:
        neural_specs.append(("v3_tab_graph_supervised", base_cfg, None, False))
    neural_specs.append(("v3_tab_graph_ssl_inv", ssl_inv_cfg, ssl_state, True))

    neural_logits: dict[str, dict[str, np.ndarray]] = {}
    neural_artifacts: dict[str, Any] = {}
    for m_name, m_cfg, init_st, inv_flag in neural_specs:
        trained = _train_neural_variant(
            m_name,
            m_cfg,
            init_st,
            corpus,
            train_lab_idx,
            train_all_idx,
            regime,
            transform,
            scaled_all,
            miss_all,
            val_sel_idx,
            use_inv_loss=inv_flag,
            seed=seed,
            device=device,
        )
        mdl = trained["model"].eval()
        val_l, _ = predict_neural_logits(mdl, corpus, val_sel_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
        cal_l, cal_w = predict_neural_logits(mdl, corpus, val_cal_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
        tst_l, tst_w = predict_neural_logits(mdl, corpus, test_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
        with torch.no_grad():
            nx_c, nt_c, ei_c, er_c, gb_c = gather_graph_list_batch(ctrl_graphs, device)
            c_out = mdl(
                torch.from_numpy(ctrl_tx).to(device=device, dtype=torch.float32),
                torch.from_numpy(ctrl_tm).to(device=device, dtype=torch.float32) if ctrl_tm is not None else None,
                torch.from_numpy(ctrl_ax).to(device=device, dtype=torch.float32),
                torch.from_numpy(ctrl_am).to(device=device, dtype=torch.float32),
                nx_c,
                nt_c,
                ei_c,
                er_c,
                gb_c,
            )
            ctrl_l = c_out["logits"].detach().cpu().numpy()
        neural_logits[m_name] = {
            "val_select": val_l,
            "val_calib": cal_l,
            "test_internal": tst_l,
            "controls": ctrl_l,
            "test_weights_mean": tst_w.mean(axis=0).tolist(),
        }
        neural_artifacts[m_name] = trained

    gbdt = _train_gbdt_variants(regime, corpus, train_lab_idx, val_sel_idx, seed)
    feat_idx = REGIME_B_INDICES if regime == "regime_b" else REGIME_A_INDICES
    x_ctrl_gbdt = np.concatenate((ctrl_raw_73[:, feat_idx], ctrl_summary_12), axis=1)
    x_gbdt = gbdt["x_gbdt"]
    gbdt_logits: dict[str, dict[str, np.ndarray]] = {}
    for g_name in ("xgboost_v3", "lightgbm_v3"):
        clf = gbdt[g_name]
        gbdt_logits[g_name] = {
            "val_select": prob_to_logits(clf.predict_proba(x_gbdt[val_sel_idx])[:, 1]),
            "val_calib": prob_to_logits(clf.predict_proba(x_gbdt[val_cal_idx])[:, 1]),
            "test_internal": prob_to_logits(clf.predict_proba(x_gbdt[test_idx])[:, 1]),
            "controls": prob_to_logits(clf.predict_proba(x_ctrl_gbdt)[:, 1]),
        }

    # Baseline shortcut controls fit strictly on train labeled rows.
    shortcut_logits: dict[str, dict[str, np.ndarray]] = {}
    if run_ablations:
        st_clf = LogisticRegression(C=1.0, max_iter=1000, random_state=seed)
        st_clf.fit(corpus.is_bc[train_lab_idx, None].astype(np.float32), corpus.labels[train_lab_idx])
        shortcut_logits["status_only"] = {
            "val_calib": prob_to_logits(st_clf.predict_proba(corpus.is_bc[val_cal_idx, None].astype(np.float32))[:, 1]),
            "test_internal": prob_to_logits(st_clf.predict_proba(corpus.is_bc[test_idx, None].astype(np.float32))[:, 1]),
            "controls": prob_to_logits(st_clf.predict_proba(np.ones((len(ctrl_names), 1), dtype=np.float32))[:, 1]),
        }
        ob_clf = LogisticRegression(C=1.0, max_iter=1000, random_state=seed)
        ob_clf.fit(miss_all[train_lab_idx], corpus.labels[train_lab_idx])
        shortcut_logits["observability_only"] = {
            "val_calib": prob_to_logits(ob_clf.predict_proba(miss_all[val_cal_idx])[:, 1]),
            "test_internal": prob_to_logits(ob_clf.predict_proba(miss_all[test_idx])[:, 1]),
            "controls": prob_to_logits(ob_clf.predict_proba(ctrl_ms)[:, 1]),
        }

    # Constrained hybrid stacking strictly on Val_Calib with grouped OOF threshold selection.
    cal_y = corpus.labels[val_cal_idx]
    cal_bc = corpus.is_bc[val_cal_idx]
    stack_members = ("v3_tab_graph_ssl_inv", "xgboost_v3", "lightgbm_v3")
    all_logits_src = {**neural_logits, **gbdt_logits, **shortcut_logits}
    stack_cal_mat = np.column_stack([all_logits_src[m]["val_calib"] for m in stack_members])
    stack_tst_mat = np.column_stack([all_logits_src[m]["test_internal"] for m in stack_members])
    stack_ctl_mat = np.column_stack([all_logits_src[m]["controls"] for m in stack_members])
    stack_fit = fit_constrained_stacker(stack_cal_mat, cal_y, corpus.groups[val_cal_idx], seed=seed)
    stack_thrs = select_thresholds(cal_y, stack_fit["oof_probs"], cal_bc)

    if lock_dir is not None:
        val_lock = {
            "regime": regime,
            "seed": seed,
            "val_calib_samples": int(len(val_cal_idx)),
            "hybrid_stacking_weights": {m: float(w) for m, w in zip(stack_members, stack_fit["weights"], strict=True)},
            "hybrid_temperature": float(stack_fit["temperature"]),
            "hybrid_thresholds": stack_thrs,
        }
        (lock_dir / f"validation_lock_{regime}.json").write_text(json.dumps(val_lock, indent=2) + "\n", encoding="utf-8")
        (lock_dir / f"test_evaluation_started_{regime}.json").write_text(
            json.dumps({"started_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "regime": regime}, indent=2) + "\n",
            encoding="utf-8",
        )

    # Single-shot Test_Internal evaluation across all locked models.
    test_y = corpus.labels[test_idx]
    test_bc = corpus.is_bc[test_idx]
    test_gp = corpus.graph_present[test_idx]
    test_src = corpus.label_sources[test_idx]

    models_report: dict[str, Any] = {}
    for m_name, l_dict in all_logits_src.items():
        ev = _evaluate_model_splits(
            m_name,
            l_dict["val_calib"],
            l_dict["test_internal"],
            cal_y,
            cal_bc,
            test_y,
            test_bc,
            test_gp,
            test_src,
            l_dict["controls"],
            ctrl_names,
        )
        if m_name in neural_artifacts:
            ev["best_epoch"] = neural_artifacts[m_name]["best_epoch"]
            ev["val_select_composite_ap"] = neural_artifacts[m_name]["val_select_composite_ap"]
            ev["mean_modality_weights_test"] = l_dict["test_weights_mean"]
        models_report[m_name] = ev

    hyb_cal_logits = stack_cal_mat @ stack_fit["weights"]
    hyb_tst_logits = stack_tst_mat @ stack_fit["weights"]
    hyb_ctl_logits = stack_ctl_mat @ stack_fit["weights"]
    hyb_ev = _evaluate_model_splits(
        "hybrid_stacking_v3",
        hyb_cal_logits,
        hyb_tst_logits,
        cal_y,
        cal_bc,
        test_y,
        test_bc,
        test_gp,
        test_src,
        hyb_ctl_logits,
        ctrl_names,
        external_temp=stack_fit["temperature"],
        external_thrs=stack_thrs,
    )
    hyb_ev["stacking_weights"] = {m: float(w) for m, w in zip(stack_members, stack_fit["weights"], strict=True)}
    models_report["hybrid_stacking_v3"] = hyb_ev

    # Adversarial / format-invariance stress on Test_Internal bounded_complete slices.
    test_bc_ben_idx = test_idx[test_bc & (test_y == 0)]
    test_bc_mal_idx = test_idx[test_bc & (test_y == 1)]
    stress_report: dict[str, Any] = {}
    for s_name, s_idx, mode, pos_expected in (
        ("benign_linearization", test_bc_ben_idx, "linearize", False),
        ("malicious_padding_dilution", test_bc_mal_idx, "pad_dilute", True),
    ):
        pert_raw = apply_stress_transform(corpus.raw_73[s_idx], mode)
        sc_p, ms_p = transform.transform(pert_raw)
        tx_p, tm_p, ax_p, am_p = slice_regime_inputs(sc_p, ms_p, regime)
        x_gbdt_p = np.concatenate((pert_raw[:, feat_idx], corpus.graph_summary_12[s_idx]), axis=1)

        s_logits: dict[str, np.ndarray] = {}
        for m_name in ("v3_tab_graph_supervised", "v3_tab_graph_ssl_inv"):
            mdl = neural_artifacts[m_name]["model"].eval()
            with torch.no_grad():
                nx_s, nt_s, ei_s, er_s, gb_s = gather_graph_batch(corpus, s_idx, device)
                s_logits[m_name] = mdl(
                    torch.from_numpy(tx_p).to(device=device, dtype=torch.float32),
                    torch.from_numpy(tm_p).to(device=device, dtype=torch.float32) if tm_p is not None else None,
                    torch.from_numpy(ax_p).to(device=device, dtype=torch.float32),
                    torch.from_numpy(am_p).to(device=device, dtype=torch.float32),
                    nx_s,
                    nt_s,
                    ei_s,
                    er_s,
                    gb_s,
                )["logits"].detach().cpu().numpy()
        for g_name in ("xgboost_v3", "lightgbm_v3"):
            s_logits[g_name] = prob_to_logits(gbdt[g_name].predict_proba(x_gbdt_p)[:, 1])
        s_mat = np.column_stack([s_logits[m] for m in stack_members])
        s_logits["hybrid_stacking_v3"] = s_mat @ stack_fit["weights"]

        slice_sel = (test_bc & (test_y == 0)) if not pos_expected else (test_bc & (test_y == 1))
        stress_report[s_name] = {"count": int(len(s_idx)), "models": {}}
        for m_name, l_after in s_logits.items():
            ev = models_report[m_name]
            p_before = ev["_test_probs"][slice_sel]
            p_after = apply_temperature(l_after, ev["temperature"])
            thr = ev["thresholds"]["thr_f1_macro"]
            before_pos = float(np.mean(p_before >= thr))
            after_pos = float(np.mean(p_after >= thr))
            delta = p_after - p_before
            stress_report[s_name]["models"][m_name] = {
                "mean_abs_delta_p": float(np.mean(np.abs(delta))),
                "max_abs_delta_p": float(np.max(np.abs(delta))),
                "mean_signed_delta_p": float(np.mean(delta)),
                "pos_rate_before": before_pos,
                "pos_rate_after": after_pos,
            }

    parity_report: dict[str, float] = {}
    if save_dir is not None:
        reg_dir = save_dir
        reg_dir.mkdir(parents=True, exist_ok=True)
        for m_name, trained in neural_artifacts.items():
            cfg = trained["model"].config
            npz_path = reg_dir / f"{m_name}.npz"
            save_v3_weights_npz(trained["model"], npz_path)
            (reg_dir / f"{m_name}_config.json").write_text(json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8")

            # Checkpoint reload initializes parameters before loading weights.
            with torch.random.fork_rng(devices=[], enabled=reg_dir.name != regime):
                reloaded = PDFTransGraphV3(cfg).to(device).eval()
            load_v3_weights_npz(reloaded, npz_path, map_location=device)
            re_cal, _ = predict_neural_logits(reloaded, corpus, val_cal_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
            parity_report[m_name] = float(np.max(np.abs(re_cal - all_logits_src[m_name]["val_calib"])))

        gbdt["xgboost_v3"].save_model(str(reg_dir / "xgboost_v3.json"))
        gbdt["lightgbm_v3"].booster_.save_model(str(reg_dir / "lightgbm_v3.txt"))

        xgb_re = xgb.XGBClassifier()
        xgb_re.load_model(str(reg_dir / "xgboost_v3.json"))
        parity_report["xgboost_v3"] = float(
            np.max(np.abs(prob_to_logits(xgb_re.predict_proba(x_gbdt[val_cal_idx])[:, 1]) - gbdt_logits["xgboost_v3"]["val_calib"]))
        )
        np.savez_compressed(
            reg_dir / "robust_transform.npz",
            center=transform.center,
            scale=transform.scale,
            available=transform.available,
        )

    for ev in models_report.values():
        ev.pop("_test_probs", None)

    return {
        "regime": regime,
        "seed": seed,
        "tabular_dim": tab_dim,
        "use_missing_mask": use_miss,
        "ssl_history": ssl_hist,
        "models": models_report,
        "stress_tests": stress_report,
        "reload_max_abs_logit_diff": parity_report,
    }


def _aggregate_seed_runs(seed_reports: list[dict[str, Any]]) -> dict[str, Any]:
    candidate = "v3_tab_graph_ssl_inv"
    core_models = ("v3_tab_graph_supervised", candidate, "xgboost_v3", "lightgbm_v3", "hybrid_stacking_v3")

    def stats(values: list[float]) -> dict[str, float]:
        return {"mean": float(np.mean(values)), "std": float(np.std(values))}

    summary: dict[str, Any] = {"seeds": [r["seed"] for r in seed_reports], "models": {}}
    for m_name in core_models:
        models = [r["models"][m_name] for r in seed_reports]
        rows = []
        for model in models:
            slices = model["test_internal"]["slices"]
            test_all, test_bc = slices["all"], slices["bounded_complete"]
            rows.append({
                "test_all_pr_auc": test_all["pr_auc"],
                "test_all_roc_auc": test_all["roc_auc"],
                "test_all_f1_macro": test_all["thr_f1_macro"]["f1_macro"],
                "test_all_ece": test_all["ece"],
                "test_bc_pr_auc": test_bc["pr_auc"],
                "test_bc_roc_auc": test_bc["roc_auc"],
                "test_bc_f1_macro": test_bc["thr_f1_macro"]["f1_macro"],
                "test_bc_ece": test_bc["ece"],
                "test_bc_recall_at_1pct_fpr": test_bc["recall_at_1pct_fpr"],
            })
        alerts = [m["reviewed_controls"]["alerts_at_thr_f1"] for m in models]
        model_summary = {key: stats([row[key] for row in rows]) for key in rows[0]}
        model_summary["reviewed_controls_alerts_thr_f1"] = alerts
        summary["models"][m_name] = model_summary
        if m_name == candidate:
            model_summary["stress_tests"] = {
                name: {
                    "count": case["count"],
                    **{
                        key: stats([r["stress_tests"][name]["models"][candidate][key] for r in seed_reports])
                        for key in case["models"][candidate]
                    },
                }
                for name, case in seed_reports[0]["stress_tests"].items()
            }
            summary["per_seed"] = [
                {
                    "seed": report["seed"],
                    "temperature": model["temperature"],
                    "mean_branch_weights": model["mean_modality_weights_test"],
                    "reload_max_abs_logit_diff": report["reload_max_abs_logit_diff"].get(candidate),
                    "reviewed_controls_alerts_thr_f1": alert_count,
                    **row,
                }
                for report, model, row, alert_count in zip(seed_reports, models, rows, alerts, strict=True)
            ]
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate PDF-TransGraph v3 across Regimes B & A")
    parser.add_argument("--pool", type=Path, default=REPO / "data/processed/pooled_bulk/pooled.jsonl.gz")
    parser.add_argument("--tabular", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/tabular_v3.jsonl.gz")
    parser.add_argument("--label-view", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/training_labels_20261122T055618Z.jsonl")
    parser.add_argument("--split-view", type=Path, default=None)
    parser.add_argument("--controls", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/reviewed_controls_v3.json")
    parser.add_argument("--benign-supplement", type=Path, default=None)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    parser.add_argument("--save-all-seeds", action="store_true", help="Save Regime B checkpoints for every seed")
    args = parser.parse_args()
    if args.save_all_seeds and len(set(args.seeds)) != len(args.seeds):
        parser.error("--save-all-seeds requires distinct seeds")

    if args.split_view is None:
        cur = (REPO / "data/processed/pooled_bulk/offline_provenance/current_split_view.txt").read_text(encoding="utf-8").strip()
        args.split_view = REPO / cur

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exp_dir = REPO / f"reports/experiments/transgraph_v3/run_{ts}_{git_rev}"
    art_dir = REPO / f"data/processed/pooled_bulk/transgraph_v3/run_{ts}_{git_rev}"
    exp_dir.mkdir(parents=True, exist_ok=not args.save_all_seeds)
    art_dir.mkdir(parents=True, exist_ok=not args.save_all_seeds)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device={device}, split_view={args.split_view.name}")

    corpus = load_pooled_corpus(
        pool_path=args.pool,
        tabular_path=args.tabular,
        label_view_path=args.label_view,
        split_view_path=args.split_view,
        benign_supplement_path=args.benign_supplement,
    )
    train_all_idx = np.flatnonzero(corpus.roles == "train")
    transform = RobustTransform.fit(corpus.raw_73[train_all_idx], roles=["train"] * len(train_all_idx))
    scaled_all, miss_all = transform.transform(corpus.raw_73)
    ctrl_names, ctrl_raw_73, ctrl_graphs, ctrl_summary_12 = _load_controls(args.controls)

    inputs_sha = {
        "pool": hashlib.sha256(args.pool.read_bytes()).hexdigest(),
        "tabular": hashlib.sha256(args.tabular.read_bytes()).hexdigest(),
        "label_view": hashlib.sha256(args.label_view.read_bytes()).hexdigest(),
        "split_view": hashlib.sha256(args.split_view.read_bytes()).hexdigest(),
        "controls": hashlib.sha256(args.controls.read_bytes()).hexdigest(),
    }
    if args.benign_supplement is not None:
        inputs_sha["benign_supplement"] = hashlib.sha256(args.benign_supplement.read_bytes()).hexdigest()

    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revision": git_rev,
        "device": str(device),
        "torch_version": torch.__version__,
        "xgboost_version": xgb.__version__,
        "lightgbm_version": lgb.__version__,
        "inputs_sha256": inputs_sha,
        "regime_b_features": list(REGIME_B_NAMES),
        "regime_a_features": list(REGIME_A_NAMES),
        "ast_features": list(AST_NAMES),
        "seeds": args.seeds,
    }
    if args.save_all_seeds:
        locked["save_all_seeds"] = True
        locked["program_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (exp_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")

    # Seed 42 primary full runs across Regime B (anti-shortcut) and Regime A (full Contract v3).
    primary_seed = args.seeds[0]
    regime_b_primary = run_regime(
        "regime_b",
        corpus,
        ctrl_names,
        ctrl_raw_73,
        ctrl_graphs,
        ctrl_summary_12,
        transform,
        scaled_all,
        miss_all,
        seed=primary_seed,
        device=device,
        run_ablations=True,
        save_dir=art_dir / "regime_b",
        lock_dir=exp_dir,
    )
    print("Completed Regime B seed", primary_seed)

    regime_a_primary = run_regime(
        "regime_a",
        corpus,
        ctrl_names,
        ctrl_raw_73,
        ctrl_graphs,
        ctrl_summary_12,
        transform,
        scaled_all,
        miss_all,
        seed=primary_seed,
        device=device,
        run_ablations=False,
        save_dir=art_dir / "regime_a",
        lock_dir=exp_dir,
    )
    print("Completed Regime A seed", primary_seed)

    seed_runs_b = [regime_b_primary]
    for s in args.seeds[1:]:
        rep = run_regime(
            "regime_b",
            corpus,
            ctrl_names,
            ctrl_raw_73,
            ctrl_graphs,
            ctrl_summary_12,
            transform,
            scaled_all,
            miss_all,
            seed=s,
            device=device,
            run_ablations=False,
            save_dir=art_dir / f"regime_b_seed{s}" if args.save_all_seeds else None,
            lock_dir=None,
        )
        seed_runs_b.append(rep)
        print("Completed Regime B stability seed", s)

    metrics = {
        "run_directory": str(exp_dir.relative_to(REPO)),
        "artifact_directory": str(art_dir.relative_to(REPO)),
        "dataset_summary": {
            "total_in_splits": len(corpus.shas),
            "train_total": int((corpus.roles == "train").sum()),
            "train_labeled": int(((corpus.roles == "train") & (corpus.labels >= 0)).sum()),
            "train_unlabeled": int(((corpus.roles == "train") & (corpus.labels < 0)).sum()),
            "val_select": int((corpus.roles == "val_select").sum()),
            "val_calib": int((corpus.roles == "val_calib").sum()),
            "test_internal": int((corpus.roles == "test_internal").sum()),
        },
        "regime_b_primary": regime_b_primary,
        "regime_a_primary": regime_a_primary,
        "regime_b_multiseed_stability": _aggregate_seed_runs(seed_runs_b),
    }
    if args.save_all_seeds:
        metrics["seed_runs_b"] = seed_runs_b
    (exp_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (REPO / "data/processed/pooled_bulk/offline_provenance/current_transgraph_v3_run.txt").write_text(
        str(exp_dir.relative_to(REPO)), encoding="utf-8"
    )
    print("Saved metrics:", exp_dir / "metrics.json")


if __name__ == "__main__":
    main()
