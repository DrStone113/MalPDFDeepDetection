"""Train, calibrate, and evaluate BUG-020-compliant leak-free PDFMultiLabelThreatNet v4 on frozen v4 inputs."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import numpy as np
from scipy.optimize import minimize_scalar
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
import torch
import torch.nn.functional as F

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.score_benign_ood import digest  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    IDX,
    REGIME_B_INDICES,
    REGIME_B_NAMES,
    CSRGraphCorpus,
    _recompute_derived,
    apply_temperature,
    compute_debiased_weights,
    fit_temperature,
    load_pooled_corpus,
    perturb_raw_format,
    set_all_seeds,
    simulate_objstm_tabular_mask,
    slice_regime_inputs,
)
from scripts.lab.train_eval_transgraph_v4 import (  # noqa: E402
    DEFAULT_LABEL_VIEW,
    DEFAULT_POOL,
    DEFAULT_SPLIT_VIEW,
    DEFAULT_SUPP,
    DEFAULT_TABULAR,
    POOL_ROOT,
    PackedGraph,
    _make_macro_bucketed_batches,
    precompute_corpus,
)

from malpdf.features.contract_v3 import RobustTransform  # noqa: E402
from malpdf.models.multilabel_threat_net import MULTILABEL_THREAT_DEFINITIONS  # noqa: E402
from malpdf.models.multilabel_threat_net_v4 import (  # noqa: E402
    EXPECTED_HEAD_IDS_V4,
    MULTILABEL_V4_CONTRACT_VERSION,
    MultiLabelV4Config,
    PDFMultiLabelThreatNetV4,
    load_multilabel_v4_npz,
    save_multilabel_v4_npz,
    validate_multilabel_v4_contract,
)
from malpdf.models.pdf_transgraph_v4 import build_padded_graph_tensors  # noqa: E402
from malpdf.models.v4_graph_numpy import AUX_TELEMETRY_V4_DIM, AUX_TELEMETRY_V4_NAMES  # noqa: E402

DEFAULT_OUT_MODEL = REPO / "artifacts/models/multilabel_threat_v4/multilabel_threat_net_v4_seed42.npz"
DEFAULT_OUT_CONTRACT = REPO / "configs/multilabel_threat_v4_contract.json"
DEFAULT_REPORT_ROOT = REPO / "reports/experiments/multilabel_threat_v4"
V4_BINARY_CONTRACT_PATH = REPO / "configs/transgraph_v4_contract.json"
REVIEWED_HEAD_COLUMNS = {
    head: EXPECTED_HEAD_IDS_V4.index(head)
    for head in ("buffer_loop_staging", "active_form_or_exploit", "suspicious_uri_redirect")
}


def _apply_reviewed_behavior_labels(
    path: Path, corpus: CSRGraphCorpus, targets: np.ndarray, masks: np.ndarray
) -> np.ndarray:
    row_by_sha = {sha: i for i, sha in enumerate(corpus.shas)}
    reviewed_rows = np.zeros(len(corpus.shas), dtype=bool)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            record = json.loads(line)
            if not isinstance(record, dict) or set(record) != {"sha256", "labels"}:
                raise ValueError(f"{path}:{line_number}: expected sha256 and labels")
            sha, labels = record["sha256"], record["labels"]
            if not isinstance(sha, str) or sha not in row_by_sha:
                raise ValueError(f"{path}:{line_number}: SHA-256 is outside the frozen corpus")
            row = row_by_sha[sha]
            if reviewed_rows[row]:
                raise ValueError(f"{path}:{line_number}: duplicate SHA-256")
            if corpus.labels[row] < 0:
                raise ValueError(f"{path}:{line_number}: unlabeled PDF in the frozen corpus")
            if not isinstance(labels, dict) or not labels or labels.keys() - REVIEWED_HEAD_COLUMNS.keys():
                raise ValueError(f"{path}:{line_number}: expected reviewed labels for the rare behavior heads")
            for head, value in labels.items():
                if value is not None and not isinstance(value, bool):
                    raise ValueError(f"{path}:{line_number}: behavior label must be true, false or null")
                if value is True and corpus.labels[row] == 0:
                    raise ValueError(f"{path}:{line_number}: positive threat behavior on a benign PDF")
                col = REVIEWED_HEAD_COLUMNS[head]
                targets[row, col] = value is True
                masks[row, col] = value is not None
            reviewed_rows[row] = True
    return reviewed_rows


def _build_aux_and_targets(
    corpus: CSRGraphCorpus,
    graphs: list[PackedGraph | None],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Build 16D bounded auxiliary telemetry and strict BUG-020-compliant per-head (y, mask) matrices."""
    n = len(corpus.shas)
    raw = corpus.raw_73
    aux = np.zeros((n, AUX_TELEMETRY_V4_DIM), dtype=np.float32)
    y_mat = np.zeros((n, 8), dtype=np.float32)
    m_mat = np.zeros((n, 8), dtype=np.float32)

    for i in range(n):
        r = raw[i]
        g = graphs[i]
        nt = g[1] if g is not None else np.zeros((0,), dtype=np.int64)
        n_action = int((nt == 3).sum())
        n_script = int((nt == 5).sum())
        n_filespec = int((nt == 7).sum())
        is_bc = bool(corpus.is_bc[i])

        def fin(col: str) -> bool:
            return bool(np.isfinite(r[IDX[col]]))

        def val(col: str) -> float:
            v = float(r[IDX[col]])
            return v if math.isfinite(v) else 0.0

        acro = max(0.0, val("lexical_AcroForm"))
        esc = max(0.0, val("raw_escaped_name_candidates"))
        js_lex = max(0.0, val("lexical_JS")) + max(0.0, val("lexical_JavaScript"))
        js_act_fin = fin("legacy_v8_action_JavaScript")
        js_act = max(0.0, val("legacy_v8_action_JavaScript"))
        ostm = max(0.0, val("lexical_ObjStm"))
        esc_fin = fin("raw_escaped_name_candidates")

        verified_zero_js_bc = (
            is_bc
            and fin("lexical_JS")
            and fin("lexical_JavaScript")
            and js_lex == 0.0
            and js_act_fin
            and js_act == 0.0
            and n_script == 0
            and fin("lexical_ObjStm")
            and ostm == 0.0
            and esc_fin
            and esc == 0.0
        )

        has_act_launch = (
            val("lexical_Launch") > 0.0
            or val("legacy_v8_action_Launch") > 0.0
            or val("legacy_v8_action_GoToE") > 0.0
            or val("legacy_v8_action_GoToR") > 0.0
            or val("legacy_v8_action_ImportData") > 0.0
        )
        has_submit = val("legacy_v8_action_SubmitForm") > 0.0
        has_emb = (
            val("lexical_EmbeddedFile") > 0.0
            or val("legacy_v8_embedded_pe") > 0.0
            or val("legacy_v8_embedded_zip") > 0.0
            or val("legacy_v8_embedded_elf") > 0.0
            or val("legacy_v8_embedded_other") > 0.0
            or n_filespec > 0
        )
        has_struct_anom = (
            abs(val("obj_endobj_diff")) > 0.0
            or abs(val("stream_endstream_diff")) > 0.0
            or val("raw_header_offset") > 0.0
        )

        aux[i, 0] = float(np.log1p(acro))
        aux[i, 1] = float(np.log1p(esc))
        if verified_zero_js_bc:
            aux[i, 2] = 1.0
        aux[i, 12] = 1.0 if has_act_launch else 0.0
        aux[i, 13] = 1.0 if has_submit else 0.0
        aux[i, 14] = 1.0 if has_emb else 0.0
        aux[i, 15] = 1.0 if has_struct_anom else 0.0

        y_bin = int(corpus.labels[i])
        if y_bin < 0:
            continue
        if y_bin == 0:
            if is_bc:
                y_mat[i, :] = 0.0
                m_mat[i, :] = 1.0
            continue

        pos_0 = (js_lex > 0.0) or (js_act > 0.0) or (n_script > 0)
        pos_1 = (val("lexical_OpenAction") > 0.0) or (val("lexical_AA") > 0.0) or (n_action > 0)
        pos_2 = esc > 0.0
        pos_3 = False
        pos_4 = (val("lexical_XFA") > 0.0) or (val("lexical_JBIG2Decode") > 0.0) or (val("lexical_RichMedia") > 0.0)
        pos_5 = has_act_launch or has_emb
        pos_6 = has_submit or ((val("lexical_URI") > 0.0 or val("legacy_v8_action_URI") > 0.0) and not pos_0)
        pos_7 = has_struct_anom

        positives = (pos_0, pos_1, pos_2, pos_3, pos_4, pos_5, pos_6, pos_7)
        no_hidden_tokens_bc = is_bc and fin("lexical_ObjStm") and ostm == 0.0 and esc_fin and esc == 0.0
        action_cov_bc = (
            no_hidden_tokens_bc
            and fin("legacy_v8_action_Launch")
            and fin("legacy_v8_action_URI")
            and fin("legacy_v8_action_SubmitForm")
            and fin("legacy_v8_embedded_other")
        )
        neg_covered = (
            verified_zero_js_bc,
            no_hidden_tokens_bc and fin("lexical_OpenAction") and fin("lexical_AA"),
            verified_zero_js_bc,
            verified_zero_js_bc,
            verified_zero_js_bc,
            action_cov_bc,
            action_cov_bc and verified_zero_js_bc and fin("lexical_URI") and val("lexical_URI") == 0.0,
            is_bc and fin("obj_endobj_diff") and fin("stream_endstream_diff") and ostm == 0.0,
        )
        for k in range(8):
            if positives[k]:
                y_mat[i, k] = 1.0
                m_mat[i, k] = 1.0
            elif neg_covered[k]:
                y_mat[i, k] = 0.0
                m_mat[i, k] = 1.0

    return aux, y_mat, m_mat


def _augment_live_runtime_telemetry_batch(
    aux_b: np.ndarray,
    y_b: np.ndarray,
    m_b: np.ndarray,
    y_bin_b: np.ndarray,
    raw_b: np.ndarray,
    rng: np.random.Generator,
    reviewed_rows: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Teach live scanner AST/phishing telemetry channels on verified train batches without unverified external labels."""
    aux_out = aux_b.copy()
    y_out = y_b.copy()
    m_out = m_b.copy()
    n = len(y_bin_b)

    for idx in range(n):
        if reviewed_rows is not None and reviewed_rows[idx]:
            continue
        yb = int(y_bin_b[idx])
        u = float(rng.random())
        if yb == 0:
            aux_out[idx, 2] = 1.0
            if u < 0.06:
                nc = float(rng.integers(6, 48))
                calls = float(rng.integers(1, max(2, int(nc * 0.35))))
                aux_out[idx, 3] = float(np.log1p(nc))
                aux_out[idx, 4] = float(np.log1p(float(rng.integers(2, 7))))
                aux_out[idx, 7] = float(np.clip(calls / nc, 0.0, 1.0))
                if float(rng.random()) < 0.25:
                    loops = float(rng.integers(1, 3))
                    aux_out[idx, 5] = float(np.log1p(loops))
                    aux_out[idx, 8] = 1.0
            y_out[idx, :] = 0.0
            m_out[idx, :] = 1.0
            continue

        has_js = bool(y_out[idx, 0] > 0.5)
        if has_js and u < 0.72:
            aux_out[idx, 2] = 1.0
            nc = float(rng.integers(18, 420))
            depth = float(rng.integers(4, 22))
            calls = float(rng.integers(2, max(3, int(nc * 0.45))))
            aux_out[idx, 3] = float(np.log1p(nc))
            aux_out[idx, 4] = float(np.log1p(depth))
            aux_out[idx, 7] = float(np.clip(calls / nc, 0.0, 1.0))

            mode = float(rng.random())
            if mode < 0.55:
                loops = float(rng.integers(1, 12))
                comp = float(rng.integers(1, 24))
                aux_out[idx, 5] = float(np.log1p(loops))
                aux_out[idx, 6] = float(np.log1p(comp))
                aux_out[idx, 8] = 1.0
                aux_out[idx, 9] = 1.0
                y_out[idx, 2] = 1.0
                y_out[idx, 3] = 1.0
                m_out[idx, 2] = 1.0
                m_out[idx, 3] = 1.0
            elif mode < 0.78:
                comp = float(rng.integers(1, 18))
                aux_out[idx, 6] = float(np.log1p(comp))
                aux_out[idx, 9] = 1.0
                y_out[idx, 2] = 1.0
                y_out[idx, 3] = 0.0
                m_out[idx, 2] = 1.0
                m_out[idx, 3] = 1.0
            else:
                y_out[idx, 3] = 0.0
                m_out[idx, 3] = 1.0
                if aux_out[idx, 1] == 0.0:
                    y_out[idx, 2] = 0.0
                    m_out[idx, 2] = 1.0

            if float(rng.random()) < 0.22:
                aux_out[idx, 10] = 1.0
                y_out[idx, 4] = 1.0
                m_out[idx, 4] = 1.0
            else:
                m_out[idx, 4] = 1.0

            if float(rng.random()) < 0.14:
                aux_out[idx, 11] = 1.0
                if float(rng.random()) < 0.5:
                    y_out[idx, 5] = 1.0
                    m_out[idx, 5] = 1.0
                else:
                    y_out[idx, 6] = 1.0
                    m_out[idx, 6] = 1.0
        elif (not has_js) and float(rng.random()) < 0.18:
            aux_out[idx, 2] = 1.0
            aux_out[idx, 13] = 1.0
            raw_b[idx, IDX["lexical_URI"]] = max(float(raw_b[idx, IDX["lexical_URI"]]), float(rng.integers(1, 6)))
            y_out[idx, 6] = 1.0
            m_out[idx, 6] = 1.0

    return aux_out, y_out, m_out


def _build_leak_free_partitions(
    corpus: CSRGraphCorpus,
    scoreable: np.ndarray,
) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    raw_test_rows = np.flatnonzero(corpus.roles == "test_internal")
    test_shas = set(np.asarray(corpus.shas)[raw_test_rows].tolist())
    test_groups = set(corpus.groups[raw_test_rows].tolist())
    in_test = np.array(
        [(s in test_shas) or (str(g) in test_groups) for s, g in zip(corpus.shas, corpus.groups)], dtype=bool
    )

    raw_sel_rows = np.flatnonzero((corpus.roles == "val_select") & (~in_test))
    sel_shas = set(np.asarray(corpus.shas)[raw_sel_rows].tolist())
    sel_groups = set(corpus.groups[raw_sel_rows].tolist())
    in_sel = np.array(
        [(s in sel_shas) or (str(g) in sel_groups) for s, g in zip(corpus.shas, corpus.groups)], dtype=bool
    )

    raw_cal_rows = np.flatnonzero((corpus.roles == "val_calib") & (~in_test) & (~in_sel))
    cal_shas = set(np.asarray(corpus.shas)[raw_cal_rows].tolist())
    cal_groups = set(corpus.groups[raw_cal_rows].tolist())

    reserved_shas = test_shas | sel_shas | cal_shas
    reserved_groups = test_groups | sel_groups | cal_groups
    in_reserved = np.array(
        [(s in reserved_shas) or (str(g) in reserved_groups) for s, g in zip(corpus.shas, corpus.groups)], dtype=bool
    )

    eligible = scoreable & (corpus.labels >= 0)
    test_rows = np.flatnonzero((corpus.roles == "test_internal") & eligible)
    sel_rows = np.flatnonzero((corpus.roles == "val_select") & eligible & (~in_test))
    cal_rows = np.flatnonzero((corpus.roles == "val_calib") & eligible & (~in_test) & (~in_sel))
    train_rows = np.flatnonzero((corpus.roles == "train") & eligible & (~in_reserved))

    assert len(set(train_rows.tolist()) & set(sel_rows.tolist())) == 0
    assert len(set(train_rows.tolist()) & set(cal_rows.tolist())) == 0
    assert len(set(train_rows.tolist()) & set(test_rows.tolist())) == 0
    assert len(set(sel_rows.tolist()) & set(cal_rows.tolist())) == 0
    assert len(set(corpus.groups[train_rows].tolist()) & reserved_groups) == 0
    assert len(sel_groups & cal_groups) == 0
    assert len(sel_groups & test_groups) == 0
    assert len(cal_groups & test_groups) == 0

    audit = {
        "bug_020_cic_labels_preserved_as_null": True,
        "heldout_groups_reserved_before_filtering": True,
        "train_rows": int(len(train_rows)),
        "val_select_rows": int(len(sel_rows)),
        "val_calib_rows": int(len(cal_rows)),
        "test_internal_rows": int(len(test_rows)),
    }
    return {
        "train": train_rows,
        "val_select": sel_rows,
        "val_calib": cal_rows,
        "test_internal": test_rows,
    }, audit


@torch.inference_mode()
def _predict_multilabel_v4(
    model: PDFMultiLabelThreatNetV4,
    graphs: list[PackedGraph | None],
    ir: np.ndarray,
    active: np.ndarray,
    tab: np.ndarray,
    aux: np.ndarray,
    indices: np.ndarray,
    device: torch.device,
    *,
    batch_size: int = 128,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    if len(indices) == 0:
        return np.empty((0, 8), dtype=np.float32), np.empty((0,), dtype=np.float32)
    lengths = np.asarray([0 if graphs[int(i)] is None else len(graphs[int(i)][0]) for i in indices], dtype=np.int32)
    order = np.argsort(lengths, kind="stable")
    sorted_idx = indices[order]
    sorted_len = lengths[order]
    lbl_list, mal_list = [], []
    start = 0
    while start < len(sorted_idx):
        rem_max = int(sorted_len[min(len(sorted_len) - 1, start + batch_size - 1)])
        step = 32 if rem_max > 160 else (64 if rem_max > 64 else batch_size)
        b = sorted_idx[start : start + step]
        start += step
        out = model(
            torch.from_numpy(tab[b]).to(device),
            torch.from_numpy(ir[b]).to(device),
            torch.from_numpy(active[b]).to(device),
            *build_padded_graph_tensors([graphs[int(i)] for i in b], device, min_nodes=1),
            torch.from_numpy(aux[b]).to(device),
        )
        lbl_list.append(out["label_logits"].cpu().numpy())
        mal_list.append(out["mal_logit"].cpu().numpy())
    all_lbl = np.concatenate(lbl_list, axis=0)
    all_mal = np.concatenate(mal_list, axis=0)
    inv = np.empty_like(order)
    inv[order] = np.arange(len(order))
    return all_lbl[inv], all_mal[inv]


def _fit_masked_head_temperature(logits: np.ndarray, y: np.ndarray, mask: np.ndarray) -> float:
    valid = mask > 0.5
    z = np.asarray(logits[valid], dtype=np.float64)
    t_y = np.asarray(y[valid], dtype=np.float64)
    if len(z) < 20 or int((t_y > 0.5).sum()) < 8 or int((t_y < 0.5).sum()) < 20:
        return 1.0

    def nll(log_t: float) -> float:
        temp = math.exp(log_t)
        s = np.clip(z / temp, -40.0, 40.0)
        return float(np.mean(np.logaddexp(0.0, s) - t_y * s))

    res = minimize_scalar(nll, bounds=(math.log(0.50), math.log(1.50)), method="bounded")
    return float(np.clip(math.exp(float(res.x)), 0.50, 1.50))


def _calibrate_head_threshold(
    probs: np.ndarray,
    y_head: np.ndarray,
    mask_head: np.ndarray,
    y_bin: np.ndarray,
    *,
    max_benign_fpr: float = 0.001,
) -> dict[str, Any]:
    ben_mask = y_bin == 0
    eval_mask = mask_head > 0.5
    pos_mask = eval_mask & (y_head > 0.5)
    positive_count = int(pos_mask.sum())
    ben_probs = np.asarray(probs[ben_mask], dtype=np.float64)

    def disabled(reason: str) -> dict[str, Any]:
        return {
            "threshold": 1.01,
            "model_flag_enabled": False,
            "val_calib_pos": positive_count,
            "val_calib_benign": int(ben_mask.sum()),
            "val_calib_benign_fpr": 0.0,
            "val_calib_f1": 0.0 if positive_count else None,
            "disable_reason": reason,
        }

    if positive_count == 0:
        return disabled("no_calibration_positives")
    if len(ben_probs) == 0:
        return disabled("no_calibration_benign")

    thresholds = np.arange(2_000, 10_000) / 10_000
    benign_fp = len(ben_probs) - np.searchsorted(np.sort(ben_probs), thresholds)
    benign_fpr = benign_fp / len(ben_probs)
    legal = benign_fpr <= max_benign_fpr
    if not legal.any():
        return disabled("no_threshold_within_fpr_budget")

    evaluated_probs = np.sort(probs[eval_mask])
    predicted = len(evaluated_probs) - np.searchsorted(evaluated_probs, thresholds)
    true_positives = positive_count - np.searchsorted(np.sort(probs[pos_mask]), thresholds)
    eligible = legal & (true_positives > 0)
    if not eligible.any():
        return disabled("no_positives_detected_within_fpr_budget")

    f1 = 2 * true_positives / (positive_count + predicted)
    best = np.flatnonzero(eligible & (f1 >= np.max(f1[eligible]) - 1e-6))
    selected = best[np.argmin(np.abs(thresholds[best] - 0.5))]
    return {
        "threshold": float(thresholds[selected]),
        "model_flag_enabled": True,
        "val_calib_pos": positive_count,
        "val_calib_benign": int(ben_mask.sum()),
        "val_calib_benign_fpr": round(float(benign_fpr[selected]), 6),
        "val_calib_f1": round(float(f1[selected]), 4),
    }


def _evaluate_multilabel_cohort(
    probs: np.ndarray,
    y_mat: np.ndarray,
    m_mat: np.ndarray,
    y_bin: np.ndarray,
    thresholds: list[float],
    enabled_flags: list[bool],
) -> dict[str, Any]:
    per_head: dict[str, Any] = {}
    ap_vals, f1_vals = [], []
    ben_rows = y_bin == 0
    any_ben_fp = np.zeros(int(ben_rows.sum()), dtype=bool)
    for k, hid in enumerate(EXPECTED_HEAD_IDS_V4):
        valid = m_mat[:, k] > 0.5
        yk = (y_mat[valid, k] > 0.5).astype(np.int64)
        pk = probs[valid, k]
        thr = float(thresholds[k])
        enabled = enabled_flags[k]
        pred = ((pk >= thr) if enabled else np.zeros_like(pk, dtype=bool)).astype(np.int64)
        pos_n = int(yk.sum())
        ben_fp_rate = (
            float(np.mean((probs[ben_rows, k] >= thr) if enabled else np.zeros(int(ben_rows.sum()), dtype=bool)))
            if ben_rows.any()
            else 0.0
        )
        if ben_rows.any() and enabled:
            any_ben_fp |= probs[ben_rows, k] >= thr
        ap = float(average_precision_score(yk, pk)) if 0 < pos_n < len(yk) else None
        auc = float(roc_auc_score(yk, pk)) if 0 < pos_n < len(yk) else None
        f1 = float(f1_score(yk, pred, zero_division=0)) if pos_n > 0 else None
        prec = float(precision_score(yk, pred, zero_division=0)) if pos_n > 0 else None
        rec = float(recall_score(yk, pred, zero_division=0)) if pos_n > 0 else None
        if ap is not None:
            ap_vals.append(ap)
        if f1 is not None:
            f1_vals.append(f1)
        per_head[hid] = {
            "evaluated_rows": int(valid.sum()),
            "positive_support": pos_n,
            "threshold": thr,
            "model_flag_enabled": enabled,
            "pr_auc": round(ap, 4) if ap is not None else None,
            "roc_auc": round(auc, 4) if auc is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "precision": round(prec, 4) if prec is not None else None,
            "recall": round(rec, 4) if rec is not None else None,
            "benign_fpr": round(ben_fp_rate, 6),
        }
    return {
        "macro_pr_auc": round(float(np.mean(ap_vals)), 4) if ap_vals else 0.0,
        "macro_f1": round(float(np.mean(f1_vals)), 4) if f1_vals else 0.0,
        "any_head_benign_fpr": round(float(np.mean(any_ben_fp)), 6) if len(any_ben_fp) else 0.0,
        "per_head": per_head,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1.2e-3)
    parser.add_argument(
        "--reviewed-behavior-labels", type=Path, help="Reviewed rare behavior labels by corpus SHA-256 (JSONL)"
    )
    args = parser.parse_args()

    t_start = time.perf_counter()
    set_all_seeds(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.set_num_threads(min(torch.get_num_threads(), 4))
    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    run_id = f"run_{now:%Y%m%dT%H%M%S%fZ}_{git_rev}"

    pool_path = DEFAULT_POOL if DEFAULT_POOL.is_file() else POOL_ROOT / "pooled.jsonl.gz"
    input_paths = {
        "pool": pool_path,
        "tabular": DEFAULT_TABULAR,
        "label_view": DEFAULT_LABEL_VIEW,
        "split_view": DEFAULT_SPLIT_VIEW,
        "benign_supplement": DEFAULT_SUPP,
    }
    if args.reviewed_behavior_labels is not None:
        input_paths["reviewed_behavior_labels"] = args.reviewed_behavior_labels
    input_hashes = {k: digest(p) for k, p in input_paths.items()}

    print(f"[BUG-038] Loading verified v4 corpus (BUG-020 CIC null preserved) on {device}...", flush=True)
    corpus = load_pooled_corpus(
        pool_path=pool_path,
        tabular_path=DEFAULT_TABULAR,
        label_view_path=DEFAULT_LABEL_VIEW,
        split_view_path=DEFAULT_SPLIT_VIEW,
        benign_supplement_path=DEFAULT_SUPP,
    )
    graphs, ir, active = precompute_corpus(corpus)
    scoreable = np.isfinite(corpus.raw_73[:, REGIME_B_INDICES]).all(axis=1)
    aux_all, y_mat, m_mat = _build_aux_and_targets(corpus, graphs)
    reviewed_rows = None
    if args.reviewed_behavior_labels is not None:
        reviewed_rows = _apply_reviewed_behavior_labels(args.reviewed_behavior_labels, corpus, y_mat, m_mat)
    parts, split_audit = _build_leak_free_partitions(corpus, scoreable)

    train_rows = parts["train"]
    select_rows = parts["val_select"]
    calib_rows = parts["val_calib"]
    test_int_rows = parts["test_internal"]
    reviewed_train = reviewed_rows[train_rows] if reviewed_rows is not None else None
    if reviewed_rows is not None:
        split_audit["reviewed_behavior_rows"] = {name: int(reviewed_rows[rows].sum()) for name, rows in parts.items()}
    print(f"[BUG-038] Leak-free split audit: {json.dumps(split_audit)}", flush=True)

    transform = RobustTransform.fit(corpus.raw_73[train_rows], roles=["train"] * len(train_rows))
    tab_all, _, _, _ = slice_regime_inputs(*transform.transform(corpus.raw_73), "regime_b")
    tab29_center = transform.center[REGIME_B_INDICES].astype(np.float64)
    tab29_scale = transform.scale[REGIME_B_INDICES].astype(np.float64)

    y_train_m = y_mat[train_rows] * m_mat[train_rows]
    pos_cnt = np.maximum(y_train_m.sum(axis=0), 25.0)
    cov_cnt = np.maximum(m_mat[train_rows].sum(axis=0), pos_cnt + 1.0)
    neg_cnt = np.maximum(cov_cnt - pos_cnt, 1.0)
    pos_weight_vec = torch.from_numpy(np.clip(np.sqrt(neg_cnt / pos_cnt), 1.0, 5.0).astype(np.float32)).to(device)

    sample_w_all = np.ones(len(corpus.shas), dtype=np.float32)
    sample_w_all[train_rows] = compute_debiased_weights(
        corpus.labels[train_rows], corpus.is_bc[train_rows], corpus.label_sources[train_rows]
    )
    node_counts = np.asarray([0 if g is None else len(g[0]) for g in graphs], dtype=np.int32)
    can_linearize = np.isfinite(corpus.raw_73[:, IDX["lexical_xref"]]) & (corpus.raw_73[:, IDX["lexical_ObjStm"]] == 0)

    config = MultiLabelV4Config()
    model = PDFMultiLabelThreatNetV4(config).to(device)
    ema_model = deepcopy(model).eval()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=2e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=2e-5)
    rng = np.random.default_rng(args.seed)

    best_score = -1e9
    best_state: dict[str, torch.Tensor] | None = None
    best_epoch = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        raw_aug_tr = perturb_raw_format(corpus.raw_73[train_rows], can_linearize[train_rows], rng, enable_padding=True)
        has_g_tr = np.asarray([graphs[int(i)] is not None for i in train_rows], dtype=bool)
        raw_aug_tr = simulate_objstm_tabular_mask(raw_aug_tr, has_g_tr, rng, prob=0.18)

        aux_ep = aux_all.copy()
        y_ep = y_mat.copy()
        m_ep = m_mat.copy()
        aux_tr, y_tr, m_tr = _augment_live_runtime_telemetry_batch(
            aux_all[train_rows],
            y_mat[train_rows],
            m_mat[train_rows],
            corpus.labels[train_rows],
            raw_aug_tr,
            rng,
            reviewed_train,
        )
        _recompute_derived(raw_aug_tr)
        tab_aug_tr, _, _, _ = slice_regime_inputs(*transform.transform(raw_aug_tr), "regime_b")
        tab_epoch = tab_all.copy()
        tab_epoch[train_rows] = tab_aug_tr
        aux_ep[train_rows] = aux_tr
        y_ep[train_rows] = y_tr
        m_ep[train_rows] = m_tr

        batches = _make_macro_bucketed_batches(train_rows, node_counts, args.batch_size, rng)
        ep_loss = 0.0
        for b_idx in batches:
            optimizer.zero_grad(set_to_none=True)
            t_tab = torch.from_numpy(tab_epoch[b_idx]).to(device)
            t_ir = torch.from_numpy(ir[b_idx]).to(device)
            t_act = torch.from_numpy(active[b_idx]).to(device)
            t_aux = torch.from_numpy(aux_ep[b_idx]).to(device)
            t_y = torch.from_numpy(y_ep[b_idx]).to(device)
            t_m = torch.from_numpy(m_ep[b_idx]).to(device)
            t_yb = torch.from_numpy(corpus.labels[b_idx].astype(np.float32)).to(device)
            t_sw = torch.from_numpy(sample_w_all[b_idx]).to(device)
            g_tensors = build_padded_graph_tensors([graphs[int(i)] for i in b_idx], device, min_nodes=1)

            out = model(t_tab, t_ir, t_act, *g_tensors, t_aux)
            bce_raw = F.binary_cross_entropy_with_logits(
                out["label_logits"], t_y, pos_weight=pos_weight_vec, reduction="none"
            )
            masked_bce = (bce_raw * t_m * t_sw.unsqueeze(-1)).sum() / torch.clamp(
                (t_m * t_sw.unsqueeze(-1)).sum(), min=1.0
            )
            mal_bce = (F.binary_cross_entropy_with_logits(out["mal_logit"], t_yb, reduction="none") * t_sw).mean()

            ben_local = np.flatnonzero(corpus.labels[b_idx] == 0)
            stab_loss = out["label_logits"].sum() * 0.0
            if len(ben_local) >= 4:
                ben_global = b_idx[ben_local]
                pad_raw = corpus.raw_73[ben_global].copy()
                n_b = len(ben_global)
                d_pages = rng.integers(35, 160, size=n_b, dtype=np.int32)
                d_obj = (d_pages * rng.integers(35, 95, size=n_b, dtype=np.int32)).astype(np.float32)
                d_st = np.floor(d_obj * 0.45).astype(np.float32)
                pad_raw[:, IDX["lexical_page_command"]] += d_pages.astype(np.float32)
                pad_raw[:, IDX["lexical_obj"]] += d_obj
                pad_raw[:, IDX["lexical_endobj"]] += d_obj
                pad_raw[:, IDX["lexical_stream"]] += d_st
                pad_raw[:, IDX["lexical_endstream"]] += d_st
                pad_raw[:, IDX["lexical_Resources"]] += (d_pages * 3).astype(np.float32)
                pad_raw[:, IDX["lexical_URI"]] += rng.integers(0, 150, size=n_b).astype(np.float32)
                pad_raw[:, IDX["lexical_ObjStm"]] += rng.integers(0, 12, size=n_b).astype(np.float32)
                pad_raw[:, IDX["raw_size_bytes"]] += (d_pages.astype(np.int64) * 95_000).astype(np.float32)
                _recompute_derived(pad_raw)
                tab_pad, _, _, _ = slice_regime_inputs(*transform.transform(pad_raw), "regime_b")
                out_clean = out["label_logits"][ben_local].detach()
                g_ben = build_padded_graph_tensors([graphs[int(i)] for i in ben_global], device, min_nodes=1)
                out_pad = model(
                    torch.from_numpy(tab_pad).to(device),
                    torch.from_numpy(ir[ben_global]).to(device),
                    torch.from_numpy(active[ben_global]).to(device),
                    *g_ben,
                    torch.from_numpy(aux_ep[ben_global]).to(device),
                )
                viol = F.relu(torch.sigmoid(out_pad["label_logits"]) - torch.sigmoid(out_clean))
                stab_loss = (viol * viol).mean() + 0.5 * torch.sigmoid(out_pad["label_logits"]).mean()

            loss = masked_bce + 0.30 * mal_bce + 0.40 * stab_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0)
            optimizer.step()
            with torch.no_grad():
                if epoch <= 2:
                    ema_model.load_state_dict(model.state_dict())
                else:
                    decay = 0.90
                    for p_ema, p_cur in zip(ema_model.parameters(), model.parameters(), strict=True):
                        p_ema.data.mul_(decay).add_(p_cur.data, alpha=1.0 - decay)
                    for b_ema, b_cur in zip(ema_model.buffers(), model.buffers(), strict=True):
                        b_ema.copy_(b_cur)
            ep_loss += float(loss.item())
        scheduler.step()

        sel_lbl_logits, sel_mal_logits = _predict_multilabel_v4(
            ema_model, graphs, ir, active, tab_all, aux_all, select_rows, device
        )
        sel_probs = 1.0 / (1.0 + np.exp(-np.clip(sel_lbl_logits, -40.0, 40.0)))
        sel_eval = _evaluate_multilabel_cohort(
            sel_probs, y_mat[select_rows], m_mat[select_rows], corpus.labels[select_rows], [0.5] * 8, [True] * 8
        )
        mal_ap = float(
            average_precision_score(
                corpus.labels[select_rows], 1.0 / (1.0 + np.exp(-np.clip(sel_mal_logits, -40.0, 40.0)))
            )
        )
        score = sel_eval["macro_pr_auc"] + 0.15 * mal_ap - 0.5 * sel_eval["any_head_benign_fpr"]
        if epoch >= 3 and score > best_score:
            best_score = score
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in ema_model.state_dict().items()}
        if epoch in (1, 5, 10, 15, args.epochs):
            print(
                f"  epoch {epoch:02d}/{args.epochs} loss={ep_loss / max(len(batches), 1):.4f} "
                f"val_select_macro_AP={sel_eval['macro_pr_auc']:.4f} ben_fpr@0.5={sel_eval['any_head_benign_fpr']:.4f}",
                flush=True,
            )

    assert best_state is not None
    model.load_state_dict(best_state, strict=True)
    model.eval()

    cal_lbl_logits, cal_mal_logits = _predict_multilabel_v4(
        model, graphs, ir, active, tab_all, aux_all, calib_rows, device
    )
    cal_y_bin = corpus.labels[calib_rows]
    mal_temperature = round(float(fit_temperature(cal_mal_logits, cal_y_bin)), 6)

    label_temps: list[float] = []
    cal_probs = np.zeros_like(cal_lbl_logits, dtype=np.float64)
    head_cal_records: list[dict[str, Any]] = []
    thresholds: list[float] = []
    enabled_flags: list[bool] = []
    for k in range(8):
        tk = round(_fit_masked_head_temperature(cal_lbl_logits[:, k], y_mat[calib_rows, k], m_mat[calib_rows, k]), 6)
        label_temps.append(tk)
        cal_probs[:, k] = apply_temperature(cal_lbl_logits[:, k], tk)
        h_rec = _calibrate_head_threshold(
            cal_probs[:, k], y_mat[calib_rows, k], m_mat[calib_rows, k], cal_y_bin, max_benign_fpr=0.001
        )
        thresholds.append(float(h_rec["threshold"]))
        enabled_flags.append(bool(h_rec["model_flag_enabled"]))
        head_cal_records.append(h_rec)

    cal_ben = cal_y_bin == 0
    while cal_ben.any():
        flags_mat = np.column_stack(
            [
                (cal_probs[cal_ben, k] >= thresholds[k])
                if enabled_flags[k]
                else np.zeros(int(cal_ben.sum()), dtype=bool)
                for k in range(8)
            ]
        )
        if float(np.mean(flags_mat.any(axis=1))) <= 0.005:
            break
        worst_k = int(np.argmax(flags_mat.sum(axis=0)))
        offending = cal_probs[cal_ben, worst_k][flags_mat[:, worst_k]]
        next_thr = round(float(np.min(offending)) + 2e-4, 4)
        positives = (m_mat[calib_rows, worst_k] > 0.5) & (y_mat[calib_rows, worst_k] > 0.5)
        if next_thr <= 0.9999 and (cal_probs[positives, worst_k] >= next_thr).any():
            thresholds[worst_k] = next_thr
        else:
            thresholds[worst_k] = 1.01
            enabled_flags[worst_k] = False
            head_cal_records[worst_k]["disable_reason"] = "combined_fpr_budget"

    def eval_indices(idx_arr: np.ndarray) -> dict[str, Any]:
        z_lbl, z_mal = _predict_multilabel_v4(model, graphs, ir, active, tab_all, aux_all, idx_arr, device)
        p_lbl = np.column_stack([apply_temperature(z_lbl[:, k], label_temps[k]) for k in range(8)])
        p_mal = apply_temperature(z_mal, mal_temperature)
        res = _evaluate_multilabel_cohort(
            p_lbl, y_mat[idx_arr], m_mat[idx_arr], corpus.labels[idx_arr], thresholds, enabled_flags
        )
        res["aux_binary_pr_auc"] = round(float(average_precision_score(corpus.labels[idx_arr], p_mal)), 4)
        res["aux_binary_roc_auc"] = round(float(roc_auc_score(corpus.labels[idx_arr], p_mal)), 4)
        return res

    val_calib_metrics = eval_indices(calib_rows)
    for head, record in zip(EXPECTED_HEAD_IDS_V4, head_cal_records, strict=True):
        final = val_calib_metrics["per_head"][head]
        record.update(
            threshold=final["threshold"],
            model_flag_enabled=final["model_flag_enabled"],
            val_calib_benign_fpr=final["benign_fpr"],
            val_calib_f1=final["f1"],
        )
    assert val_calib_metrics["any_head_benign_fpr"] <= 0.005
    for hid_m in val_calib_metrics["per_head"].values():
        assert hid_m["benign_fpr"] <= 0.001
    test_internal_metrics = eval_indices(test_int_rows)

    ben_test_rows = test_int_rows[corpus.labels[test_int_rows] == 0]
    heavy_book_raw = corpus.raw_73[ben_test_rows].copy()
    heavy_book_raw[:, IDX["lexical_page_command"]] += 120.0
    heavy_book_raw[:, IDX["lexical_obj"]] += 12_500.0
    heavy_book_raw[:, IDX["lexical_endobj"]] += 12_500.0
    heavy_book_raw[:, IDX["lexical_stream"]] += 5_200.0
    heavy_book_raw[:, IDX["lexical_endstream"]] += 5_200.0
    heavy_book_raw[:, IDX["lexical_Resources"]] += 360.0
    heavy_book_raw[:, IDX["lexical_URI"]] += 85.0
    heavy_book_raw[:, IDX["lexical_ObjStm"]] += 16.0
    heavy_book_raw[:, IDX["raw_size_bytes"]] += 8_500_000.0
    _recompute_derived(heavy_book_raw)
    tab_heavy, _, _, _ = slice_regime_inputs(*transform.transform(heavy_book_raw), "regime_b")
    model.eval()
    with torch.inference_mode():
        z_heavy_list = []
        for s in range(0, len(ben_test_rows), 64):
            sl = ben_test_rows[s : s + 64]
            out_h = model(
                torch.from_numpy(tab_heavy[s : s + 64]).to(device),
                torch.from_numpy(ir[sl]).to(device),
                torch.from_numpy(active[sl]).to(device),
                *build_padded_graph_tensors([graphs[int(i)] for i in sl], device, min_nodes=1),
                torch.from_numpy(aux_all[sl]).to(device),
            )
            z_heavy_list.append(out_h["label_logits"].cpu().numpy())
        z_heavy = np.concatenate(z_heavy_list, axis=0)
    p_heavy = np.column_stack([apply_temperature(z_heavy[:, k], label_temps[k]) for k in range(8)])
    heavy_flags = np.column_stack(
        [(p_heavy[:, k] >= thresholds[k]) if enabled_flags[k] else np.zeros(len(p_heavy), dtype=bool) for k in range(8)]
    )
    heavy_book_any_fpr = float(np.mean(heavy_flags.any(axis=1)))

    DEFAULT_OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    save_multilabel_v4_npz(model, DEFAULT_OUT_MODEL)
    load_multilabel_v4_npz(model, DEFAULT_OUT_MODEL, map_location=device)
    weights_sha = hashlib.sha256(DEFAULT_OUT_MODEL.read_bytes()).hexdigest()

    labels_contract = []
    for k, base_def in enumerate(MULTILABEL_THREAT_DEFINITIONS):
        labels_contract.append(
            {
                **base_def,
                "threshold": thresholds[k],
                "temperature": label_temps[k],
                "model_flag_enabled": enabled_flags[k],
            }
        )

    contract_payload = {
        "contract_version": MULTILABEL_V4_CONTRACT_VERSION,
        "model_version": "PDFMultiLabelThreatNet v4",
        "source_run": run_id,
        "fitted_on": "verified_clean_split_20261122T064432Z+v32_benign_supplement_bug020_cic_null_preserved",
        "seed": args.seed,
        "checkpoint_relpath": str(DEFAULT_OUT_MODEL.relative_to(REPO)).replace("\\", "/"),
        "weights_npz_sha256": weights_sha,
        "v4_binary_contract_sha256": hashlib.sha256(
            V4_BINARY_CONTRACT_PATH.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest(),
        "model_config": config.to_dict(),
        "tab_feature_names": list(REGIME_B_NAMES),
        "aux_feature_names": list(AUX_TELEMETRY_V4_NAMES),
        "tab29_center": [float(x) for x in tab29_center.tolist()],
        "tab29_scale": [float(x) for x in tab29_scale.tolist()],
        "label_temperatures": label_temps,
        "mal_temperature": mal_temperature,
        "labels": labels_contract,
    }
    validate_multilabel_v4_contract(contract_payload, REGIME_B_NAMES)
    DEFAULT_OUT_CONTRACT.write_text(
        json.dumps(contract_payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
    )

    exp_dir = DEFAULT_REPORT_ROOT / run_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    methodology = {
        "generated_utc": now.isoformat(),
        "run_id": run_id,
        "git_revision": git_rev,
        "device": str(device),
        "seed": args.seed,
        "epochs": args.epochs,
        "best_epoch": best_epoch,
        "inputs_sha256": input_hashes,
        "split_audit": split_audit,
        "calibration_rule": "Per-head masked NLL temperature in [0.50, 1.50]; maximize positive F1 over four-decimal thresholds in [0.20, 0.9999]; benign Val_Calib FPR <= 0.1% per head and <= 0.5% combined under runtime >=",
    }
    meth_path = exp_dir / "locked_methodology.json"
    meth_path.write_text(json.dumps(methodology, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    metrics_report = {
        "run_id": run_id,
        "locked_methodology_sha256": digest(meth_path),
        "weights_npz_sha256": weights_sha,
        "parameter_count": int(sum(p.numel() for p in model.parameters())),
        "elapsed_seconds": round(time.perf_counter() - t_start, 2),
        "head_calibration": dict(zip(EXPECTED_HEAD_IDS_V4, head_cal_records, strict=True)),
        "val_calib": val_calib_metrics,
        "test_internal": test_internal_metrics,
        "heavy_120p_12500obj_benign_any_head_fpr": round(heavy_book_any_fpr, 6),
    }
    (exp_dir / "metrics.json").write_text(
        json.dumps(metrics_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(metrics_report, indent=2, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
