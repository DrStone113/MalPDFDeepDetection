from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import time
from typing import Any

import numpy as np
import onnxruntime as ort
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
import torch

REPO_ROOT = Path(__file__).resolve().parents[2]
for candidate in (REPO_ROOT / "src", REPO_ROOT / "production", REPO_ROOT):
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from malpdf.cdr.engine import PDFDisarmer
from malpdf.data.graph_export_v2_loader import (
    load_multimodal_dataset_v2,
    safe_div_series,
    verify_graph_export_v2_directory,
)
from malpdf.models.multilabel_threat_net import (
    LEXICAL_EXTRA_FEATURE_NAMES,
    MULTILABEL_THREAT_DEFINITIONS,
    PDFMultiLabelThreatNet,
)
from malpdf.models.pdf_transgraph import PDFTransGraph
from malpdf.scanner.ingestion import AST_NODE_TYPES
from onnx_engine import ONNXMalPDFScannerEngine


def _sigmoid_np(x: np.ndarray | float) -> np.ndarray | float:
    clipped = np.clip(x, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _extract_v2_float(feat_map: dict[str, Any], key: str, fallback: float = 0.0) -> float:
    item = feat_map.get(key)
    if not isinstance(item, dict):
        return fallback
    val = item.get("value")
    if val is None:
        return fallback
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)) and np.isfinite(val):
        return float(val)
    return fallback


def build_eval_multilabel_splits(
    export_dir: Path,
    parquet_ours_path: Path,
    parquet_cic_path: Path,
    verified_export: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verified = verified_export if verified_export is not None else verify_graph_export_v2_directory(export_dir)
    tabular_rows = verified["tabular_rows"]
    graph_dict = verified["graph_dict"]

    df_ours = pd.read_parquet(parquet_ours_path)
    df_cic = pd.read_parquet(parquet_cic_path)
    merged = pd.merge(df_ours, df_cic, left_on="pdf_sha256", right_on="FileName", how="inner")
    merged = merged.set_index("pdf_sha256").loc[[r["sha256"] for r in tabular_rows]].reset_index()

    for pos, row in enumerate(tabular_rows):
        fmap = row["features"]
        for ent_col in ("raw_entropy", "raw_prefix_entropy", "raw_suffix_entropy"):
            if ent_col in fmap and fmap[ent_col].get("value") is not None:
                merged.loc[pos, ent_col] = _extract_v2_float(fmap, ent_col, float(merged.loc[pos, ent_col]))
        for ast_col in (
            "legacy_observed_ast_node_count",
            "legacy_observed_ast_max_depth",
            "legacy_observed_ast_loops",
            "legacy_observed_ast_computed_members",
            "legacy_observed_ast_type_CallExpression",
            "legacy_observed_ast_type_Identifier",
        ):
            if ast_col in fmap and fmap[ast_col].get("value") is not None:
                merged.loc[pos, ast_col] = _extract_v2_float(fmap, ast_col, 0.0)

    cic_cols = [c for c in df_cic.columns if c not in {"FileName", "Class"}]
    for col in cic_cols:
        merged[col] = pd.to_numeric(merged[col], errors="coerce").fillna(-1.0)

    merged["density_stream_ratio"] = safe_div_series(merged["Stream"], merged["PdfSize"])
    merged["density_obj_stream_ratio"] = safe_div_series(merged["Obj"], merged["Stream"])
    merged["density_metadata_ratio"] = safe_div_series(merged["MetadataSize"], merged["PdfSize"])
    merged["entropy_gap"] = (merged["raw_prefix_entropy"] - merged["raw_suffix_entropy"]).abs().fillna(0.0)
    merged["ast_complexity_per_node"] = safe_div_series(
        merged["legacy_observed_ast_max_depth"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_call_ratio"] = safe_div_series(
        merged["legacy_observed_ast_type_CallExpression"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_identifier_ratio"] = safe_div_series(
        merged["legacy_observed_ast_type_Identifier"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_computed_ratio"] = safe_div_series(
        merged["legacy_observed_ast_computed_members"],
        merged["legacy_observed_ast_node_count"],
    )

    base_38_cols = [
        "Javascript",
        "JS",
        "Stream",
        "Endstream",
        "Obj",
        "Endobj",
        "MetadataSize",
        "PdfSize",
        "Pages",
        "PageNo",
        "XFA",
        "OpenAction",
        "Colors",
        "Images",
        "density_stream_ratio",
        "density_obj_stream_ratio",
        "density_metadata_ratio",
        "entropy_gap",
        "ast_complexity_per_node",
        "ast_call_ratio",
        "ast_identifier_ratio",
        "ast_computed_ratio",
        "byte_image_file_encoded_ratio",
        "byte_image_file_persisted_ratio",
        "stream_truncation_ratio",
        "legacy_observed_ast_node_count",
        "legacy_observed_ast_max_depth",
        "legacy_observed_ast_loops",
        "legacy_observed_ast_computed_members",
        "evasive_timeout_anomaly",
        "flag_decompression_ratio_exceeded",
        "is_truncated_stream",
        "flag_spec_violation_flood",
        "flag_excessive_object_graph",
        "flag_ast_complexity_truncated",
        "raw_entropy",
        "raw_prefix_entropy",
        "raw_suffix_entropy",
    ]
    num_raw = lambda c: pd.to_numeric(merged[c], errors="coerce").fillna(0.0)
    merged["ast_has_loop"] = (
        (num_raw("legacy_observed_ast_loops") > 0)
        | (num_raw("legacy_observed_ast_type_ForStatement") > 0)
        | (num_raw("legacy_observed_ast_type_WhileStatement") > 0)
    ).astype(np.float32)
    merged["js_has_deobf_call"] = (
        (num_raw("legacy_v8_pypdf_call_unescape") > 0)
        | (num_raw("legacy_v8_pypdf_call_eval") > 0)
        | (num_raw("legacy_v8_pypdf_call_String.fromCharCode") > 0)
    ).astype(np.float32)
    merged["effective_uri_count"] = np.maximum(
        np.maximum(np.maximum(num_raw("lexical_URI"), 0.0), np.maximum(num_raw("canonical_URI"), 0.0)),
        np.maximum(num_raw("legacy_v8_action_URI"), 0.0),
    ).astype(np.float32)
    merged["effective_embedded_or_launch"] = (
        np.maximum(np.maximum(num_raw("EmbeddedFile"), 0.0), np.maximum(num_raw("lexical_EmbeddedFile"), 0.0))
        + np.maximum(np.maximum(num_raw("Launch"), 0.0), np.maximum(num_raw("lexical_Launch"), 0.0))
    ).astype(np.float32)

    all_tab_cols = base_38_cols + LEXICAL_EXTRA_FEATURE_NAMES
    for col in all_tab_cols:
        merged[col] = pd.to_numeric(merged[col], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)

    is_mal = merged["Label"].astype(int) == 1
    num = lambda c: pd.to_numeric(merged[c], errors="coerce").fillna(0.0)
    target_series = {
        "js_script_exec": is_mal
        & (
            (num("JS") > 0)
            | (num("Javascript") > 0)
            | (num("lexical_JS") > 0)
            | (num("lexical_JavaScript") > 0)
            | (num("legacy_v8_action_JavaScript") > 0)
        ),
        "auto_open_trigger": is_mal
        & (
            (num("OpenAction") > 0)
            | (num("AA") > 0)
            | (num("lexical_OpenAction") > 0)
            | (num("lexical_AA") > 0)
        ),
        "obfuscated_payload": is_mal
        & (
            (num("raw_escaped_name_candidates") > 0)
            | (num("legacy_v8_pypdf_call_unescape") > 0)
            | (num("legacy_v8_pypdf_call_eval") > 0)
            | (num("legacy_v8_pypdf_call_String.fromCharCode") > 0)
            | (num("legacy_observed_ast_computed_members") > 0)
        ),
        "buffer_loop_staging": is_mal
        & (
            (num("legacy_observed_ast_loops") > 0)
            | (num("legacy_observed_ast_type_ForStatement") > 0)
            | (num("legacy_observed_ast_type_WhileStatement") > 0)
        ),
        "active_form_or_exploit": is_mal
        & (
            (num("XFA") > 0)
            | (num("lexical_XFA") > 0)
            | (num("JBIG2Decode") > 0)
            | (num("lexical_JBIG2Decode") > 0)
            | (num("RichMedia") > 0)
            | (num("lexical_RichMedia") > 0)
            | (num("legacy_v8_pypdf_call_util.printf") > 0)
            | (num("legacy_v8_pypdf_call_Collab.collectEmailInfo") > 0)
        ),
        "embedded_dropper_or_launch": is_mal
        & (
            (num("EmbeddedFile") > 0)
            | (num("EmbeddedFiles") > 0)
            | (num("lexical_EmbeddedFile") > 0)
            | (num("Launch") > 0)
            | (num("lexical_Launch") > 0)
            | (num("legacy_v8_action_Launch") > 0)
            | (num("observed_artifact_kind_pe_candidate") > 0)
            | (num("observed_artifact_kind_zip") > 0)
        ),
        "suspicious_uri_redirect": is_mal
        & (
            (num("lexical_URI") > 0)
            | (num("legacy_v8_action_URI") > 0)
            | (num("legacy_v8_pypdf_call_app.launchURL") > 0)
        ),
        "structural_parser_evasion": is_mal
        & (
            (num("observed_parser_conflicts") > 0)
            | (num("arlington_candidate_checks_fail") > 0)
            | (num("is_truncated_stream") > 0)
            | (num("flag_spec_violation_flood") > 0)
            | (num("evasive_timeout_anomaly") > 0)
            | (num("ObjStm") > 0)
        ),
    }

    label_ids = [d["id"] for d in MULTILABEL_THREAT_DEFINITIONS]
    y_matrix = np.column_stack([target_series[lid].astype(np.float32).values for lid in label_ids])

    train_mask = (merged["split"] == "train").values
    scaler = StandardScaler()
    scaler.fit(merged.loc[train_mask, all_tab_cols].values)
    safe_scale = np.where(np.abs(scaler.scale_) < 1e-6, 1.0, scaler.scale_)
    scaled_tab = ((merged[all_tab_cols].values - scaler.mean_) / safe_scale).astype(np.float32)

    ordered_ast_cols = [f"legacy_observed_ast_type_{name}" for name in AST_NODE_TYPES]
    splits_all: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}

    for pos, v2_row in enumerate(tabular_rows):
        m_row = merged.iloc[pos]
        sha = v2_row["sha256"]
        split = v2_row["split"]
        gnn_ok = bool(v2_row["gnn_message_passing_eligible"])
        fmap = v2_row["features"]

        ast_vals: list[int] = []
        for col in ordered_ast_cols:
            if col in fmap and fmap[col].get("value") is not None:
                ast_vals.append(int(_extract_v2_float(fmap, col, 0.0)) % 64)
            elif col in m_row and not pd.isna(m_row[col]):
                ast_vals.append(int(float(m_row[col])) % 64)
            else:
                ast_vals.append(0)
        while len(ast_vals) < 32:
            ast_vals.append(0)
        ast_tokens = torch.tensor(ast_vals[:32], dtype=torch.long)

        item: dict[str, Any] = {
            "index": int(v2_row["index"]),
            "sha256": sha,
            "split": split,
            "label": int(v2_row["label"]),
            "y_multi": y_matrix[pos].copy(),
            "ast_tokens": ast_tokens,
            "tab_features": torch.tensor(scaled_tab[pos], dtype=torch.float32),
            "gnn_ok": gnn_ok,
        }
        if gnn_ok:
            g = graph_dict[sha]
            item["node_features"] = torch.tensor(g["node_features"], dtype=torch.float32)
            item["node_types"] = torch.tensor(g["node_types"], dtype=torch.long)
            item["edge_src"] = torch.tensor(g["edge_src"], dtype=torch.long)
            item["edge_dst"] = torch.tensor(g["edge_dst"], dtype=torch.long)
            item["edge_rel"] = torch.tensor(g["edge_rel"], dtype=torch.long)
        else:
            item["node_features"] = None
            item["node_types"] = None
            item["edge_src"] = None
            item["edge_dst"] = None
            item["edge_rel"] = None
        splits_all[split].append(item)

    return {
        "splits_all": splits_all,
        "label_defs": MULTILABEL_THREAT_DEFINITIONS,
    }


def _prepare_ort_graph_inputs(sample: dict[str, Any]) -> dict[str, np.ndarray]:
    nf = sample["node_features"].numpy().astype(np.float32, copy=False)
    nt = sample["node_types"].numpy().astype(np.int64, copy=False)
    es = sample["edge_src"].numpy().astype(np.int64, copy=False)
    ed = sample["edge_dst"].numpy().astype(np.int64, copy=False)
    er = sample["edge_rel"].numpy().astype(np.int64, copy=False)
    if es.size > 0:
        es_in = np.ascontiguousarray(es, dtype=np.int64)
        ed_in = np.ascontiguousarray(ed, dtype=np.int64)
        er_in = np.ascontiguousarray(er, dtype=np.int64)
        em_in = np.ones((es.size, 1), dtype=np.float32)
        he_in = np.array([1.0], dtype=np.float32)
    else:
        es_in = np.zeros((1,), dtype=np.int64)
        ed_in = np.zeros((1,), dtype=np.int64)
        er_in = np.zeros((1,), dtype=np.int64)
        em_in = np.zeros((1, 1), dtype=np.float32)
        he_in = np.array([0.0], dtype=np.float32)
    b_in = np.zeros((nf.shape[0],), dtype=np.int64)
    tok_in = np.ascontiguousarray(sample["ast_tokens"].numpy().reshape(1, -1), dtype=np.int64)
    tab_in = np.ascontiguousarray(sample["tab_features"].numpy().reshape(1, -1), dtype=np.float32)
    return {
        "node_features": np.ascontiguousarray(nf, dtype=np.float32),
        "node_types": np.ascontiguousarray(nt, dtype=np.int64),
        "edge_src": es_in,
        "edge_dst": ed_in,
        "edge_rel": er_in,
        "edge_mask": em_in,
        "has_edges": he_in,
        "batch": b_in,
        "ast_tokens": tok_in,
        "tabular_features": tab_in,
    }


def _evaluate_binary_split(
    samples: list[dict[str, Any]],
    pt_model: PDFTransGraph,
    ort_sess: ort.InferenceSession,
) -> dict[str, Any]:
    y_true: list[int] = []
    pt_logits: list[float] = []
    ort_logits: list[float] = []
    pt_latencies_ms: list[float] = []
    ort_latencies_ms: list[float] = []

    for sample in samples[:8]:
        if sample["gnn_message_passing_eligible"]:
            feed = _prepare_ort_graph_inputs(sample)
            ort_sess.run(["logits"], feed)

    with torch.no_grad():
        for sample in samples:
            y_true.append(int(sample["label"]))
            tok_t = sample["ast_tokens"].unsqueeze(0)
            tab_t = sample["tab_features"].unsqueeze(0)
            nf_t = sample["node_features"]
            nt_t = sample["node_types"]
            es_t = sample["edge_src"]
            ed_t = sample["edge_dst"]
            er_t = sample["edge_rel"]
            if es_t.numel() > 0:
                ei_t = torch.stack([es_t, ed_t], dim=0)
            else:
                ei_t = torch.zeros((2, 0), dtype=torch.long)
            b_t = torch.zeros((nf_t.size(0),), dtype=torch.long)

            t0 = time.perf_counter()
            pt_out, _ = pt_model(nf_t, nt_t, ei_t, er_t, b_t, tok_t, tab_t)
            pt_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            pt_logits.append(float(pt_out.reshape(-1)[0].item()))

            feed = _prepare_ort_graph_inputs(sample)
            t1 = time.perf_counter()
            ort_out = ort_sess.run(["logits"], feed)[0]
            ort_latencies_ms.append((time.perf_counter() - t1) * 1000.0)
            ort_logits.append(float(np.asarray(ort_out).reshape(-1)[0]))

    y_arr = np.array(y_true, dtype=np.int64)
    pt_log_arr = np.array(pt_logits, dtype=np.float64)
    ort_log_arr = np.array(ort_logits, dtype=np.float64)
    pt_prob_arr = _sigmoid_np(pt_log_arr)
    ort_prob_arr = _sigmoid_np(ort_log_arr)
    pt_pred = (pt_prob_arr >= 0.5).astype(np.int64)
    ort_pred = (ort_prob_arr >= 0.5).astype(np.int64)

    tn, fp, fn, tp = confusion_matrix(y_arr, ort_pred, labels=[0, 1]).ravel()
    pt_med = float(statistics.median(pt_latencies_ms))
    ort_med = float(statistics.median(ort_latencies_ms))
    pt_mean = float(statistics.mean(pt_latencies_ms))
    ort_mean = float(statistics.mean(ort_latencies_ms))

    return {
        "sample_count": int(len(samples)),
        "malware_count": int(np.sum(y_arr == 1)),
        "benign_count": int(np.sum(y_arr == 0)),
        "onnx_metrics": {
            "accuracy": round(float(accuracy_score(y_arr, ort_pred)), 6),
            "precision": round(float(precision_score(y_arr, ort_pred, zero_division=0)), 6),
            "recall": round(float(recall_score(y_arr, ort_pred, zero_division=0)), 6),
            "f1": round(float(f1_score(y_arr, ort_pred, zero_division=0)), 6),
            "mcc": round(float(matthews_corrcoef(y_arr, ort_pred)), 6),
            "roc_auc": round(float(roc_auc_score(y_arr, ort_prob_arr)), 6),
            "pr_auc": round(float(average_precision_score(y_arr, ort_prob_arr)), 6),
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
        },
        "pytorch_parity": {
            "max_abs_logit_diff": float(np.max(np.abs(pt_log_arr - ort_log_arr))),
            "mean_abs_logit_diff": float(np.mean(np.abs(pt_log_arr - ort_log_arr))),
            "max_abs_prob_diff": float(np.max(np.abs(pt_prob_arr - ort_prob_arr))),
            "verdict_agreement_count": int(np.sum(pt_pred == ort_pred)),
            "verdict_agreement_rate": round(float(np.mean(pt_pred == ort_pred)), 6),
        },
        "latency_benchmark": {
            "pytorch_cpu_median_ms": round(pt_med, 4),
            "pytorch_cpu_mean_ms": round(pt_mean, 4),
            "pytorch_cpu_total_ms": round(float(sum(pt_latencies_ms)), 2),
            "onnx_cpu_median_ms": round(ort_med, 4),
            "onnx_cpu_mean_ms": round(ort_mean, 4),
            "onnx_cpu_total_ms": round(float(sum(ort_latencies_ms)), 2),
            "onnx_throughput_samples_per_sec": round(1000.0 / max(ort_mean, 1e-6), 2),
            "speedup_median_x": round(pt_med / max(ort_med, 1e-6), 2),
            "speedup_mean_x": round(pt_mean / max(ort_mean, 1e-6), 2),
        },
    }


def _evaluate_multilabel_split(
    samples: list[dict[str, Any]],
    pt_ml: PDFMultiLabelThreatNet,
    ort_ml_sess: ort.InferenceSession,
    contract: dict[str, Any],
) -> dict[str, Any]:
    label_defs = contract["labels"]
    thresholds = np.array([float(d.get("threshold", 0.5)) for d in label_defs], dtype=np.float32)

    y_multi_list: list[np.ndarray] = []
    y_mal_list: list[int] = []
    pt_logits_list: list[np.ndarray] = []
    ort_logits_list: list[np.ndarray] = []
    pt_latencies_ms: list[float] = []
    ort_latencies_ms: list[float] = []

    with torch.no_grad():
        for sample in samples:
            y_multi_list.append(sample["y_multi"])
            y_mal_list.append(int(sample["label"]))
            tok_t = sample["ast_tokens"].unsqueeze(0)
            tab_t = sample["tab_features"].unsqueeze(0)

            if sample["gnn_ok"]:
                nf_t = sample["node_features"]
                nt_t = sample["node_types"]
                es_t = sample["edge_src"]
                ed_t = sample["edge_dst"]
                er_t = sample["edge_rel"]
                ei_t = torch.stack([es_t, ed_t], dim=0) if es_t.numel() > 0 else torch.zeros((2, 0), dtype=torch.long)
                b_t = torch.zeros((nf_t.size(0),), dtype=torch.long)
                feed = _prepare_ort_graph_inputs(sample)
                feed["use_graph_flag"] = np.array([1.0], dtype=np.float32)
            else:
                nf_t = None
                nt_t = None
                ei_t = None
                er_t = None
                b_t = None
                feed = {
                    "node_features": np.zeros((1, 23), dtype=np.float32),
                    "node_types": np.array([8], dtype=np.int64),
                    "edge_src": np.zeros((1,), dtype=np.int64),
                    "edge_dst": np.zeros((1,), dtype=np.int64),
                    "edge_rel": np.zeros((1,), dtype=np.int64),
                    "edge_mask": np.zeros((1, 1), dtype=np.float32),
                    "has_edges": np.array([0.0], dtype=np.float32),
                    "use_graph_flag": np.array([0.0], dtype=np.float32),
                    "batch": np.zeros((1,), dtype=np.int64),
                    "ast_tokens": np.ascontiguousarray(sample["ast_tokens"].numpy().reshape(1, -1), dtype=np.int64),
                    "tabular_features": np.ascontiguousarray(
                        sample["tab_features"].numpy().reshape(1, -1), dtype=np.float32
                    ),
                }

            t0 = time.perf_counter()
            pt_lbl = pt_ml(nf_t, nt_t, ei_t, er_t, b_t, tok_t, tab_t)[0]
            pt_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            pt_logits_list.append(pt_lbl.squeeze(0).numpy().astype(np.float64))

            t1 = time.perf_counter()
            ort_lbl, _ = ort_ml_sess.run(["label_logits", "mal_logit"], feed)
            ort_latencies_ms.append((time.perf_counter() - t1) * 1000.0)
            ort_logits_list.append(np.asarray(ort_lbl).reshape(-1).astype(np.float64))

    y_true = np.vstack(y_multi_list)
    y_mal = np.array(y_mal_list, dtype=np.int64)
    pt_log = np.vstack(pt_logits_list)
    ort_log = np.vstack(ort_logits_list)
    pt_prob = _sigmoid_np(pt_log)
    ort_prob = _sigmoid_np(ort_log)
    ort_pred = (ort_prob >= thresholds[None, :]).astype(np.int64)
    pt_pred = (pt_prob >= thresholds[None, :]).astype(np.int64)

    per_head: list[dict[str, Any]] = []
    roc_aucs: list[float] = []
    pr_aucs: list[float] = []
    f1s: list[float] = []
    mal_mask = y_mal == 1

    for idx, ldef in enumerate(label_defs):
        yt = y_true[:, idx]
        yp = ort_prob[:, idx]
        yh = ort_pred[:, idx]
        pos_count = int(np.sum(yt == 1))
        roc = float(roc_auc_score(yt, yp)) if 0 < pos_count < len(yt) else 1.0
        pr = float(average_precision_score(yt, yp)) if pos_count > 0 else 1.0
        f1_val = float(f1_score(yt, yh, zero_division=0))
        prec_val = float(precision_score(yt, yh, zero_division=0))
        rec_val = float(recall_score(yt, yh, zero_division=0))
        roc_aucs.append(roc)
        pr_aucs.append(pr)
        f1s.append(f1_val)
        per_head.append(
            {
                "id": ldef["id"],
                "code_name": ldef["code_name"],
                "label_vi": ldef["label_vi"],
                "mitre_id": ldef["mitre_id"],
                "threshold": float(thresholds[idx]),
                "ground_truth_positives": pos_count,
                "onnx_predicted_positives_all": int(np.sum(yh == 1)),
                "onnx_predicted_positives_on_malware": int(np.sum(yh[mal_mask] == 1)),
                "roc_auc": round(roc, 6),
                "pr_auc": round(pr, 6),
                "f1": round(f1_val, 6),
                "precision": round(prec_val, 6),
                "recall": round(rec_val, 6),
            }
        )

    pt_med = float(statistics.median(pt_latencies_ms))
    ort_med = float(statistics.median(ort_latencies_ms))
    pt_mean = float(statistics.mean(pt_latencies_ms))
    ort_mean = float(statistics.mean(ort_latencies_ms))

    return {
        "sample_count": int(len(samples)),
        "macro_roc_auc": round(float(np.mean(roc_aucs)), 6),
        "macro_pr_auc": round(float(np.mean(pr_aucs)), 6),
        "macro_f1": round(float(np.mean(f1s)), 6),
        "per_head_metrics": per_head,
        "pytorch_parity": {
            "max_abs_logit_diff": float(np.max(np.abs(pt_log - ort_log))),
            "mean_abs_logit_diff": float(np.mean(np.abs(pt_log - ort_log))),
            "max_abs_prob_diff": float(np.max(np.abs(pt_prob - ort_prob))),
            "prediction_agreement_rate": round(float(np.mean(pt_pred == ort_pred)), 6),
        },
        "latency_benchmark": {
            "pytorch_cpu_median_ms": round(pt_med, 4),
            "pytorch_cpu_mean_ms": round(pt_mean, 4),
            "onnx_cpu_median_ms": round(ort_med, 4),
            "onnx_cpu_mean_ms": round(ort_mean, 4),
            "speedup_median_x": round(pt_med / max(ort_med, 1e-6), 2),
            "speedup_mean_x": round(pt_mean / max(ort_mean, 1e-6), 2),
        },
    }


def _evaluate_fixtures_end_to_end(
    benign_pdf_path: Path,
    threat_pdf_path: Path,
    prod_dir: Path,
) -> dict[str, Any]:
    engine = ONNXMalPDFScannerEngine(
        model_path=prod_dir / "models" / "pdf_transgraph_v2.onnx",
        scaler_path=prod_dir / "configs" / "tabular_scaler.json",
        manifest_path=prod_dir / "configs" / "onnx_manifest.json",
    )
    disarmer = PDFDisarmer()

    benign_bytes = benign_pdf_path.read_bytes()
    threat_bytes = threat_pdf_path.read_bytes()

    benign_scan = engine.scan_bytes(benign_bytes, file_name=benign_pdf_path.name, explain=True)
    threat_scan = engine.scan_bytes(threat_bytes, file_name=threat_pdf_path.name, explain=True)

    cleaned_bytes, cdr_audit = disarmer.sanitize_bytes(threat_bytes, file_name=threat_pdf_path.name)
    post_cdr_scan = engine.scan_bytes(cleaned_bytes, file_name="disarmed_" + threat_pdf_path.name, explain=True)

    size_ratio = len(cleaned_bytes) / max(len(threat_bytes), 1)
    cdr_invariants_passed = (
        size_ratio > 0.8
        and cdr_audit.sanitized_pages == cdr_audit.original_pages
        and cdr_audit.extracted_text_chars > 0
        and bool(cdr_audit.text_integrity_verified)
    )

    return {
        "benign_fixture": {
            "file_name": benign_pdf_path.name,
            "sha256": benign_scan.sha256,
            "verdict": benign_scan.verdict,
            "malware_probability": benign_scan.malware_probability,
            "latency_ms": benign_scan.latency_ms,
            "threat_label": benign_scan.threat_taxonomy.get("threat_label"),
            "threat_title_vi": benign_scan.threat_taxonomy.get("threat_title_vi"),
        },
        "threat_fixture": {
            "file_name": threat_pdf_path.name,
            "sha256": threat_scan.sha256,
            "verdict": threat_scan.verdict,
            "malware_probability": threat_scan.malware_probability,
            "latency_ms": threat_scan.latency_ms,
            "threat_label": threat_scan.threat_taxonomy.get("threat_label"),
            "threat_title_vi": threat_scan.threat_taxonomy.get("threat_title_vi"),
            "predicted_labels_vi": threat_scan.threat_taxonomy.get("predicted_labels_vi") or [],
        },
        "cdr_disarm_verification": {
            "size_before_bytes": cdr_audit.size_before,
            "size_after_bytes": cdr_audit.size_after,
            "size_retention_ratio": round(size_ratio, 4),
            "original_pages": cdr_audit.original_pages,
            "sanitized_pages": cdr_audit.sanitized_pages,
            "extracted_text_chars": cdr_audit.extracted_text_chars,
            "text_integrity_verified": cdr_audit.text_integrity_verified,
            "removed_triggers_count": len(cdr_audit.removed_triggers),
            "post_cdr_verdict": post_cdr_scan.verdict,
            "post_cdr_malware_probability": post_cdr_scan.malware_probability,
            "all_cdr_invariants_passed": cdr_invariants_passed,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--parquet-ours", type=Path, required=True)
    parser.add_argument("--parquet-cic", type=Path, required=True)
    parser.add_argument("--pt-binary", type=Path, required=True)
    parser.add_argument("--pt-multilabel", type=Path, required=True)
    parser.add_argument("--prod-dir", type=Path, required=True)
    parser.add_argument("--benign-fixture", type=Path, required=True)
    parser.add_argument("--threat-fixture", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()

    torch.set_num_threads(2)

    bin_dataset = load_multimodal_dataset_v2(
        export_dir=args.export_dir,
        parquet_ours_path=args.parquet_ours,
        parquet_cic_path=args.parquet_cic,
    )
    ml_dataset = build_eval_multilabel_splits(
        export_dir=args.export_dir,
        parquet_ours_path=args.parquet_ours,
        parquet_cic_path=args.parquet_cic,
        verified_export=bin_dataset["verified_export"],
    )

    bin_sd = torch.load(args.pt_binary, map_location="cpu", weights_only=True)
    pt_bin = PDFTransGraph(node_in_dim=23, tabular_in_features=38, hidden_dim=128)
    pt_bin.load_state_dict(bin_sd, strict=True)
    pt_bin.eval()

    ml_sd = torch.load(args.pt_multilabel, map_location="cpu", weights_only=True)
    pt_ml = PDFMultiLabelThreatNet(node_in_dim=23, tabular_in_features=52, hidden_dim=128, num_labels=8)
    pt_ml.load_state_dict(ml_sd, strict=True)
    pt_ml.eval()

    sess_opts = ort.SessionOptions()
    sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    sess_opts.intra_op_num_threads = 2
    sess_opts.inter_op_num_threads = 1

    bin_onnx_path = args.prod_dir / "models" / "pdf_transgraph_v2.onnx"
    ml_onnx_path = args.prod_dir / "models" / "multilabel_threat_net_v2.onnx"
    contract_path = args.prod_dir / "configs" / "multilabel_threat_contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    ort_bin = ort.InferenceSession(str(bin_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])
    ort_ml = ort.InferenceSession(str(ml_onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])

    test_bin_eval = _evaluate_binary_split(
        samples=bin_dataset["gnn_eligible_samples"]["test"],
        pt_model=pt_bin,
        ort_sess=ort_bin,
    )
    val_bin_eval = _evaluate_binary_split(
        samples=bin_dataset["gnn_eligible_samples"]["validation"],
        pt_model=pt_bin,
        ort_sess=ort_bin,
    )
    test_ml_eval = _evaluate_multilabel_split(
        samples=ml_dataset["splits_all"]["test"],
        pt_ml=pt_ml,
        ort_ml_sess=ort_ml,
        contract=contract,
    )
    val_ml_eval = _evaluate_multilabel_split(
        samples=ml_dataset["splits_all"]["validation"],
        pt_ml=pt_ml,
        ort_ml_sess=ort_ml,
        contract=contract,
    )

    e2e_eval = _evaluate_fixtures_end_to_end(
        benign_pdf_path=args.benign_fixture,
        threat_pdf_path=args.threat_fixture,
        prod_dir=args.prod_dir,
    )

    combined_pt_med = (
        test_bin_eval["latency_benchmark"]["pytorch_cpu_median_ms"]
        + test_ml_eval["latency_benchmark"]["pytorch_cpu_median_ms"]
    )
    combined_ort_med = (
        test_bin_eval["latency_benchmark"]["onnx_cpu_median_ms"]
        + test_ml_eval["latency_benchmark"]["onnx_cpu_median_ms"]
    )

    report = {
        "schema": "malpdf_remnux_onnx_production_evaluation_v1",
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "torch_version": torch.__version__,
            "onnxruntime_version": ort.__version__,
            "ort_providers": ort.get_available_providers(),
        },
        "models": {
            "binary_onnx_sha256": hashlib.sha256(bin_onnx_path.read_bytes()).hexdigest(),
            "multilabel_onnx_sha256": hashlib.sha256(ml_onnx_path.read_bytes()).hexdigest(),
            "binary_onnx_size_bytes": bin_onnx_path.stat().st_size,
            "multilabel_onnx_size_bytes": ml_onnx_path.stat().st_size,
        },
        "canonical_cic_export": {
            "export_dir": str(args.export_dir),
            "protocol": "Protocol G (seed=42)",
            "total_records": 1452,
            "test_split_records": 291,
            "validation_split_records": 291,
        },
        "binary_transgraph_v2_test": test_bin_eval,
        "binary_transgraph_v2_validation": val_bin_eval,
        "multilabel_threat_net_v2_test": test_ml_eval,
        "multilabel_threat_net_v2_validation": val_ml_eval,
        "combined_dual_model_benchmark": {
            "pytorch_cpu_dual_median_ms": round(combined_pt_med, 4),
            "onnx_cpu_dual_median_ms": round(combined_ort_med, 4),
            "combined_speedup_median_x": round(combined_pt_med / max(combined_ort_med, 1e-6), 2),
        },
        "end_to_end_scanner_and_cdr": e2e_eval,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["combined_dual_model_benchmark"], indent=2))
    print(json.dumps(report["binary_transgraph_v2_test"]["onnx_metrics"], indent=2))
    print(json.dumps(report["binary_transgraph_v2_test"]["pytorch_parity"], indent=2))
    print(f"Report written to: {args.output_json}")


if __name__ == "__main__":
    main()
