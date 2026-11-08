from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from malpdf.data.graph_export_v2_loader import safe_div_series, verify_graph_export_v2_directory
from malpdf.extraction.graph_projection_v2 import NODE_FEATURE_DIM_V2
from malpdf.models.multilabel_threat_net import (
    LEXICAL_EXTRA_FEATURE_NAMES,
    MULTILABEL_THREAT_DEFINITIONS,
    PDFMultiLabelThreatNet,
)
from malpdf.scanner.ingestion import AST_NODE_TYPES

DEFAULT_EXPORT_DIR = REPO / "data/processed/graph_exports_v2/export_20261106T135440198431Z_89bf66f04d93"
DEFAULT_PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
DEFAULT_PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
DEFAULT_BASE_CHECKPOINT = REPO / "artifacts/models/pdf_transgraph_v2/pdf_transgraph_v2_23d_best.pt"
DEFAULT_OUT_MODEL = REPO / "artifacts/models/multilabel_threat_v2/multilabel_threat_net_v2_best.pt"
DEFAULT_OUT_CONTRACT = REPO / "configs/multilabel_threat_contract.json"
DEFAULT_REPORT_ROOT = REPO / "reports/experiments/multilabel_threat_v2"


class MultiLabelDataset(Dataset):
    def __init__(self, samples: list[dict[str, Any]]) -> None:
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        return self.samples[idx]


def collate_gnn_multilabel(batch: list[dict[str, Any]]) -> dict[str, Any]:
    node_feats = []
    node_types = []
    edge_src = []
    edge_dst = []
    edge_rel = []
    batch_idx = []
    offset = 0
    for g_idx, item in enumerate(batch):
        nf = item["node_features"]
        nt = item["node_types"]
        n_nodes = nf.size(0)
        node_feats.append(nf)
        node_types.append(nt)
        batch_idx.append(torch.full((n_nodes,), g_idx, dtype=torch.long))
        es = item["edge_src"]
        ed = item["edge_dst"]
        if es.numel() > 0:
            edge_src.append(es + offset)
            edge_dst.append(ed + offset)
            edge_rel.append(item["edge_rel"])
        offset += n_nodes
    if edge_src:
        edge_index = torch.stack([torch.cat(edge_src, dim=0), torch.cat(edge_dst, dim=0)], dim=0)
        batched_er = torch.cat(edge_rel, dim=0)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        batched_er = torch.zeros((0,), dtype=torch.long)
    return {
        "node_features": torch.cat(node_feats, dim=0),
        "node_types": torch.cat(node_types, dim=0),
        "edge_index": edge_index,
        "edge_rel": batched_er,
        "batch": torch.cat(batch_idx, dim=0),
        "ast_tokens": torch.stack([s["ast_tokens"] for s in batch], dim=0),
        "tab_features": torch.stack([s["tab_features"] for s in batch], dim=0),
        "y_multi": torch.stack([s["y_multi"] for s in batch], dim=0),
        "y_mal": torch.tensor([s["label"] for s in batch], dtype=torch.float32),
        "indices": [s["index"] for s in batch],
    }


def collate_nongraph_multilabel(batch: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "node_features": None,
        "node_types": None,
        "edge_index": None,
        "edge_rel": None,
        "batch": None,
        "ast_tokens": torch.stack([s["ast_tokens"] for s in batch], dim=0),
        "tab_features": torch.stack([s["tab_features"] for s in batch], dim=0),
        "y_multi": torch.stack([s["y_multi"] for s in batch], dim=0),
        "y_mal": torch.tensor([s["label"] for s in batch], dtype=torch.float32),
        "indices": [s["index"] for s in batch],
    }


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


def build_multilabel_dataset(
    export_dir: Path,
    parquet_ours_path: Path,
    parquet_cic_path: Path,
    seed: int = 42,
) -> dict[str, Any]:
    verified = verify_graph_export_v2_directory(export_dir)
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
    splits_gnn: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}
    splits_nongraph: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}
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
            "y_multi": torch.tensor(y_matrix[pos], dtype=torch.float32),
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
            splits_gnn[split].append(item)
        else:
            item["node_features"] = None
            item["node_types"] = None
            item["edge_src"] = None
            item["edge_dst"] = None
            item["edge_rel"] = None
            splits_nongraph[split].append(item)
        splits_all[split].append(item)

    carrier_cols = {
        "Stream",
        "Endstream",
        "Obj",
        "Endobj",
        "MetadataSize",
        "PdfSize",
        "Pages",
        "PageNo",
        "Colors",
        "Images",
        "density_stream_ratio",
        "density_obj_stream_ratio",
        "density_metadata_ratio",
        "byte_image_file_encoded_ratio",
        "byte_image_file_persisted_ratio",
        "raw_entropy",
        "raw_prefix_entropy",
        "raw_suffix_entropy",
        "entropy_gap",
        "lexical_URI",
        "effective_uri_count",
    }
    carrier_col_indices = [idx for idx, cname in enumerate(all_tab_cols) if cname in carrier_cols]
    additive_max_cols = {"Stream", "Endstream", "Obj", "Endobj", "lexical_URI", "effective_uri_count"}
    additive_max_indices = {idx for idx, cname in enumerate(all_tab_cols) if cname in additive_max_cols}

    train_benign_gnn = [s for s in splits_gnn["train"] if s["label"] == 0]
    train_mal_gnn = [s for s in splits_gnn["train"] if s["label"] == 1 and float(s["y_multi"].sum().item()) > 0]
    if train_benign_gnn and train_mal_gnn:
        rng = np.random.default_rng(seed)
        aug_count = min(320, len(train_mal_gnn))
        chosen_mal = rng.choice(len(train_mal_gnn), size=aug_count, replace=False)
        chosen_ben = rng.choice(len(train_benign_gnn), size=aug_count, replace=True)
        for k_idx, (m_i, b_i) in enumerate(zip(chosen_mal, chosen_ben)):
            m_s = train_mal_gnn[int(m_i)]
            b_s = train_benign_gnn[int(b_i)]
            mixed_tab = m_s["tab_features"].clone()
            for c_idx in carrier_col_indices:
                if c_idx in additive_max_indices:
                    mixed_tab[c_idx] = torch.maximum(m_s["tab_features"][c_idx], b_s["tab_features"][c_idx])
                else:
                    mixed_tab[c_idx] = b_s["tab_features"][c_idx]
            aug_item = dict(m_s)
            aug_item["index"] = 100000 + k_idx
            aug_item["tab_features"] = mixed_tab
            splits_gnn["train"].append(aug_item)

    y_train = y_matrix[train_mask]
    pos_counts = np.maximum(y_train.sum(axis=0), 1.0)
    neg_counts = np.maximum(float(y_train.shape[0]) - pos_counts, 1.0)
    pos_weights = np.clip(np.sqrt(neg_counts / pos_counts), 1.0, 5.0).astype(np.float32)

    support_by_split: dict[str, dict[str, int]] = {}
    for idx_l, lid in enumerate(label_ids):
        support_by_split[lid] = {
            sp: int(y_matrix[(merged["split"] == sp).values, idx_l].sum())
            for sp in ("train", "validation", "test")
        }

    return {
        "verified": verified,
        "feature_names": all_tab_cols,
        "scaler_mean": [float(x) for x in scaler.mean_],
        "scaler_scale": [float(x) for x in safe_scale],
        "pos_weights": pos_weights,
        "splits_gnn": splits_gnn,
        "splits_nongraph": splits_nongraph,
        "splits_all": splits_all,
        "support_by_split": support_by_split,
    }


def predict_split(
    model: PDFMultiLabelThreatNet,
    gnn_samples: list[dict[str, Any]],
    nongraph_samples: list[dict[str, Any]],
    all_samples: list[dict[str, Any]],
    device: torch.device,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    probs_by_idx: dict[int, np.ndarray] = {}
    with torch.no_grad():
        if gnn_samples:
            loader = DataLoader(
                MultiLabelDataset(gnn_samples),
                batch_size=64,
                shuffle=False,
                collate_fn=collate_gnn_multilabel,
            )
            for batch in loader:
                logits, _, _ = model(
                    batch["node_features"].to(device),
                    batch["node_types"].to(device),
                    batch["edge_index"].to(device),
                    batch["edge_rel"].to(device),
                    batch["batch"].to(device),
                    batch["ast_tokens"].to(device),
                    batch["tab_features"].to(device),
                )
                probs = torch.sigmoid(logits).cpu().numpy()
                for idx_v, p_row in zip(batch["indices"], probs):
                    probs_by_idx[int(idx_v)] = p_row
        if nongraph_samples:
            loader_ng = DataLoader(
                MultiLabelDataset(nongraph_samples),
                batch_size=64,
                shuffle=False,
                collate_fn=collate_nongraph_multilabel,
            )
            for batch in loader_ng:
                logits, _, _ = model(
                    None,
                    None,
                    None,
                    None,
                    None,
                    batch["ast_tokens"].to(device),
                    batch["tab_features"].to(device),
                )
                probs = torch.sigmoid(logits).cpu().numpy()
                for idx_v, p_row in zip(batch["indices"], probs):
                    probs_by_idx[int(idx_v)] = p_row

    y_true = np.vstack([s["y_multi"].numpy() for s in all_samples])
    y_prob = np.vstack([probs_by_idx[int(s["index"])] for s in all_samples])
    return y_true, y_prob


def tune_thresholds_on_validation(y_val: np.ndarray, p_val: np.ndarray) -> list[float]:
    thresholds: list[float] = []
    grid = np.linspace(0.30, 0.70, 41)
    for col in range(y_val.shape[1]):
        yt = y_val[:, col].astype(int)
        yp = p_val[:, col]
        best_t = 0.50
        best_f1 = -1.0
        for cand in grid:
            pred = (yp >= cand).astype(int)
            score = float(f1_score(yt, pred, zero_division=0))
            if score > best_f1:
                best_f1 = score
                best_t = float(cand)
        thresholds.append(round(best_t, 3))
    return thresholds


def evaluate_multilabel_metrics(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    thresholds: list[float],
) -> dict[str, Any]:
    label_ids = [d["id"] for d in MULTILABEL_THREAT_DEFINITIONS]
    per_label: dict[str, dict[str, float]] = {}
    rocs: list[float] = []
    prs: list[float] = []
    f1s: list[float] = []

    y_pred_cols = []
    for idx, lid in enumerate(label_ids):
        yt = y_true[:, idx].astype(int)
        yp = y_prob[:, idx]
        thr = thresholds[idx]
        pred = (yp >= thr).astype(int)
        y_pred_cols.append(pred)
        roc = float(roc_auc_score(yt, yp)) if len(np.unique(yt)) > 1 else 0.0
        pr = float(average_precision_score(yt, yp)) if len(np.unique(yt)) > 1 else 0.0
        f1 = float(f1_score(yt, pred, zero_division=0))
        prec = float(precision_score(yt, pred, zero_division=0))
        rec = float(recall_score(yt, pred, zero_division=0))
        rocs.append(roc)
        prs.append(pr)
        f1s.append(f1)
        per_label[lid] = {
            "support_pos": int(yt.sum()),
            "threshold": thr,
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr, 4),
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
        }

    y_pred_mat = np.column_stack(y_pred_cols)
    micro_f1 = float(f1_score(y_true.astype(int), y_pred_mat, average="micro", zero_division=0))
    samples_exact_acc = float((y_true.astype(int) == y_pred_mat).all(axis=1).mean())
    return {
        "denominator": int(y_true.shape[0]),
        "macro_roc_auc": round(float(np.mean(rocs)), 4),
        "macro_pr_auc": round(float(np.mean(prs)), 4),
        "macro_f1": round(float(np.mean(f1s)), 4),
        "micro_f1": round(micro_f1, 4),
        "exact_subset_accuracy": round(samples_exact_acc, 4),
        "per_label": per_label,
    }


def git_commit_full() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    except Exception:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=45)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--lr", type=float, default=1.2e-3)
    args = parser.parse_args()

    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    start_ts = time.perf_counter()

    bundle = build_multilabel_dataset(
        DEFAULT_EXPORT_DIR,
        DEFAULT_PARQUET_OURS,
        DEFAULT_PARQUET_CIC,
        seed=args.seed,
    )

    model = PDFMultiLabelThreatNet(
        node_in_dim=NODE_FEATURE_DIM_V2,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=len(bundle["feature_names"]),
        hidden_dim=128,
        num_labels=len(MULTILABEL_THREAT_DEFINITIONS),
    ).to(device)

    if DEFAULT_BASE_CHECKPOINT.is_file():
        base_sd = torch.load(DEFAULT_BASE_CHECKPOINT, map_location=device, weights_only=True)
        transfer_sd = {
            k: v
            for k, v in base_sd.items()
            if k.startswith(("graph_encoder.", "ast_encoder.", "fusion."))
            and k in model.state_dict()
            and model.state_dict()[k].shape == v.shape
        }
        model.load_state_dict(transfer_sd, strict=False)

    pos_weight_tensor = torch.tensor(bundle["pos_weights"], dtype=torch.float32, device=device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs, eta_min=5e-5)

    gen = torch.Generator()
    gen.manual_seed(args.seed)
    train_gnn_loader = DataLoader(
        MultiLabelDataset(bundle["splits_gnn"]["train"]),
        batch_size=32,
        shuffle=True,
        generator=gen,
        collate_fn=collate_gnn_multilabel,
    )
    train_ng_loader = (
        DataLoader(
            MultiLabelDataset(bundle["splits_nongraph"]["train"]),
            batch_size=32,
            shuffle=True,
            generator=gen,
            collate_fn=collate_nongraph_multilabel,
        )
        if bundle["splits_nongraph"]["train"]
        else None
    )

    best_val_score = -1.0
    best_state: dict[str, torch.Tensor] = {}

    for _epoch in range(1, args.epochs + 1):
        model.train()
        for batch in train_gnn_loader:
            optimizer.zero_grad(set_to_none=True)
            logits, mal_logit, _ = model(
                batch["node_features"].to(device),
                batch["node_types"].to(device),
                batch["edge_index"].to(device),
                batch["edge_rel"].to(device),
                batch["batch"].to(device),
                batch["ast_tokens"].to(device),
                batch["tab_features"].to(device),
                graph_drop_prob=0.20,
            )
            y_multi = batch["y_multi"].to(device)
            y_mal = batch["y_mal"].to(device)
            loss_multi = F.binary_cross_entropy_with_logits(logits, y_multi, pos_weight=pos_weight_tensor)
            loss_aux = F.binary_cross_entropy_with_logits(mal_logit, y_mal)
            loss = loss_multi + 0.25 * loss_aux
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0)
            optimizer.step()

        if train_ng_loader is not None:
            for batch in train_ng_loader:
                optimizer.zero_grad(set_to_none=True)
                logits, mal_logit, _ = model(
                    None,
                    None,
                    None,
                    None,
                    None,
                    batch["ast_tokens"].to(device),
                    batch["tab_features"].to(device),
                )
                y_multi = batch["y_multi"].to(device)
                y_mal = batch["y_mal"].to(device)
                loss_multi = F.binary_cross_entropy_with_logits(logits, y_multi, pos_weight=pos_weight_tensor)
                loss_aux = F.binary_cross_entropy_with_logits(mal_logit, y_mal)
                loss = loss_multi + 0.25 * loss_aux
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0)
                optimizer.step()

        scheduler.step()

        y_val, p_val = predict_split(
            model,
            bundle["splits_gnn"]["validation"],
            bundle["splits_nongraph"]["validation"],
            bundle["splits_all"]["validation"],
            device,
        )
        val_default = evaluate_multilabel_metrics(y_val, p_val, [0.5] * len(MULTILABEL_THREAT_DEFINITIONS))
        composite_score = 0.6 * val_default["macro_pr_auc"] + 0.4 * val_default["macro_f1"]
        if composite_score > best_val_score:
            best_val_score = composite_score
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    y_val, p_val = predict_split(
        model,
        bundle["splits_gnn"]["validation"],
        bundle["splits_nongraph"]["validation"],
        bundle["splits_all"]["validation"],
        device,
    )
    tuned_thresholds = tune_thresholds_on_validation(y_val, p_val)
    val_metrics = evaluate_multilabel_metrics(y_val, p_val, tuned_thresholds)

    y_test, p_test = predict_split(
        model,
        bundle["splits_gnn"]["test"],
        bundle["splits_nongraph"]["test"],
        bundle["splits_all"]["test"],
        device,
    )
    test_metrics = evaluate_multilabel_metrics(y_test, p_test, tuned_thresholds)

    DEFAULT_OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    torch.save(best_state, DEFAULT_OUT_MODEL)
    ckpt_sha256 = hashlib.sha256(DEFAULT_OUT_MODEL.read_bytes()).hexdigest()

    contract_payload = {
        "contract_version": "multilabel-threat-v2",
        "model_architecture": "PDFMultiLabelThreatNet",
        "node_in_dim": NODE_FEATURE_DIM_V2,
        "ast_vocab_size": 64,
        "hidden_dim": 128,
        "tabular_in_features": len(bundle["feature_names"]),
        "feature_names": bundle["feature_names"],
        "scaler_mean": bundle["scaler_mean"],
        "scaler_scale": bundle["scaler_scale"],
        "fitted_on": "protocol_g_seed42_train_only",
        "checkpoint_relpath": "artifacts/models/multilabel_threat_v2/multilabel_threat_net_v2_best.pt",
        "checkpoint_sha256": ckpt_sha256,
        "labels": [
            {
                **defn,
                "threshold": tuned_thresholds[idx],
                "test_roc_auc": test_metrics["per_label"][defn["id"]]["roc_auc"],
                "test_f1": test_metrics["per_label"][defn["id"]]["f1"],
            }
            for idx, defn in enumerate(MULTILABEL_THREAT_DEFINITIONS)
        ],
        "validation_summary": {
            "macro_roc_auc": val_metrics["macro_roc_auc"],
            "macro_pr_auc": val_metrics["macro_pr_auc"],
            "macro_f1": val_metrics["macro_f1"],
            "micro_f1": val_metrics["micro_f1"],
        },
        "test_summary": {
            "macro_roc_auc": test_metrics["macro_roc_auc"],
            "macro_pr_auc": test_metrics["macro_pr_auc"],
            "macro_f1": test_metrics["macro_f1"],
            "micro_f1": test_metrics["micro_f1"],
            "exact_subset_accuracy": test_metrics["exact_subset_accuracy"],
        },
    }
    DEFAULT_OUT_CONTRACT.write_text(json.dumps(contract_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    ts_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = DEFAULT_REPORT_ROOT / f"run_{ts_utc}_seed{args.seed}"
    run_dir.mkdir(parents=True, exist_ok=True)
    locked_methodology = {
        "protocol": "Protocol_G_deterministic_split",
        "seed": args.seed,
        "scaler_fitted_strictly_on": "train",
        "thresholds_tuned_strictly_on": "validation",
        "source_export_dir": str(DEFAULT_EXPORT_DIR.relative_to(REPO)),
        "git_commit": git_commit_full(),
        "device": str(device),
        "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
        "elapsed_seconds": round(time.perf_counter() - start_ts, 2),
    }
    (run_dir / "locked_methodology.json").write_text(
        json.dumps(locked_methodology, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (run_dir / "evaluation_report.json").write_text(
        json.dumps(
            {
                "support_by_split": bundle["support_by_split"],
                "validation": val_metrics,
                "test": test_metrics,
                "checkpoint_sha256": ckpt_sha256,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "device": str(device),
                "elapsed_sec": round(time.perf_counter() - start_ts, 2),
                "val_macro_roc_auc": val_metrics["macro_roc_auc"],
                "val_macro_f1": val_metrics["macro_f1"],
                "test_macro_roc_auc": test_metrics["macro_roc_auc"],
                "test_macro_pr_auc": test_metrics["macro_pr_auc"],
                "test_macro_f1": test_metrics["macro_f1"],
                "test_micro_f1": test_metrics["micro_f1"],
                "per_label_test": test_metrics["per_label"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
