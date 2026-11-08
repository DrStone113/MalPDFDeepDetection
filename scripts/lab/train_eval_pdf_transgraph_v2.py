from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
import torch
from torch.utils.data import DataLoader

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from malpdf.data.graph_export_v2_loader import (
    MultimodalPDFDatasetV2,
    collate_multimodal_batch_v2,
    collate_non_graph_batch_v2,
    load_multimodal_dataset_v2,
    sha256_bytes,
)
from malpdf.extraction.graph_projection_v2 import NODE_FEATURE_DIM_V2, PROJECTION_CONTRACT_VERSION
from malpdf.extraction.quality_gate import GATE_CONTRACT_VERSION_V2
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph


DEFAULT_EXPORT_DIR = REPO / "data/processed/graph_exports_v2/export_20261106T135440198431Z_89bf66f04d93"
DEFAULT_PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
DEFAULT_PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
DEFAULT_REPORT_ROOT = REPO / "reports/experiments/pdf_transgraph_v2"
DEFAULT_CHECKPOINT_ROOT = REPO / "artifacts/models/pdf_transgraph_v2"
V1_ABLATION_PATH = REPO / "reports/experiments/pdf_transgraph/academic_ablation_results.json"


def git_commit_short() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
        return out[:12] if out else "unknown"
    except Exception:
        return "unknown"


def git_commit_full() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
        return out if out else "unknown"
    except Exception:
        return "unknown"


def compute_metrics(y_true: list[int], y_pred: list[int], y_prob: list[float]) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    return {
        "denominator": len(y_true),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier": float(brier_score_loss(y_true, y_prob)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def set_deterministic_seed(seed: int) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def evaluate_split_v2(
    model: PDFTransGraph,
    full_samples: list[dict],
    gnn_samples: list[dict],
    device: torch.device,
    *,
    fallback_tab_ast_model: PDFTransGraph | None = None,
) -> dict:
    model.eval()
    if fallback_tab_ast_model is not None:
        fallback_tab_ast_model.eval()

    gnn_prob_by_idx: dict[int, float] = {}
    if gnn_samples:
        gnn_loader = DataLoader(
            MultimodalPDFDatasetV2(gnn_samples),
            batch_size=64,
            shuffle=False,
            collate_fn=collate_multimodal_batch_v2,
        )
        with torch.no_grad():
            for batch in gnn_loader:
                nf = batch["node_features"].to(device)
                nt = batch["node_types"].to(device)
                ei = batch["edge_index"].to(device)
                er = batch["edge_rel"].to(device)
                b = batch["batch"].to(device)
                tok = batch["ast_tokens"].to(device)
                tab = batch["tab_features"].to(device)
                logits, _ = model(nf, nt, ei, er, b, tok, tab)
                probs = torch.sigmoid(logits).cpu().tolist()
                for idx_val, p_val in zip(batch["indices"], probs):
                    gnn_prob_by_idx[int(idx_val)] = float(p_val)

    unavail_samples = [s for s in full_samples if not s["gnn_message_passing_eligible"]]
    unavail_fallback_prob_by_idx: dict[int, float] = {}
    unavail_direct_prob_by_idx: dict[int, float] = {}
    if unavail_samples:
        unavail_loader = DataLoader(
            MultimodalPDFDatasetV2(unavail_samples),
            batch_size=64,
            shuffle=False,
            collate_fn=collate_non_graph_batch_v2,
        )
        with torch.no_grad():
            for batch in unavail_loader:
                tok = batch["ast_tokens"].to(device)
                tab = batch["tab_features"].to(device)
                if fallback_tab_ast_model is not None:
                    fb_logits, _ = fallback_tab_ast_model(None, None, None, None, None, tok, tab)
                    fb_probs = torch.sigmoid(fb_logits).cpu().tolist()
                else:
                    fb_probs = [0.5] * len(batch["indices"])

                if model.ablation_mode != "graph_only":
                    dir_logits, _ = model(None, None, None, None, None, tok, tab)
                    dir_probs = torch.sigmoid(dir_logits).cpu().tolist()
                else:
                    dir_probs = list(fb_probs)

                for idx_val, fb_p, dir_p in zip(batch["indices"], fb_probs, dir_probs):
                    unavail_fallback_prob_by_idx[int(idx_val)] = float(fb_p)
                    unavail_direct_prob_by_idx[int(idx_val)] = float(dir_p)

    full_targets = []
    full_probs = []
    full_preds = []
    full_direct_probs = []
    full_direct_preds = []
    full_shas = []
    full_sample_ids = []
    unavailable_decisions = []

    gnn_targets = []
    gnn_probs = []
    gnn_preds = []

    for sample in full_samples:
        idx_val = int(sample["index"])
        y_val = int(sample["label"])
        full_targets.append(y_val)
        full_shas.append(sample["sha256"])
        full_sample_ids.append(sample["sample_id"])
        if sample["gnn_message_passing_eligible"]:
            p_val = gnn_prob_by_idx[idx_val]
            pred_val = 1 if p_val >= 0.5 else 0
            full_probs.append(p_val)
            full_preds.append(pred_val)
            full_direct_probs.append(p_val)
            full_direct_preds.append(pred_val)
            gnn_targets.append(y_val)
            gnn_probs.append(p_val)
            gnn_preds.append(pred_val)
        else:
            use_fb = fallback_tab_ast_model is not None and model.ablation_mode in {"full", "graph_only", "tab_graph"}
            p_primary = unavail_fallback_prob_by_idx[idx_val] if use_fb else unavail_direct_prob_by_idx[idx_val]
            pred_primary = 1 if p_primary >= 0.5 else 0
            p_dir = unavail_direct_prob_by_idx[idx_val]
            pred_dir = 1 if p_dir >= 0.5 else 0
            full_probs.append(p_primary)
            full_preds.append(pred_primary)
            full_direct_probs.append(p_dir)
            full_direct_preds.append(pred_dir)
            unavailable_decisions.append({
                "index": idx_val,
                "sha256": sample["sha256"],
                "sample_id": sample["sample_id"],
                "label": y_val,
                "sample_disposition": sample["meta"]["sample_disposition"],
                "evaluation_handling": sample["evaluation_handling"],
                "placeholder_nodes_inserted": False,
                "verified_fallback_prob": round(p_primary, 6),
                "verified_fallback_pred": pred_primary,
                "no_graph_branch_prob": round(p_dir, 6),
                "no_graph_branch_pred": pred_dir,
            })

    full_metrics = compute_metrics(full_targets, full_preds, full_probs)
    direct_metrics = compute_metrics(full_targets, full_direct_preds, full_direct_probs)
    gnn_metrics = compute_metrics(gnn_targets, gnn_preds, gnn_probs)
    return {
        "full_denominator": full_metrics,
        "full_denominator_no_graph_branch": direct_metrics,
        "gnn_eligible_subset": gnn_metrics,
        "unavailable_count": len(unavailable_decisions),
        "unavailable_decisions": unavailable_decisions,
        "targets": full_targets,
        "preds": full_preds,
        "probs": full_probs,
        "shas": full_shas,
        "sample_ids": full_sample_ids,
    }


def train_and_eval_mode_v2(
    dataset_bundle: dict,
    ablation_mode: str,
    seed: int,
    epochs: int,
    device: torch.device,
    *,
    fallback_tab_ast_model: PDFTransGraph | None = None,
) -> tuple[dict, PDFTransGraph, dict[str, torch.Tensor]]:
    set_deterministic_seed(seed)
    tab_dim = dataset_bundle["tabular_in_features"]
    node_dim = dataset_bundle["node_in_dim"]
    full_splits = dataset_bundle["full_split_samples"]
    gnn_splits = dataset_bundle["gnn_eligible_samples"]

    uses_graph_in_train = ablation_mode in {"full", "graph_only", "tab_graph"}
    if uses_graph_in_train:
        train_samples = gnn_splits["train"]
        collate_fn = collate_multimodal_batch_v2
    else:
        train_samples = full_splits["train"]
        collate_fn = collate_non_graph_batch_v2

    generator = torch.Generator()
    generator.manual_seed(seed)
    train_loader = DataLoader(
        MultimodalPDFDatasetV2(train_samples),
        batch_size=32,
        shuffle=True,
        collate_fn=collate_fn,
        generator=generator,
    )

    model = PDFTransGraph(
        node_in_dim=node_dim,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=tab_dim,
        hidden_dim=128,
        ablation_mode=ablation_mode,
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = FocalLoss(alpha=0.6, gamma=2.0)

    best_val_f1 = -1.0
    best_val_auc = -1.0
    best_epoch = 1
    best_weights = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    epoch_history = []

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        seen = 0
        for batch in train_loader:
            optimizer.zero_grad()
            nf = batch["node_features"].to(device) if batch["node_features"] is not None else None
            nt = batch["node_types"].to(device) if batch["node_types"] is not None else None
            ei = batch["edge_index"].to(device) if batch["edge_index"] is not None else None
            er = batch["edge_rel"].to(device) if batch["edge_rel"] is not None else None
            b = batch["batch"].to(device) if batch["batch"] is not None else None
            tok = batch["ast_tokens"].to(device)
            tab = batch["tab_features"].to(device)
            y = batch["labels"].to(device)
            logits, _ = model(nf, nt, ei, er, b, tok, tab)
            loss = criterion(logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()
            total_loss += float(loss.item()) * len(y)
            seen += len(y)
        scheduler.step()

        val_eval = evaluate_split_v2(
            model,
            full_splits["validation"],
            gnn_splits["validation"],
            device,
            fallback_tab_ast_model=fallback_tab_ast_model,
        )
        v_full = val_eval["full_denominator"]
        avg_loss = total_loss / max(seen, 1)
        epoch_history.append({
            "epoch": epoch,
            "train_loss": round(avg_loss, 6),
            "val_f1_full_291": round(v_full["f1"], 6),
            "val_roc_auc_full_291": round(v_full["roc_auc"], 6),
        })
        if (v_full["f1"] > best_val_f1) or (
            abs(v_full["f1"] - best_val_f1) < 1e-9 and v_full["roc_auc"] > best_val_auc
        ):
            best_val_f1 = v_full["f1"]
            best_val_auc = v_full["roc_auc"]
            best_epoch = epoch
            best_weights = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    val_final = evaluate_split_v2(
        model,
        full_splits["validation"],
        gnn_splits["validation"],
        device,
        fallback_tab_ast_model=fallback_tab_ast_model,
    )
    test_final = evaluate_split_v2(
        model,
        full_splits["test"],
        gnn_splits["test"],
        device,
        fallback_tab_ast_model=fallback_tab_ast_model,
    )

    out = {
        "ablation_mode": ablation_mode,
        "seed": seed,
        "epochs": epochs,
        "best_epoch": best_epoch,
        "train_samples_used": len(train_samples),
        "train_gnn_message_passing_only": uses_graph_in_train,
        "placeholder_nodes_inserted": False,
        "validation": {
            "full_denominator": val_final["full_denominator"],
            "full_denominator_no_graph_branch": val_final["full_denominator_no_graph_branch"],
            "gnn_eligible_subset": val_final["gnn_eligible_subset"],
            "unavailable_count": val_final["unavailable_count"],
            "unavailable_decisions": val_final["unavailable_decisions"],
        },
        "test": {
            "full_denominator": test_final["full_denominator"],
            "full_denominator_no_graph_branch": test_final["full_denominator_no_graph_branch"],
            "gnn_eligible_subset": test_final["gnn_eligible_subset"],
            "unavailable_count": test_final["unavailable_count"],
            "unavailable_decisions": test_final["unavailable_decisions"],
        },
        "test_predictions": {
            "targets": test_final["targets"],
            "preds": test_final["preds"],
            "probs": test_final["probs"],
            "shas": test_final["shas"],
            "sample_ids": test_final["sample_ids"],
        },
        "epoch_history": epoch_history,
    }
    return out, model, best_weights


def measure_latency_and_params_v2(
    model: PDFTransGraph,
    test_gnn_samples: list[dict],
    device: torch.device,
) -> dict:
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    graph_params = sum(p.numel() for p in model.graph_encoder.parameters())
    ast_params = sum(p.numel() for p in model.ast_encoder.parameters())
    tab_params = sum(p.numel() for p in model.tabular_encoder.parameters())
    fusion_params = sum(p.numel() for p in model.fusion.parameters()) + sum(
        p.numel() for p in model.classifier.parameters()
    )
    single_head_params = sum(p.numel() for p in model.single_branch_head.parameters())

    loader = DataLoader(
        MultimodalPDFDatasetV2(test_gnn_samples),
        batch_size=1,
        shuffle=False,
        collate_fn=collate_multimodal_batch_v2,
    )
    model.eval()
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats()
        with torch.no_grad():
            for idx, b in enumerate(loader):
                if idx >= 10:
                    break
                _ = model(
                    b["node_features"].to(device),
                    b["node_types"].to(device),
                    b["edge_index"].to(device),
                    b["edge_rel"].to(device),
                    b["batch"].to(device),
                    b["ast_tokens"].to(device),
                    b["tab_features"].to(device),
                )
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        with torch.no_grad():
            for b in loader:
                _ = model(
                    b["node_features"].to(device),
                    b["node_types"].to(device),
                    b["edge_index"].to(device),
                    b["edge_rel"].to(device),
                    b["batch"].to(device),
                    b["ast_tokens"].to(device),
                    b["tab_features"].to(device),
                )
        torch.cuda.synchronize()
        gpu_ms = ((time.perf_counter() - t0) / len(test_gnn_samples)) * 1000.0
        peak_vram_mb = torch.cuda.max_memory_allocated() / (1024.0 * 1024.0)
    else:
        gpu_ms = 0.0
        peak_vram_mb = 0.0

    cpu_device = torch.device("cpu")
    model_cpu = model.to(cpu_device)
    model_cpu.eval()
    with torch.no_grad():
        for idx, b in enumerate(loader):
            if idx >= 5:
                break
            _ = model_cpu(
                b["node_features"].to(cpu_device),
                b["node_types"].to(cpu_device),
                b["edge_index"].to(cpu_device),
                b["edge_rel"].to(cpu_device),
                b["batch"].to(cpu_device),
                b["ast_tokens"].to(cpu_device),
                b["tab_features"].to(cpu_device),
            )
    t_cpu = time.perf_counter()
    with torch.no_grad():
        for b in loader:
            _ = model_cpu(
                b["node_features"].to(cpu_device),
                b["node_types"].to(cpu_device),
                b["edge_index"].to(cpu_device),
                b["edge_rel"].to(cpu_device),
                b["batch"].to(cpu_device),
                b["ast_tokens"].to(cpu_device),
                b["tab_features"].to(cpu_device),
            )
    cpu_ms = ((time.perf_counter() - t_cpu) / len(test_gnn_samples)) * 1000.0
    model.to(device)
    return {
        "node_in_dim": NODE_FEATURE_DIM_V2,
        "total_parameters": total_params,
        "graph_encoder_params": graph_params,
        "ast_encoder_params": ast_params,
        "tabular_encoder_params": tab_params,
        "fusion_and_head_params": fusion_params,
        "single_branch_head_params": single_head_params,
        "gpu_latency_ms_per_sample": round(gpu_ms, 3),
        "cpu_latency_ms_per_sample": round(cpu_ms, 3),
        "peak_vram_mb": round(peak_vram_mb, 2),
    }


def summarize_seed_runs(runs: list[dict]) -> dict:
    metric_names = ("accuracy", "precision", "recall", "f1", "mcc", "roc_auc", "pr_auc", "brier")
    out = {}
    for m_name in metric_names:
        vals = [r["test"]["full_denominator"][m_name] for r in runs]
        out[f"{m_name}_mean"] = float(np.mean(vals))
        out[f"{m_name}_std"] = float(np.std(vals))
        out[f"{m_name}_min"] = float(np.min(vals))
        out[f"{m_name}_max"] = float(np.max(vals))
    return out


def build_error_analysis(test_samples: list[dict], pred_bundle: dict) -> dict:
    meta_by_sha = {s["sha256"]: s["meta"] for s in test_samples}
    fn_samples = []
    fp_samples = []
    fn_by_status: dict[str, int] = {}
    fp_by_status: dict[str, int] = {}
    fn_by_disposition: dict[str, int] = {}
    fp_by_disposition: dict[str, int] = {}

    for y_true, y_pred, prob, sha, sid in zip(
        pred_bundle["targets"],
        pred_bundle["preds"],
        pred_bundle["probs"],
        pred_bundle["shas"],
        pred_bundle["sample_ids"],
    ):
        meta = meta_by_sha[sha]
        st = str(meta["status"])
        disp = str(meta["sample_disposition"])
        entry = {
            "index": meta["index"],
            "sample_id": sid,
            "sha256": sha,
            "predicted_prob": round(float(prob), 4),
            "status": st,
            "sample_disposition": disp,
            "has_js": int(meta.get("JS", 0.0) > 0 or meta.get("Javascript", 0.0) > 0),
            "pdf_size": meta.get("PdfSize"),
            "streams": meta.get("Stream"),
            "xfa": meta.get("XFA"),
        }
        if y_true == 1 and y_pred == 0:
            fn_samples.append(entry)
            fn_by_status[st] = fn_by_status.get(st, 0) + 1
            fn_by_disposition[disp] = fn_by_disposition.get(disp, 0) + 1
        elif y_true == 0 and y_pred == 1:
            fp_samples.append(entry)
            fp_by_status[st] = fp_by_status.get(st, 0) + 1
            fp_by_disposition[disp] = fp_by_disposition.get(disp, 0) + 1

    return {
        "test_denominator": len(test_samples),
        "test_malware_total": sum(1 for s in test_samples if s["label"] == 1),
        "test_benign_total": sum(1 for s in test_samples if s["label"] == 0),
        "false_negatives_count": len(fn_samples),
        "false_positives_count": len(fp_samples),
        "fn_by_status": dict(sorted(fn_by_status.items())),
        "fp_by_status": dict(sorted(fp_by_status.items())),
        "fn_by_disposition": dict(sorted(fn_by_disposition.items())),
        "fp_by_disposition": dict(sorted(fp_by_disposition.items())),
        "false_negatives": fn_samples,
        "false_positives": fp_samples,
    }


def render_markdown_report(
    run_id: str,
    commit: str,
    device_name: str,
    verified_export: dict,
    ablation_summary: dict[str, dict],
    v1_comparison: dict,
    academic_3seed: dict,
    protocol_g_5seed: dict,
    error_analysis: dict,
    complexity: dict,
) -> str:
    gate = verified_export["gate_summary"]
    lines = [
        f"# Canonical PDF-TransGraph v2 (23D) Training & Evaluation Report — `{run_id}`",
        "",
        "## 1. Provenance & Quality Gate v2 Pre-Flight Verification",
        "",
        f"- **Git Commit:** `{commit}`",
        f"- **Execution Device:** `{device_name}`",
        f"- **Canonical Extraction Job ID:** `{verified_export['locked_methodology']['baseline_job_id']}`",
        f"- **Quality Gate Contract:** `{gate['gate_contract_version']}` (`{gate['cohort_gate_verdict']}`, `{gate['checks_passed_count']}/{gate['checks_total_count']}` checks passed)",
        f"- **Graph Projection Contract:** `{gate['projection_contract_version']}` (`node_feature_dim = {gate['node_feature_dim']}`, `node_cap = {gate['node_cap']}`)",
        f"- **Cohort Accounting:** `1,452` planned (`870` train, `291` validation, `291` test); `1,446` GNN-eligible 23D graphs (`866` train, `289` validation, `291` test); `6` ledgered unavailable empty-graph documents (`train=[11, 292, 407, 749]`, `validation=[3, 141]`, `test=[]`).",
        f"- **Strict Policy Enforcement:** `placeholder_nodes_inserted = false`, `eval_denominator_shrinkage_allowed = false`, `StandardScaler` fit strictly on `train` (`870` rows).",
        "",
        "## 2. Component Ablation Study (Seed 42 — Full Split Denominators: Val=291, Test=291)",
        "",
        "| Configuration | Mode | Train N | Val Acc (291) | Val F1 (291) | Test Acc (291) | Test Precision | Test Recall | Test F1 | Test MCC | Test ROC-AUC | Test PR-AUC |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, entry in ablation_summary.items():
        va = entry["validation"]["full_denominator"]
        te = entry["test"]["full_denominator"]
        lines.append(
            f"| {label} | `{entry['ablation_mode']}` | {entry['train_samples_used']} | "
            f"{va['accuracy']*100:.2f}% | {va['f1']:.4f} | "
            f"{te['accuracy']*100:.2f}% | {te['precision']*100:.2f}% | {te['recall']*100:.2f}% | "
            f"{te['f1']:.4f} | {te['mcc']:.4f} | {te['roc_auc']:.4f} | {te['pr_auc']:.4f} |"
        )

    if v1_comparison.get("available"):
        lines.extend([
            "",
            "## 3. Representation Comparison: Legacy 19D (`v1`) vs Provenance-Backed 23D (`v2`)",
            "",
            "| Configuration | `v1` (19D) Test Acc | `v2` (23D) Test Acc | `v1` (19D) Test F1 | `v2` (23D) Test F1 | `v1` (19D) ROC-AUC | `v2` (23D) ROC-AUC | F1 Delta (`v2 - v1`) |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ])
        for label, row in v1_comparison["rows"].items():
            lines.append(
                f"| {label} | {row['v1_accuracy']*100:.2f}% | {row['v2_accuracy']*100:.2f}% | "
                f"{row['v1_f1']:.4f} | {row['v2_f1']:.4f} | "
                f"{row['v1_roc_auc']:.4f} | {row['v2_roc_auc']:.4f} | "
                f"{row['f1_delta']:+.4f} |"
            )

    s3 = academic_3seed["statistics"]
    s5 = protocol_g_5seed["statistics"]
    lines.extend([
        "",
        "## 4. Multi-Seed Statistical Significance (`PDF-TransGraph v2 Full`, 23D)",
        "",
        "### 4.1 Academic 3-Seed Suite (`[42, 100, 2026]`)",
        f"- **Test Accuracy:** `{s3['accuracy_mean']*100:.2f}% +/- {s3['accuracy_std']*100:.2f}%`",
        f"- **Test Precision:** `{s3['precision_mean']*100:.2f}% +/- {s3['precision_std']*100:.2f}%`",
        f"- **Test Recall:** `{s3['recall_mean']*100:.2f}% +/- {s3['recall_std']*100:.2f}%`",
        f"- **Test F1-Score:** `{s3['f1_mean']:.4f} +/- {s3['f1_std']:.4f}`",
        f"- **Test MCC:** `{s3['mcc_mean']:.4f} +/- {s3['mcc_std']:.4f}`",
        f"- **Test ROC-AUC:** `{s3['roc_auc_mean']:.4f} +/- {s3['roc_auc_std']:.4f}`",
        f"- **Test PR-AUC:** `{s3['pr_auc_mean']:.4f} +/- {s3['pr_auc_std']:.4f}`",
        f"- **Test Brier Score:** `{s3['brier_mean']:.4f} +/- {s3['brier_std']:.4f}`",
        "",
        "### 4.2 Protocol G 5-Seed Suite (`[42, 43, 44, 45, 46]`)",
        f"- **Test Accuracy:** `{s5['accuracy_mean']*100:.2f}% +/- {s5['accuracy_std']*100:.2f}%`",
        f"- **Test Precision:** `{s5['precision_mean']*100:.2f}% +/- {s5['precision_std']*100:.2f}%`",
        f"- **Test Recall:** `{s5['recall_mean']*100:.2f}% +/- {s5['recall_std']*100:.2f}%`",
        f"- **Test F1-Score:** `{s5['f1_mean']:.4f} +/- {s5['f1_std']:.4f}`",
        f"- **Test MCC:** `{s5['mcc_mean']:.4f} +/- {s5['mcc_std']:.4f}`",
        f"- **Test ROC-AUC:** `{s5['roc_auc_mean']:.4f} +/- {s5['roc_auc_std']:.4f}`",
        f"- **Test PR-AUC:** `{s5['pr_auc_mean']:.4f} +/- {s5['pr_auc_std']:.4f}`",
        f"- **Test Brier Score:** `{s5['brier_mean']:.4f} +/- {s5['brier_std']:.4f}`",
        "",
        "### 4.3 Individual Seed Runs (`Test N = 291`)",
        "",
        "| Seed | Val F1 (291) | Val F1 (GNN 289) | Test Acc (291) | Test Precision | Test Recall | Test F1 | Test MCC | Test ROC-AUC | Confusion Matrix (TN, FP, FN, TP) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for r in protocol_g_5seed["all_unique_seed_runs"]:
        va_f = r["validation"]["full_denominator"]
        va_g = r["validation"]["gnn_eligible_subset"]
        te = r["test"]["full_denominator"]
        cm = te["confusion_matrix"]
        lines.append(
            f"| {r['seed']} | {va_f['f1']:.4f} | {va_g['f1']:.4f} | "
            f"{te['accuracy']*100:.2f}% | {te['precision']*100:.2f}% | {te['recall']*100:.2f}% | "
            f"{te['f1']:.4f} | {te['mcc']:.4f} | {te['roc_auc']:.4f} | "
            f"`({cm['tn']}, {cm['fp']}, {cm['fn']}, {cm['tp']})` |"
        )

    lines.extend([
        "",
        "## 5. Error Taxonomy & Unavailable-Document Audit (Seed 42)",
        "",
        f"- **Held-Out Test Set (`291` samples, `0` unavailable):** `{error_analysis['false_negatives_count']}/{error_analysis['test_malware_total']}` False Negatives, `{error_analysis['false_positives_count']}/{error_analysis['test_benign_total']}` False Positives.",
        f"- **False Negatives by Extraction Status:** `{json.dumps(error_analysis['fn_by_status'])}`",
        f"- **False Positives by Extraction Status:** `{json.dumps(error_analysis['fp_by_status'])}`",
        f"- **False Negatives by Sample Disposition:** `{json.dumps(error_analysis['fn_by_disposition'])}`",
        f"- **False Positives by Sample Disposition:** `{json.dumps(error_analysis['fp_by_disposition'])}`",
        "",
        "## 6. Computational Complexity & Latency Benchmark",
        "",
        f"- **Node Input Dimension:** `{complexity['node_in_dim']}D`",
        f"- **Total Trainable Parameters:** `{complexity['total_parameters']:,}`",
        f"  - Graph Encoder (`HeteroGraphTransformer` 23D): `{complexity['graph_encoder_params']:,}`",
        f"  - AST Encoder (`ASTSequenceTransformer` RoPE): `{complexity['ast_encoder_params']:,}`",
        f"  - Tabular Encoder (`TabularResNet`): `{complexity['tabular_encoder_params']:,}`",
        f"  - Cross-Modal Attention & Classifier Head: `{complexity['fusion_and_head_params']:,}`",
        f"- **GPU Inference Latency:** `{complexity['gpu_latency_ms_per_sample']} ms/sample` (Peak VRAM: `{complexity['peak_vram_mb']} MB`)",
        f"- **CPU Inference Latency:** `{complexity['cpu_latency_ms_per_sample']} ms/sample`",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-dir", type=Path, default=DEFAULT_EXPORT_DIR)
    parser.add_argument("--parquet-ours", type=Path, default=DEFAULT_PARQUET_OURS)
    parser.add_argument("--parquet-cic", type=Path, default=DEFAULT_PARQUET_CIC)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--checkpoint-root", type=Path, default=DEFAULT_CHECKPOINT_ROOT)
    parser.add_argument("--epochs", type=int, default=25)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    device_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
    print(f"Using device: {device} ({device_name})")

    dataset_bundle = load_multimodal_dataset_v2(
        args.export_dir,
        args.parquet_ours,
        args.parquet_cic,
    )
    verified_export = dataset_bundle["verified_export"]
    full_splits = dataset_bundle["full_split_samples"]
    gnn_splits = dataset_bundle["gnn_eligible_samples"]
    print(
        f"Verified v2 export: full splits={{train:{len(full_splits['train'])}, "
        f"val:{len(full_splits['validation'])}, test:{len(full_splits['test'])}}} | "
        f"gnn_eligible={{train:{len(gnn_splits['train'])}, "
        f"val:{len(gnn_splits['validation'])}, test:{len(gnn_splits['test'])}}}"
    )

    print("\n=== 1. COMPONENT ABLATION STUDY (SEED 42, 23D V2) ===")
    ablation_order = [
        ("Tabular ResNet Only", "tab_only"),
        ("AST Transformer Only", "ast_only"),
        ("Tabular + AST (No Graph)", "tab_ast"),
        ("Hetero HGT Graph Only", "graph_only"),
        ("Tabular + HGT (No AST)", "tab_graph"),
        ("PDF-TransGraph Full (All 3 Fused)", "full"),
    ]
    ablation_summary: dict[str, dict] = {}
    tab_ast_model_seed42: PDFTransGraph | None = None
    full_model_seed42: PDFTransGraph | None = None
    full_weights_seed42: dict[str, torch.Tensor] | None = None
    tab_ast_weights_seed42: dict[str, torch.Tensor] | None = None

    for label, mode in ablation_order:
        print(f"Training ablation mode: {label} ({mode})...")
        res, mdl, weights = train_and_eval_mode_v2(
            dataset_bundle,
            mode,
            seed=42,
            epochs=args.epochs,
            device=device,
            fallback_tab_ast_model=tab_ast_model_seed42,
        )
        if mode == "tab_ast":
            tab_ast_model_seed42 = mdl
            tab_ast_weights_seed42 = weights
        elif mode == "full":
            full_model_seed42 = mdl
            full_weights_seed42 = weights
        ablation_summary[label] = res
        te = res["test"]["full_denominator"]
        va = res["validation"]["full_denominator"]
        print(
            f"  -> Val F1 (291): {va['f1']:.4f} | Test Acc (291): {te['accuracy']*100:.2f}% | "
            f"Recall: {te['recall']*100:.2f}% | F1: {te['f1']:.4f} | ROC-AUC: {te['roc_auc']:.4f}"
        )

    print("\n=== 2. MULTI-SEED STATISTICAL SIGNIFICANCE (SEEDS 42, 100, 2026, 43, 44, 45, 46) ===")
    all_seeds = [42, 100, 2026, 43, 44, 45, 46]
    seed_run_map: dict[int, dict] = {42: ablation_summary["PDF-TransGraph Full (All 3 Fused)"]}
    for s in all_seeds:
        if s == 42:
            te = seed_run_map[42]["test"]["full_denominator"]
            print(
                f"  Seed 42 (cached) -> Test Acc: {te['accuracy']*100:.2f}% | "
                f"Recall: {te['recall']*100:.2f}% | F1: {te['f1']:.4f} | AUC: {te['roc_auc']:.4f}"
            )
            continue
        print(f"Training verified tab_ast fallback + Full PDF-TransGraph v2 (23D) for Seed {s}...")
        _, fb_mdl, _ = train_and_eval_mode_v2(
            dataset_bundle,
            "tab_ast",
            seed=s,
            epochs=args.epochs,
            device=device,
        )
        run_s, _, _ = train_and_eval_mode_v2(
            dataset_bundle,
            "full",
            seed=s,
            epochs=args.epochs,
            device=device,
            fallback_tab_ast_model=fb_mdl,
        )
        seed_run_map[s] = run_s
        te = run_s["test"]["full_denominator"]
        print(
            f"  Seed {s} -> Test Acc: {te['accuracy']*100:.2f}% | "
            f"Recall: {te['recall']*100:.2f}% | F1: {te['f1']:.4f} | AUC: {te['roc_auc']:.4f}"
        )

    academic_seeds = [42, 100, 2026]
    protocol_g_seeds = [42, 43, 44, 45, 46]
    academic_runs = [seed_run_map[s] for s in academic_seeds]
    protocol_g_runs = [seed_run_map[s] for s in protocol_g_seeds]

    academic_3seed = {
        "seeds": academic_seeds,
        "statistics": summarize_seed_runs(academic_runs),
        "individual_runs": [
            {
                "seed": r["seed"],
                "best_epoch": r["best_epoch"],
                "validation_full_291": r["validation"]["full_denominator"],
                "validation_gnn_289": r["validation"]["gnn_eligible_subset"],
                "test_full_291": r["test"]["full_denominator"],
            }
            for r in academic_runs
        ],
    }
    protocol_g_5seed = {
        "seeds": protocol_g_seeds,
        "statistics": summarize_seed_runs(protocol_g_runs),
        "individual_runs": [
            {
                "seed": r["seed"],
                "best_epoch": r["best_epoch"],
                "validation_full_291": r["validation"]["full_denominator"],
                "validation_gnn_289": r["validation"]["gnn_eligible_subset"],
                "test_full_291": r["test"]["full_denominator"],
            }
            for r in protocol_g_runs
        ],
        "all_unique_seed_runs": [seed_run_map[s] for s in all_seeds],
    }

    v1_comparison = {"available": False, "rows": {}}
    if V1_ABLATION_PATH.is_file():
        v1_data = json.loads(V1_ABLATION_PATH.read_text(encoding="utf-8"))
        v1_abl = v1_data.get("ablation_study", {})
        comp_rows = {}
        for label, v2_entry in ablation_summary.items():
            if label in v1_abl:
                v1_m = v1_abl[label]
                v2_m = v2_entry["test"]["full_denominator"]
                comp_rows[label] = {
                    "v1_accuracy": float(v1_m["accuracy"]),
                    "v2_accuracy": float(v2_m["accuracy"]),
                    "accuracy_delta": round(float(v2_m["accuracy"]) - float(v1_m["accuracy"]), 6),
                    "v1_f1": float(v1_m["f1"]),
                    "v2_f1": float(v2_m["f1"]),
                    "f1_delta": round(float(v2_m["f1"]) - float(v1_m["f1"]), 6),
                    "v1_recall": float(v1_m["recall"]),
                    "v2_recall": float(v2_m["recall"]),
                    "recall_delta": round(float(v2_m["recall"]) - float(v1_m["recall"]), 6),
                    "v1_roc_auc": float(v1_m["roc_auc"]),
                    "v2_roc_auc": float(v2_m["roc_auc"]),
                    "roc_auc_delta": round(float(v2_m["roc_auc"]) - float(v1_m["roc_auc"]), 6),
                }
        v1_comparison = {"available": True, "rows": comp_rows}

    print("\n=== 3. ERROR ANALYSIS & LATENCY BENCHMARK ===")
    error_analysis = build_error_analysis(
        full_splits["test"],
        seed_run_map[42]["test_predictions"],
    )
    assert full_model_seed42 is not None
    complexity = measure_latency_and_params_v2(
        full_model_seed42,
        gnn_splits["test"],
        device,
    )
    print(
        f"Test FN: {error_analysis['false_negatives_count']}/{error_analysis['test_malware_total']} | "
        f"Test FP: {error_analysis['false_positives_count']}/{error_analysis['test_benign_total']}"
    )
    print(
        f"Params: {complexity['total_parameters']:,} | "
        f"GPU: {complexity['gpu_latency_ms_per_sample']} ms/sample ({complexity['peak_vram_mb']} MB) | "
        f"CPU: {complexity['cpu_latency_ms_per_sample']} ms/sample"
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    commit_short = git_commit_short()
    commit_full = git_commit_full()
    run_id = f"run_{stamp}_{commit_short}"

    run_report_dir = args.report_root / run_id
    run_report_dir.mkdir(parents=True, exist_ok=True)
    run_ckpt_dir = args.checkpoint_root / run_id
    run_ckpt_dir.mkdir(parents=True, exist_ok=True)

    assert full_weights_seed42 is not None and tab_ast_weights_seed42 is not None
    full_ckpt_path = run_ckpt_dir / "pdf_transgraph_v2_23d_seed42_best.pt"
    tab_ast_ckpt_path = run_ckpt_dir / "pdf_transgraph_v2_tab_ast_seed42_best.pt"
    torch.save(full_weights_seed42, full_ckpt_path)
    torch.save(tab_ast_weights_seed42, tab_ast_ckpt_path)
    _ = torch.load(full_ckpt_path, map_location="cpu", weights_only=True)
    _ = torch.load(tab_ast_ckpt_path, map_location="cpu", weights_only=True)

    locked_methodology = {
        "schema_version": 2,
        "study": "pdf_transgraph_v2",
        "run_id": run_id,
        "generated_utc": stamp,
        "git_commit": commit_full,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "tabular_in_features": dataset_bundle["tabular_in_features"],
        "tabular_feature_names": dataset_bundle["tabular_feature_names"],
        "protocol": "Protocol G",
        "primary_seed": 42,
        "academic_seeds": academic_seeds,
        "protocol_g_seeds": protocol_g_seeds,
        "epochs": args.epochs,
        "batch_size_train": 32,
        "batch_size_eval": 64,
        "optimizer": {"name": "AdamW", "lr": 1e-3, "weight_decay": 1e-4},
        "loss": {"name": "FocalLoss", "alpha": 0.6, "gamma": 2.0},
        "scaler_fit_partition": "train_only_870",
        "unavailable_document_policy": verified_export["gate_summary"]["unavailable_document_policy"],
        "source_export": {
            "export_dir": verified_export["export_dir"],
            "baseline_job_id": verified_export["locked_methodology"]["baseline_job_id"],
            "verified_files": verified_export["verified_hashes"],
        },
        "checkpoints": {
            "full_seed42_path": str(full_ckpt_path.relative_to(REPO)),
            "full_seed42_sha256": sha256_bytes(full_ckpt_path.read_bytes()),
            "tab_ast_seed42_path": str(tab_ast_ckpt_path.relative_to(REPO)),
            "tab_ast_seed42_sha256": sha256_bytes(tab_ast_ckpt_path.read_bytes()),
        },
    }

    sanitized_ablation = {}
    for label, entry in ablation_summary.items():
        sanitized_ablation[label] = {
            k: v for k, v in entry.items() if k not in {"test_predictions", "epoch_history"}
        }

    metrics_payload = {
        "schema_version": 2,
        "run_id": run_id,
        "git_commit": commit_full,
        "device": device_name,
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "tabular_in_features": dataset_bundle["tabular_in_features"],
        "seed42_full_model": {
            "validation_full_291": seed_run_map[42]["validation"]["full_denominator"],
            "validation_no_graph_branch_291": seed_run_map[42]["validation"]["full_denominator_no_graph_branch"],
            "validation_gnn_289": seed_run_map[42]["validation"]["gnn_eligible_subset"],
            "validation_unavailable_decisions": seed_run_map[42]["validation"]["unavailable_decisions"],
            "test_full_291": seed_run_map[42]["test"]["full_denominator"],
            "test_gnn_291": seed_run_map[42]["test"]["gnn_eligible_subset"],
        },
        "academic_3seed_summary": academic_3seed["statistics"],
        "protocol_g_5seed_summary": protocol_g_5seed["statistics"],
        "complexity_and_latency": complexity,
    }

    full_results_payload = {
        "schema_version": 2,
        "run_id": run_id,
        "ablation_study_seed42": sanitized_ablation,
        "v1_vs_v2_comparison": v1_comparison,
        "academic_3seed_significance": academic_3seed,
        "protocol_g_5seed_significance": {
            "seeds": protocol_g_5seed["seeds"],
            "statistics": protocol_g_5seed["statistics"],
            "individual_runs": protocol_g_5seed["individual_runs"],
        },
        "error_analysis_seed42_test": error_analysis,
        "complexity_and_latency": complexity,
    }

    report_md = render_markdown_report(
        run_id=run_id,
        commit=commit_full,
        device_name=device_name,
        verified_export=verified_export,
        ablation_summary=sanitized_ablation,
        v1_comparison=v1_comparison,
        academic_3seed=academic_3seed,
        protocol_g_5seed=protocol_g_5seed,
        error_analysis=error_analysis,
        complexity=complexity,
    )

    files_to_write = {
        "locked_methodology.json": json.dumps(locked_methodology, indent=2, sort_keys=True) + "\n",
        "metrics.json": json.dumps(metrics_payload, indent=2, sort_keys=True) + "\n",
        "ablation_and_multiseed_results.json": json.dumps(full_results_payload, indent=2, sort_keys=True) + "\n",
        "report.md": report_md,
    }
    manifest_entries = {}
    for fname, content in files_to_write.items():
        fpath = run_report_dir / fname
        raw_bytes = content.encode("utf-8")
        fpath.write_bytes(raw_bytes)
        manifest_entries[fname] = {
            "bytes": len(raw_bytes),
            "sha256": sha256_bytes(raw_bytes),
        }

    run_manifest = {
        "schema_version": 2,
        "run_id": run_id,
        "generated_utc": stamp,
        "git_commit": commit_full,
        "files": manifest_entries,
    }
    (run_report_dir / "manifest.json").write_text(
        json.dumps(run_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.report_root / "latest_summary.json").write_text(
        json.dumps(metrics_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"\nCompleted canonical v2 training & evaluation! Artifacts written to: {run_report_dir}")


if __name__ == "__main__":
    main()

