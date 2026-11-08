import gzip
import json
from pathlib import Path
import time
import numpy as np
import pandas as pd
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
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import DataLoader, Dataset

from malpdf.data.graph_contract import index_measured_graphs
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph

REPO = Path(__file__).resolve().parents[2]
GRAPHS_PATH = REPO / "data/processed/cic_full/hetero_cic_graphs.json.gz"
PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
REPORT_DIR = REPO / "reports/experiments/pdf_transgraph"


def safe_div(a: pd.Series, b: pd.Series) -> pd.Series:
    res = a.astype(float) / np.maximum(b.astype(float).abs(), 1.0)
    return res.replace([np.inf, -np.inf, np.nan], 0.0)


class MultimodalPDFDataset(Dataset):
    def __init__(self, samples: list[dict]):
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        return self.samples[idx]


def collate_multimodal_batch(batch: list[dict]) -> dict:
    all_node_feats = []
    all_node_types = []
    all_edge_src = []
    all_edge_dst = []
    all_edge_rel = []
    batch_indices = []
    ast_tokens_list = []
    tab_feats_list = []
    labels_list = []
    sha256_list = []
    sample_ids = []
    current_node_offset = 0
    for graph_idx, sample in enumerate(batch):
        nf = sample["node_features"]
        nt = sample["node_types"]
        num_nodes = nf.size(0)
        all_node_feats.append(nf)
        all_node_types.append(nt)
        batch_indices.append(torch.full((num_nodes,), graph_idx, dtype=torch.long))
        e_src = sample["edge_src"]
        e_dst = sample["edge_dst"]
        if e_src.numel() > 0:
            all_edge_src.append(e_src + current_node_offset)
            all_edge_dst.append(e_dst + current_node_offset)
            all_edge_rel.append(sample["edge_rel"])
        current_node_offset += num_nodes
        ast_tokens_list.append(sample["ast_tokens"])
        tab_feats_list.append(sample["tab_features"])
        labels_list.append(sample["label"])
        sha256_list.append(sample["sha256"])
        sample_ids.append(sample.get("sample_id", ""))
    batched_node_feats = torch.cat(all_node_feats, dim=0)
    batched_node_types = torch.cat(all_node_types, dim=0)
    batched_batch = torch.cat(batch_indices, dim=0)
    if len(all_edge_src) > 0:
        batched_edge_index = torch.stack([torch.cat(all_edge_src, dim=0), torch.cat(all_edge_dst, dim=0)], dim=0)
        batched_edge_rel = torch.cat(all_edge_rel, dim=0)
    else:
        batched_edge_index = torch.zeros((2, 0), dtype=torch.long)
        batched_edge_rel = torch.zeros((0,), dtype=torch.long)
    return {
        "node_features": batched_node_feats,
        "node_types": batched_node_types,
        "edge_index": batched_edge_index,
        "edge_rel": batched_edge_rel,
        "batch": batched_batch,
        "ast_tokens": torch.stack(ast_tokens_list, dim=0),
        "tab_features": torch.stack(tab_feats_list, dim=0),
        "labels": torch.tensor(labels_list, dtype=torch.float32),
        "sha256": sha256_list,
        "sample_ids": sample_ids,
    }


def compute_metrics(y_true, y_pred, y_prob):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    return {
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


def load_dataset():
    df_ours = pd.read_parquet(PARQUET_OURS)
    df_cic = pd.read_parquet(PARQUET_CIC)
    merged = pd.merge(df_ours, df_cic, left_on="pdf_sha256", right_on="FileName", how="inner")
    cic_cols = [c for c in df_cic.columns if c not in {"FileName", "Class"}]
    for c in cic_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").fillna(-1.0)
    merged["density_stream_ratio"] = safe_div(merged["Stream"], merged["PdfSize"])
    merged["density_obj_stream_ratio"] = safe_div(merged["Obj"], merged["Stream"])
    merged["density_metadata_ratio"] = safe_div(merged["MetadataSize"], merged["PdfSize"])
    merged["entropy_gap"] = (merged["raw_prefix_entropy"] - merged["raw_suffix_entropy"]).abs().fillna(0.0)
    merged["ast_complexity_per_node"] = safe_div(merged["legacy_observed_ast_max_depth"], merged["legacy_observed_ast_node_count"])
    merged["ast_call_ratio"] = safe_div(merged["legacy_observed_ast_type_CallExpression"], merged["legacy_observed_ast_node_count"])
    merged["ast_identifier_ratio"] = safe_div(merged["legacy_observed_ast_type_Identifier"], merged["legacy_observed_ast_node_count"])
    merged["ast_computed_ratio"] = safe_div(merged["legacy_observed_ast_computed_members"], merged["legacy_observed_ast_node_count"])
    pillar_engineered_cols = [
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
    ]
    for c in pillar_engineered_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)
    evasion_cols = [
        "evasive_timeout_anomaly",
        "flag_decompression_ratio_exceeded",
        "is_truncated_stream",
        "flag_spec_violation_flood",
        "flag_excessive_object_graph",
        "flag_ast_complexity_truncated",
    ]
    for c in evasion_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)
    entropy_cols = ["raw_entropy", "raw_prefix_entropy", "raw_suffix_entropy"]
    for c in entropy_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)
    key_cic_cols = [
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
    ]
    tab_cols = key_cic_cols + pillar_engineered_cols + evasion_cols + entropy_cols
    train_mask = merged["split"] == "train"
    scaler = StandardScaler()
    scaler.fit(merged.loc[train_mask, tab_cols].values)
    scaled_tab = scaler.transform(merged[tab_cols].values).astype(np.float32)
    merged_tab_dict = {row["pdf_sha256"]: scaled_tab[i] for i, (_, row) in enumerate(merged.iterrows())}
    meta_info_dict = {
        row["pdf_sha256"]: {
            "sample_id": row["sample_id"],
            "status": row.get("status", "unknown"),
            "PdfSize": row.get("PdfSize", 0),
            "Stream": row.get("Stream", 0),
            "JS": row.get("JS", 0),
            "Javascript": row.get("Javascript", 0),
            "XFA": row.get("XFA", 0),
            "StartXref": row.get("StartXref", 0),
        }
        for _, row in merged.iterrows()
    }
    with gzip.open(GRAPHS_PATH, "rt", encoding="utf-8") as stream:
        raw_graphs = json.load(stream)
    graph_dict = index_measured_graphs(raw_graphs, set(merged["pdf_sha256"]))
    samples_by_split = {"train": [], "validation": [], "test": []}
    ast_type_cols = [c for c in df_ours.columns if "ast_type_" in c]
    for _, row in merged.iterrows():
        sha = row["pdf_sha256"]
        split = row["split"]
        label = int(row["Label"])
        tab_feat = torch.tensor(merged_tab_dict[sha], dtype=torch.float32)
        ast_counts = [float(row[c]) if c in row and not pd.isna(row[c]) else 0.0 for c in ast_type_cols[:32]]
        if len(ast_counts) < 32:
            ast_counts += [0.0] * (32 - len(ast_counts))
        ast_tokens = torch.tensor([int(c) % 64 for c in ast_counts], dtype=torch.long)
        g = graph_dict[sha]
        nf = torch.tensor(g["node_features"], dtype=torch.float32)
        nt = torch.tensor(g["node_types"], dtype=torch.long)
        e_src = torch.tensor(g["edge_src"], dtype=torch.long)
        e_dst = torch.tensor(g["edge_dst"], dtype=torch.long)
        e_rel = torch.tensor(g["edge_rel"], dtype=torch.long)
        samples_by_split[split].append(
            {
                "sha256": sha,
                "sample_id": meta_info_dict[sha]["sample_id"],
                "node_features": nf,
                "node_types": nt,
                "edge_src": e_src,
                "edge_dst": e_dst,
                "edge_rel": e_rel,
                "ast_tokens": ast_tokens,
                "tab_features": tab_feat,
                "label": label,
                "meta": meta_info_dict[sha],
            }
        )
    return samples_by_split, len(tab_cols)


def train_and_eval(samples_by_split, tab_dim, ablation_mode, seed, epochs, device):
    torch.manual_seed(seed)
    np.random.seed(seed)
    train_ds = MultimodalPDFDataset(samples_by_split["train"])
    val_ds = MultimodalPDFDataset(samples_by_split["validation"])
    test_ds = MultimodalPDFDataset(samples_by_split["test"])
    train_loader = DataLoader(train_ds, batch_size=32, shuffle=True, collate_fn=collate_multimodal_batch)
    val_loader = DataLoader(val_ds, batch_size=64, shuffle=False, collate_fn=collate_multimodal_batch)
    test_loader = DataLoader(test_ds, batch_size=64, shuffle=False, collate_fn=collate_multimodal_batch)
    model = PDFTransGraph(
        node_in_dim=19,
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
    best_weights = None
    for epoch in range(1, epochs + 1):
        model.train()
        for batch in train_loader:
            optimizer.zero_grad()
            nf = batch["node_features"].to(device)
            nt = batch["node_types"].to(device)
            ei = batch["edge_index"].to(device)
            er = batch["edge_rel"].to(device)
            b = batch["batch"].to(device)
            tok = batch["ast_tokens"].to(device)
            tab = batch["tab_features"].to(device)
            y = batch["labels"].to(device)
            logits, _ = model(nf, nt, ei, er, b, tok, tab)
            loss = criterion(logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()
        scheduler.step()
        model.eval()
        val_probs, val_preds, val_targets = [], [], []
        with torch.no_grad():
            for batch in val_loader:
                nf = batch["node_features"].to(device)
                nt = batch["node_types"].to(device)
                ei = batch["edge_index"].to(device)
                er = batch["edge_rel"].to(device)
                b = batch["batch"].to(device)
                tok = batch["ast_tokens"].to(device)
                tab = batch["tab_features"].to(device)
                y = batch["labels"].to(device)
                logits, _ = model(nf, nt, ei, er, b, tok, tab)
                probs = torch.sigmoid(logits)
                preds = (probs >= 0.5).long()
                val_probs.extend(probs.cpu().tolist())
                val_preds.extend(preds.cpu().tolist())
                val_targets.extend(y.cpu().tolist())
        v_metrics = compute_metrics(val_targets, val_preds, val_probs)
        if v_metrics["f1"] > best_val_f1:
            best_val_f1 = v_metrics["f1"]
            best_weights = {k: v.cpu() for k, v in model.state_dict().items()}
    if best_weights is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    model.eval()
    test_probs, test_preds, test_targets, test_shas, test_samples = [], [], [], [], []
    with torch.no_grad():
        for batch in test_loader:
            nf = batch["node_features"].to(device)
            nt = batch["node_types"].to(device)
            ei = batch["edge_index"].to(device)
            er = batch["edge_rel"].to(device)
            b = batch["batch"].to(device)
            tok = batch["ast_tokens"].to(device)
            tab = batch["tab_features"].to(device)
            y = batch["labels"].to(device)
            logits, _ = model(nf, nt, ei, er, b, tok, tab)
            probs = torch.sigmoid(logits)
            preds = (probs >= 0.5).long()
            test_probs.extend(probs.cpu().tolist())
            test_preds.extend(preds.cpu().tolist())
            test_targets.extend(y.cpu().tolist())
            test_shas.extend(batch["sha256"])
            test_samples.extend(batch["sample_ids"])
    te_metrics = compute_metrics(test_targets, test_preds, test_probs)
    return te_metrics, test_targets, test_preds, test_probs, test_shas, test_samples, model


def measure_latency_and_params(model, test_ds, tab_dim, device):
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    graph_params = sum(p.numel() for p in model.graph_encoder.parameters())
    ast_params = sum(p.numel() for p in model.ast_encoder.parameters())
    tab_params = sum(p.numel() for p in model.tabular_encoder.parameters())
    fusion_params = sum(p.numel() for p in model.fusion.parameters()) + sum(p.numel() for p in model.classifier.parameters())
    loader = DataLoader(test_ds, batch_size=1, shuffle=False, collate_fn=collate_multimodal_batch)
    model.eval()
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats()
        for i, b in enumerate(loader):
            if i >= 10:
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
        start = time.perf_counter()
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
        gpu_total = time.perf_counter() - start
        gpu_ms = (gpu_total / len(test_ds)) * 1000.0
        peak_vram_mb = torch.cuda.max_memory_allocated() / (1024 * 1024)
    else:
        gpu_ms = 0.0
        peak_vram_mb = 0.0
    cpu_device = torch.device("cpu")
    cpu_model = model.to(cpu_device)
    cpu_model.eval()
    for i, b in enumerate(loader):
        if i >= 5:
            break
        _ = cpu_model(
            b["node_features"].to(cpu_device),
            b["node_types"].to(cpu_device),
            b["edge_index"].to(cpu_device),
            b["edge_rel"].to(cpu_device),
            b["batch"].to(cpu_device),
            b["ast_tokens"].to(cpu_device),
            b["tab_features"].to(cpu_device),
        )
    start_cpu = time.perf_counter()
    with torch.no_grad():
        for b in loader:
            _ = cpu_model(
                b["node_features"].to(cpu_device),
                b["node_types"].to(cpu_device),
                b["edge_index"].to(cpu_device),
                b["edge_rel"].to(cpu_device),
                b["batch"].to(cpu_device),
                b["ast_tokens"].to(cpu_device),
                b["tab_features"].to(cpu_device),
            )
    cpu_total = time.perf_counter() - start_cpu
    cpu_ms = (cpu_total / len(test_ds)) * 1000.0
    return {
        "total_parameters": total_params,
        "graph_encoder_params": graph_params,
        "ast_encoder_params": ast_params,
        "tabular_encoder_params": tab_params,
        "fusion_and_head_params": fusion_params,
        "gpu_latency_ms_per_sample": round(gpu_ms, 3),
        "cpu_latency_ms_per_sample": round(cpu_ms, 3),
        "peak_vram_mb": round(peak_vram_mb, 2),
    }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Academic Evaluation on Device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")
    samples_by_split, tab_dim = load_dataset()
    print("\n=== 1. COMPONENT ABLATION STUDY ===")
    ablation_modes = [
        ("Tabular ResNet Only", "tab_only"),
        ("Hetero HGT Graph Only", "graph_only"),
        ("AST Transformer Only", "ast_only"),
        ("Tabular + AST (No Graph)", "tab_ast"),
        ("Tabular + HGT (No AST)", "tab_graph"),
        ("PDF-TransGraph Full (All 3 Fused)", "full"),
    ]
    ablation_results = {}
    for label, mode in ablation_modes:
        print(f"Training ablation configuration: {label} (mode={mode})...")
        m, _, _, _, _, _, _ = train_and_eval(samples_by_split, tab_dim, mode, seed=42, epochs=25, device=device)
        ablation_results[label] = m
        print(f"  -> Acc: {m['accuracy']:.4f} | Recall: {m['recall']:.4f} | F1: {m['f1']:.4f} | AUC: {m['roc_auc']:.4f}")
    print("\n=== 2. MULTI-SEED STATISTICAL SIGNIFICANCE (SEEDS 42, 100, 2026) ===")
    seeds = [42, 100, 2026]
    multi_seed_metrics = []
    final_model = None
    for s in seeds:
        print(f"Training Full PDF-TransGraph with Seed {s}...")
        m, tg, pr, pb, shas, sids, mdl = train_and_eval(samples_by_split, tab_dim, "full", seed=s, epochs=25, device=device)
        multi_seed_metrics.append(m)
        print(f"  Seed {s} -> Acc: {m['accuracy']:.4f} | Recall: {m['recall']:.4f} | F1: {m['f1']:.4f} | AUC: {m['roc_auc']:.4f}")
        if s == 42:
            test_targets_42 = tg
            test_preds_42 = pr
            test_probs_42 = pb
            test_shas_42 = shas
            test_sids_42 = sids
            final_model = mdl
    accs = [m["accuracy"] for m in multi_seed_metrics]
    recs = [m["recall"] for m in multi_seed_metrics]
    f1s = [m["f1"] for m in multi_seed_metrics]
    aucs = [m["roc_auc"] for m in multi_seed_metrics]
    stats_summary = {
        "accuracy_mean": float(np.mean(accs)),
        "accuracy_std": float(np.std(accs)),
        "recall_mean": float(np.mean(recs)),
        "recall_std": float(np.std(recs)),
        "f1_mean": float(np.mean(f1s)),
        "f1_std": float(np.std(f1s)),
        "roc_auc_mean": float(np.mean(aucs)),
        "roc_auc_std": float(np.std(aucs)),
    }
    print(f"\nStatistical Significance Across 3 Seeds:")
    print(f"  Accuracy: {stats_summary['accuracy_mean']*100:.2f}% +/- {stats_summary['accuracy_std']*100:.2f}%")
    print(f"  Recall:   {stats_summary['recall_mean']*100:.2f}% +/- {stats_summary['recall_std']*100:.2f}%")
    print(f"  F1-Score: {stats_summary['f1_mean']:.4f} +/- {stats_summary['f1_std']:.4f}")
    print(f"  ROC-AUC:  {stats_summary['roc_auc_mean']:.4f} +/- {stats_summary['roc_auc_std']:.4f}")
    print("\n=== 3. FAILURE CASE & ERROR ANALYSIS (SEED 42 TEST SET) ===")
    test_meta_map = {s["sha256"]: s["meta"] for s in samples_by_split["test"]}
    fn_samples = []
    fp_samples = []
    for true_y, pred_y, prob, sha, sid in zip(test_targets_42, test_preds_42, test_probs_42, test_shas_42, test_sids_42):
        meta = test_meta_map.get(sha, {})
        if true_y == 1 and pred_y == 0:
            fn_samples.append({
                "sample_id": sid,
                "sha256": sha,
                "predicted_prob": round(prob, 4),
                "status": meta.get("status"),
                "has_js": int(meta.get("JS", 0) > 0 or meta.get("Javascript", 0) > 0),
                "pdf_size": meta.get("PdfSize"),
                "streams": meta.get("Stream"),
                "xfa": meta.get("XFA"),
            })
        elif true_y == 0 and pred_y == 1:
            fp_samples.append({
                "sample_id": sid,
                "sha256": sha,
                "predicted_prob": round(prob, 4),
                "status": meta.get("status"),
                "has_js": int(meta.get("JS", 0) > 0 or meta.get("Javascript", 0) > 0),
                "pdf_size": meta.get("PdfSize"),
                "streams": meta.get("Stream"),
                "xfa": meta.get("XFA"),
            })
    print(f"Total False Negatives (Malware missed): {len(fn_samples)} / 160")
    print(f"Total False Positives (Benign flagged): {len(fp_samples)} / 131")
    fn_status_counts = {}
    for item in fn_samples:
        st = item["status"]
        fn_status_counts[st] = fn_status_counts.get(st, 0) + 1
    print("FN breakdown by parser status:", fn_status_counts)
    print("\n=== 4. COMPUTATIONAL LATENCY & COMPLEXITY BENCHMARK ===")
    test_ds = MultimodalPDFDataset(samples_by_split["test"])
    perf_stats = measure_latency_and_params(final_model, test_ds, tab_dim, device)
    print(f"Total Trainable Parameters: {perf_stats['total_parameters']:,}")
    print(f"  - Graph Encoder (HGT):    {perf_stats['graph_encoder_params']:,}")
    print(f"  - AST Encoder (RoPE):     {perf_stats['ast_encoder_params']:,}")
    print(f"  - Tabular ResNet:         {perf_stats['tabular_encoder_params']:,}")
    print(f"  - Fusion & Head:          {perf_stats['fusion_and_head_params']:,}")
    print(f"GPU Inference Latency:      {perf_stats['gpu_latency_ms_per_sample']} ms/sample")
    print(f"CPU Inference Latency:      {perf_stats['cpu_latency_ms_per_sample']} ms/sample")
    print(f"Peak GPU VRAM Allocated:    {perf_stats['peak_vram_mb']} MB")
    full_output = {
        "ablation_study": ablation_results,
        "multi_seed_significance": {
            "seeds": seeds,
            "individual_runs": multi_seed_metrics,
            "statistics": stats_summary,
        },
        "error_analysis": {
            "false_negatives_count": len(fn_samples),
            "false_positives_count": len(fp_samples),
            "false_negatives": fn_samples,
            "false_positives": fp_samples,
            "fn_by_status": fn_status_counts,
        },
        "complexity_and_latency": perf_stats,
    }
    with (REPORT_DIR / "academic_ablation_results.json").open("w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)
    print(f"\nSUCCESS: Academic Rigor Evaluation completed! Saved to {REPORT_DIR / 'academic_ablation_results.json'}")


if __name__ == "__main__":
    main()

