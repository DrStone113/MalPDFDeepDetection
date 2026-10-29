import gzip
import json
from pathlib import Path
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
    with gzip.open(GRAPHS_PATH, "rt", encoding="utf-8") as stream:
        raw_graphs = json.load(stream)
    graph_dict = {g["sha256"]: g for g in raw_graphs}
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
        g = graph_dict.get(sha)
        if g is not None and g["num_nodes"] > 0:
            nf = torch.tensor(g["node_features"], dtype=torch.float32)
            nt = torch.tensor(g["node_types"], dtype=torch.long)
            e_src = torch.tensor(g["edge_src"], dtype=torch.long)
            e_dst = torch.tensor(g["edge_dst"], dtype=torch.long)
            e_rel = torch.tensor(g["edge_rel"], dtype=torch.long)
        else:
            nf = torch.zeros((1, 19), dtype=torch.float32)
            nt = torch.tensor([8], dtype=torch.long)
            e_src = torch.zeros((0,), dtype=torch.long)
            e_dst = torch.zeros((0,), dtype=torch.long)
            e_rel = torch.zeros((0,), dtype=torch.long)
        samples_by_split[split].append(
            {
                "sha256": sha,
                "node_features": nf,
                "node_types": nt,
                "edge_src": e_src,
                "edge_dst": e_dst,
                "edge_rel": e_rel,
                "ast_tokens": ast_tokens,
                "tab_features": tab_feat,
                "label": label,
            }
        )
    return samples_by_split, len(tab_cols)


def evaluate(model, loader, device):
    model.eval()
    all_preds = []
    all_probs = []
    all_targets = []
    with torch.no_grad():
        for batch in loader:
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
            all_probs.extend(probs.cpu().tolist())
            all_preds.extend(preds.cpu().tolist())
            all_targets.extend(y.cpu().tolist())
    return compute_metrics(all_targets, all_preds, all_probs)


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")
    samples_by_split, tab_dim = load_dataset()
    train_ds = MultimodalPDFDataset(samples_by_split["train"])
    val_ds = MultimodalPDFDataset(samples_by_split["validation"])
    test_ds = MultimodalPDFDataset(samples_by_split["test"])
    print(f"Dataset splits: Train={len(train_ds)}, Val={len(val_ds)}, Test={len(test_ds)}")
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
    ).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    epochs = 25
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = FocalLoss(alpha=0.6, gamma=2.0)
    best_val_f1 = 0.0
    best_checkpoint = None
    print(f"Starting training PDF-TransGraph for {epochs} epochs...")
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
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
            total_loss += loss.item() * len(y)
        scheduler.step()
        val_metrics = evaluate(model, val_loader, device)
        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_checkpoint = {k: v.cpu() for k, v in model.state_dict().items()}
        if epoch % 5 == 0 or epoch == epochs:
            avg_loss = total_loss / len(train_ds)
            print(f"Epoch {epoch:02d}/{epochs:02d} | Loss: {avg_loss:.4f} | Val Acc: {val_metrics['accuracy']:.4f} | Val F1: {val_metrics['f1']:.4f} | Val AUC: {val_metrics['roc_auc']:.4f}")
    if best_checkpoint is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_checkpoint.items()})
    val_final = evaluate(model, val_loader, device)
    test_final = evaluate(model, test_loader, device)
    torch.save(best_checkpoint, REPORT_DIR / "pdf_transgraph_best.pt")
    results = {
        "architecture": "PDF-TransGraph (Heterogeneous HGT + AST Transformer + Tabular ResNet)",
        "protocol": "Protocol G (seed 42: 870 Train / 291 Val / 291 Test)",
        "hardware": "NVIDIA GeForce RTX 5060 Ti (CUDA 12.8)",
        "validation_metrics": val_final,
        "test_metrics": test_final,
    }
    with (REPORT_DIR / "transgraph_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nSUCCESS: PDF-TransGraph evaluation completed!")
    print(f"Validation Set | Acc: {val_final['accuracy']:.4f} | Recall: {val_final['recall']:.4f} | F1: {val_final['f1']:.4f} | AUC: {val_final['roc_auc']:.4f}")
    cm = test_final["confusion_matrix"]
    print(f"Test Set (Held-out) | Acc: {test_final['accuracy']:.4f} | Recall: {test_final['recall']:.4f} | F1: {test_final['f1']:.4f} | AUC: {test_final['roc_auc']:.4f}")
    print(f"Test Confusion Matrix: TN={cm['tn']}, FP={cm['fp']}, FN={cm['fn']}, TP={cm['tp']} (Caught {cm['tp']}/160 malware!)")


if __name__ == "__main__":
    main()
