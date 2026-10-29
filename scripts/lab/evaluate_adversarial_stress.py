import copy
import gzip
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from malpdf.models.adversarial_simulator import create_adversarial_sample
from malpdf.models.adversarial_trainer import AdversarialRobustLoss
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph

REPO = Path(__file__).resolve().parents[2]
GRAPHS_PATH = REPO / "data/processed/cic_full/hetero_cic_graphs.json.gz"
PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
REPORT_DIR = REPO / "reports/experiments/adversarial_defense"
FIGURES_DIR = REPO / "reports/figures"


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


def train_transgraph(samples_by_split, tab_dim, adversarial: bool, epochs: int, device: torch.device):
    torch.manual_seed(42)
    np.random.seed(42)
    train_samples = samples_by_split["train"]
    val_ds = MultimodalPDFDataset(samples_by_split["validation"])
    val_loader = DataLoader(val_ds, batch_size=64, shuffle=False, collate_fn=collate_multimodal_batch)

    model = PDFTransGraph(
        node_in_dim=19,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=tab_dim,
        hidden_dim=128,
        ablation_mode="full",
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    focal_criterion = FocalLoss(alpha=0.6, gamma=2.0)
    adv_criterion = AdversarialRobustLoss(alpha=0.5, beta=1.0)

    best_val_f1 = -1.0
    best_weights = None

    for epoch in range(1, epochs + 1):
        model.train()
        np.random.shuffle(train_samples)
        batch_size = 32
        for start_idx in range(0, len(train_samples), batch_size):
            raw_batch = train_samples[start_idx : start_idx + batch_size]
            batch_clean = collate_multimodal_batch(raw_batch)

            optimizer.zero_grad()
            nf = batch_clean["node_features"].to(device)
            nt = batch_clean["node_types"].to(device)
            ei = batch_clean["edge_index"].to(device)
            er = batch_clean["edge_rel"].to(device)
            b = batch_clean["batch"].to(device)
            tok = batch_clean["ast_tokens"].to(device)
            tab = batch_clean["tab_features"].to(device)
            y = batch_clean["labels"].to(device)

            logits_clean, _ = model(nf, nt, ei, er, b, tok, tab)

            if adversarial:
                adv_raw_batch = [create_adversarial_sample(s, attack_type="combined", num_orphans=25) for s in raw_batch]
                batch_adv = collate_multimodal_batch(adv_raw_batch)
                nf_a = batch_adv["node_features"].to(device)
                nt_a = batch_adv["node_types"].to(device)
                ei_a = batch_adv["edge_index"].to(device)
                er_a = batch_adv["edge_rel"].to(device)
                b_a = batch_adv["batch"].to(device)
                tok_a = batch_adv["ast_tokens"].to(device)
                tab_a = batch_adv["tab_features"].to(device)
                logits_adv, _ = model(nf_a, nt_a, ei_a, er_a, b_a, tok_a, tab_a)
                loss = adv_criterion(logits_clean, logits_adv, y)
            else:
                loss = focal_criterion(logits_clean, y)

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
                logits, _ = model(nf, nt, ei, er, b, tok, tab)
                probs = torch.sigmoid(logits)
                preds = (probs >= 0.5).long()
                val_probs.extend(probs.cpu().tolist())
                val_preds.extend(preds.cpu().tolist())
                val_targets.extend(batch["labels"].tolist())
        v_metrics = compute_metrics(val_targets, val_preds, val_probs)
        if v_metrics["f1"] > best_val_f1:
            best_val_f1 = v_metrics["f1"]
            best_weights = {k: v.cpu() for k, v in model.state_dict().items()}

    if best_weights is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    return model


def evaluate_transgraph_on_samples(model, samples: list[dict], device: torch.device):
    model.eval()
    ds = MultimodalPDFDataset(samples)
    loader = DataLoader(ds, batch_size=64, shuffle=False, collate_fn=collate_multimodal_batch)
    probs_list, preds_list, targets_list = [], [], []
    with torch.no_grad():
        for batch in loader:
            nf = batch["node_features"].to(device)
            nt = batch["node_types"].to(device)
            ei = batch["edge_index"].to(device)
            er = batch["edge_rel"].to(device)
            b = batch["batch"].to(device)
            tok = batch["ast_tokens"].to(device)
            tab = batch["tab_features"].to(device)
            logits, _ = model(nf, nt, ei, er, b, tok, tab)
            probs = torch.sigmoid(logits)
            preds = (probs >= 0.5).long()
            probs_list.extend(probs.cpu().tolist())
            preds_list.extend(preds.cpu().tolist())
            targets_list.extend(batch["labels"].tolist())
    return compute_metrics(targets_list, preds_list, probs_list)


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Running Adversarial Stress Testing on: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")

    samples_by_split, tab_dim = load_dataset()
    clean_test_samples = samples_by_split["test"]
    clean_train_samples = samples_by_split["train"]

    print("\nPre-generating 3 Adversarial Test Sets...")
    adv_orphan_test = [create_adversarial_sample(s, attack_type="orphan_only", num_orphans=30) for s in clean_test_samples]
    adv_ast_test = [create_adversarial_sample(s, attack_type="ast_only") for s in clean_test_samples]
    adv_combined_test = [create_adversarial_sample(s, attack_type="combined", num_orphans=30) for s in clean_test_samples]

    test_scenarios = {
        "Clean Test": clean_test_samples,
        "Orphan Injection": adv_orphan_test,
        "AST Obfuscation": adv_ast_test,
        "Combined Multi-Vector": adv_combined_test,
    }

    print("\n--- 1. Training Baseline Random Forest & Tabular Models ---")
    x_train_tab = np.stack([s["tab_features"].numpy() for s in clean_train_samples])
    y_train = np.array([s["label"] for s in clean_train_samples])

    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(x_train_tab, y_train)

    rf_results = {}
    for sc_name, sc_samples in test_scenarios.items():
        x_te = np.stack([s["tab_features"].numpy() for s in sc_samples])
        y_te = np.array([s["label"] for s in sc_samples])
        probs = rf.predict_proba(x_te)[:, 1]
        preds = (probs >= 0.5).astype(int)
        m = compute_metrics(y_te, preds, probs)
        rf_results[sc_name] = m
        print(f"Random Forest [{sc_name}]: Acc {m['accuracy']*100:.2f}% | Recall {m['recall']*100:.2f}% | F1 {m['f1']:.4f}")

    print("\n--- 2. Training Tabular ResNet (Clean) ---")
    model_tab = PDFTransGraph(
        node_in_dim=19,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=tab_dim,
        hidden_dim=128,
        ablation_mode="tab_only",
    ).to(device)
    optimizer_tab = torch.optim.AdamW(model_tab.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion_tab = FocalLoss(alpha=0.6, gamma=2.0)
    train_loader_tab = DataLoader(MultimodalPDFDataset(clean_train_samples), batch_size=32, shuffle=True, collate_fn=collate_multimodal_batch)

    for epoch in range(1, 26):
        model_tab.train()
        for b in train_loader_tab:
            optimizer_tab.zero_grad()
            logits, _ = model_tab(
                b["node_features"].to(device),
                b["node_types"].to(device),
                b["edge_index"].to(device),
                b["edge_rel"].to(device),
                b["batch"].to(device),
                b["ast_tokens"].to(device),
                b["tab_features"].to(device),
            )
            loss = criterion_tab(logits, b["labels"].to(device))
            loss.backward()
            optimizer_tab.step()

    tab_results = {}
    for sc_name, sc_samples in test_scenarios.items():
        m = evaluate_transgraph_on_samples(model_tab, sc_samples, device)
        tab_results[sc_name] = m
        print(f"Tabular ResNet [{sc_name}]: Acc {m['accuracy']*100:.2f}% | Recall {m['recall']*100:.2f}% | F1 {m['f1']:.4f}")

    print("\n--- 3. Training PDF-TransGraph Standard (Clean) ---")
    model_clean = train_transgraph(samples_by_split, tab_dim, adversarial=False, epochs=25, device=device)
    clean_results = {}
    for sc_name, sc_samples in test_scenarios.items():
        m = evaluate_transgraph_on_samples(model_clean, sc_samples, device)
        clean_results[sc_name] = m
        print(f"PDF-TransGraph Standard [{sc_name}]: Acc {m['accuracy']*100:.2f}% | Recall {m['recall']*100:.2f}% | F1 {m['f1']:.4f}")

    print("\n--- 4. Training PDF-TransGraph Adversarially-Trained (Robust Defense) ---")
    model_adv = train_transgraph(samples_by_split, tab_dim, adversarial=True, epochs=25, device=device)
    adv_results = {}
    for sc_name, sc_samples in test_scenarios.items():
        m = evaluate_transgraph_on_samples(model_adv, sc_samples, device)
        adv_results[sc_name] = m
        print(f"PDF-TransGraph Robust (Adv-Trained) [{sc_name}]: Acc {m['accuracy']*100:.2f}% | Recall {m['recall']*100:.2f}% | F1 {m['f1']:.4f}")

    torch.save(model_adv.state_dict(), REPORT_DIR / "pdf_transgraph_adv_trained.pt")
    print(f"Saved robust model weights to: {REPORT_DIR / 'pdf_transgraph_adv_trained.pt'}")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    scenarios = list(test_scenarios.keys())

    rf_accs = [rf_results[s]["accuracy"] * 100 for s in scenarios]
    tab_accs = [tab_results[s]["accuracy"] * 100 for s in scenarios]
    clean_accs = [clean_results[s]["accuracy"] * 100 for s in scenarios]
    adv_accs = [adv_results[s]["accuracy"] * 100 for s in scenarios]

    x = np.arange(len(scenarios))
    w = 0.2

    ax1.bar(x - 1.5 * w, rf_accs, width=w, label="Random Forest Baseline", color="#d62728", alpha=0.85)
    ax1.bar(x - 0.5 * w, tab_accs, width=w, label="Tabular ResNet (Clean)", color="#ff7f0e", alpha=0.85)
    ax1.bar(x + 0.5 * w, clean_accs, width=w, label="PDF-TransGraph (Standard)", color="#1f77b4", alpha=0.85)
    ax1.bar(x + 1.5 * w, adv_accs, width=w, label="PDF-TransGraph (Adv-Trained)", color="#2ca02c", alpha=0.85)

    ax1.set_title("Test Accuracy Decay Across Adversarial Attack Scenarios", fontsize=12, fontweight="bold")
    ax1.set_ylabel("Accuracy (%)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(scenarios, rotation=15)
    ax1.set_ylim(60, 100)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="lower left")

    rf_rec = [rf_results[s]["recall"] * 100 for s in scenarios]
    tab_rec = [tab_results[s]["recall"] * 100 for s in scenarios]
    clean_rec = [clean_results[s]["recall"] * 100 for s in scenarios]
    adv_rec = [adv_results[s]["recall"] * 100 for s in scenarios]

    ax2.plot(scenarios, rf_rec, marker="o", linewidth=2.5, label="Random Forest Baseline", color="#d62728")
    ax2.plot(scenarios, tab_rec, marker="s", linewidth=2.5, label="Tabular ResNet (Clean)", color="#ff7f0e")
    ax2.plot(scenarios, clean_rec, marker="^", linewidth=2.5, label="PDF-TransGraph (Standard)", color="#1f77b4")
    ax2.plot(scenarios, adv_rec, marker="D", linewidth=3.0, label="PDF-TransGraph (Adv-Trained)", color="#2ca02c")

    ax2.set_title("Malware Recall Resilience (Malware Evasion Rate)", fontsize=12, fontweight="bold")
    ax2.set_ylabel("Malware Recall (%)")
    ax2.set_xticks(range(len(scenarios)))
    ax2.set_xticklabels(scenarios, rotation=15)
    ax2.set_ylim(50, 105)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(loc="lower left")

    fig_path = FIGURES_DIR / "adversarial_decay_curves.png"
    plt.tight_layout()
    plt.savefig(fig_path, dpi=300, bbox_inches="tight")
    plt.close()

    summary_output = {
        "models": {
            "random_forest_baseline": rf_results,
            "tabular_resnet_clean": tab_results,
            "pdf_transgraph_standard": clean_results,
            "pdf_transgraph_adv_trained": adv_results,
        },
        "figure_path": str(fig_path),
    }

    with (REPORT_DIR / "adversarial_results.json").open("w", encoding="utf-8") as f:
        json.dump(summary_output, f, indent=2)

    print(f"\nSUCCESS: Adversarial Stress Testing completed! Results saved to {REPORT_DIR / 'adversarial_results.json'}")
    print(f"Decay curves plot saved to: {fig_path}")


if __name__ == "__main__":
    main()
