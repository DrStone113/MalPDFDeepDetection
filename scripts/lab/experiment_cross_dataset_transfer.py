import json
from pathlib import Path
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
from torch.utils.data import DataLoader, TensorDataset

from malpdf.data.cross_dataset_loader import load_aligned_datasets

REPO = Path(__file__).resolve().parents[2]
REPORT_DIR = REPO / "reports/experiments/cross_dataset_rit_cic"


class TabularMLP(nn.Module):
    def __init__(self, in_features: int, hidden_dim: int = 128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


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


def train_pytorch_mlp(x_train, y_train, x_val, y_val, in_features, epochs=25, seed=42, device="cpu"):
    torch.manual_seed(seed)
    np.random.seed(seed)
    model = TabularMLP(in_features=in_features).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = nn.BCEWithLogitsLoss()

    ds = TensorDataset(torch.tensor(x_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.float32))
    loader = DataLoader(ds, batch_size=64, shuffle=True)

    best_val_f1 = -1.0
    best_weights = None

    for _ in range(epochs):
        model.train()
        for bx, by in loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_x_t = torch.tensor(x_val, dtype=torch.float32).to(device)
            val_logits = model(val_x_t)
            val_probs = torch.sigmoid(val_logits).cpu().numpy()
            val_preds = (val_probs >= 0.5).astype(int)
            val_f1 = f1_score(y_val, val_preds, zero_division=0)
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    if best_weights is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    return model


def predict_pytorch_mlp(model, x, device="cpu"):
    model.eval()
    with torch.no_grad():
        xt = torch.tensor(x, dtype=torch.float32).to(device)
        logits = model(xt)
        probs = torch.sigmoid(logits).cpu().numpy()
        preds = (probs >= 0.5).astype(int)
    return preds, probs


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Running Bidirectional Transfer on device: {device}")

    rit_df, cic_df = load_aligned_datasets(REPO, include_ratios=True)
    feature_cols = [c for c in rit_df.columns if c not in {"label", "split"}]

    rit_train_mask = rit_df["split"] == "train"
    rit_test_mask = rit_df["split"] == "test"

    cic_train_mask = cic_df["split"] == "train"
    cic_val_mask = cic_df["split"] == "validation"
    cic_test_mask = cic_df["split"] == "test"

    scaler_rit = StandardScaler()
    x_rit_train = scaler_rit.fit_transform(rit_df.loc[rit_train_mask, feature_cols].values)
    x_rit_test = scaler_rit.transform(rit_df.loc[rit_test_mask, feature_cols].values)
    x_rit_all = scaler_rit.transform(rit_df[feature_cols].values)
    y_rit_train = rit_df.loc[rit_train_mask, "label"].values
    y_rit_test = rit_df.loc[rit_test_mask, "label"].values
    y_rit_all = rit_df["label"].values

    x_cic_test_for_rit = scaler_rit.transform(cic_df.loc[cic_test_mask, feature_cols].values)
    y_cic_test = cic_df.loc[cic_test_mask, "label"].values

    scaler_cic = StandardScaler()
    x_cic_train = scaler_cic.fit_transform(cic_df.loc[cic_train_mask, feature_cols].values)
    x_cic_val = scaler_cic.transform(cic_df.loc[cic_val_mask, feature_cols].values)
    x_cic_test = scaler_cic.transform(cic_df.loc[cic_test_mask, feature_cols].values)
    y_cic_train = cic_df.loc[cic_train_mask, "label"].values
    y_cic_val = cic_df.loc[cic_val_mask, "label"].values

    x_rit_test_for_cic = scaler_cic.transform(rit_df.loc[rit_test_mask, feature_cols].values)
    x_rit_all_for_cic = scaler_cic.transform(rit_df[feature_cols].values)

    print("\n--- 1. Training RIT-Conventional Models ---")
    rf_rit = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_rit.fit(x_rit_train, y_rit_train)

    rf_rit_indomain_probs = rf_rit.predict_proba(x_rit_test)[:, 1]
    rf_rit_indomain_preds = (rf_rit_indomain_probs >= 0.5).astype(int)
    m_rf_rit_indomain = compute_metrics(y_rit_test, rf_rit_indomain_preds, rf_rit_indomain_probs)
    print(f"RIT In-Domain (Test): Acc {m_rf_rit_indomain['accuracy']*100:.2f}% | Recall {m_rf_rit_indomain['recall']*100:.2f}% | F1 {m_rf_rit_indomain['f1']:.4f}")

    rf_rit_cic_probs = rf_rit.predict_proba(x_cic_test_for_rit)[:, 1]
    rf_rit_cic_preds = (rf_rit_cic_probs >= 0.5).astype(int)
    m_rf_rit_to_cic = compute_metrics(y_cic_test, rf_rit_cic_preds, rf_rit_cic_probs)
    print(f"RIT -> CIC-Evasive (COLLAPSE TRAP): Acc {m_rf_rit_to_cic['accuracy']*100:.2f}% | Recall {m_rf_rit_to_cic['recall']*100:.2f}% | F1 {m_rf_rit_to_cic['f1']:.4f}")

    mlp_rit = train_pytorch_mlp(x_rit_train, y_rit_train, x_rit_test, y_rit_test, in_features=len(feature_cols), epochs=20, device=device)
    mlp_rit_indomain_preds, mlp_rit_indomain_probs = predict_pytorch_mlp(mlp_rit, x_rit_test, device=device)
    m_mlp_rit_indomain = compute_metrics(y_rit_test, mlp_rit_indomain_preds, mlp_rit_indomain_probs)

    mlp_rit_cic_preds, mlp_rit_cic_probs = predict_pytorch_mlp(mlp_rit, x_cic_test_for_rit, device=device)
    m_mlp_rit_to_cic = compute_metrics(y_cic_test, mlp_rit_cic_preds, mlp_rit_cic_probs)
    print(f"RIT MLP -> CIC-Evasive (COLLAPSE TRAP): Acc {m_mlp_rit_to_cic['accuracy']*100:.2f}% | Recall {m_mlp_rit_to_cic['recall']*100:.2f}% | F1 {m_mlp_rit_to_cic['f1']:.4f}")

    print("\n--- 2. Training CIC-Evasive Hardened Models ---")
    rf_cic = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    rf_cic.fit(x_cic_train, y_cic_train)

    rf_cic_indomain_probs = rf_cic.predict_proba(x_cic_test)[:, 1]
    rf_cic_indomain_preds = (rf_cic_indomain_probs >= 0.5).astype(int)
    m_rf_cic_indomain = compute_metrics(y_cic_test, rf_cic_indomain_preds, rf_cic_indomain_probs)
    print(f"CIC In-Domain (Test): Acc {m_rf_cic_indomain['accuracy']*100:.2f}% | Recall {m_rf_cic_indomain['recall']*100:.2f}% | F1 {m_rf_cic_indomain['f1']:.4f}")

    rf_cic_rit_probs = rf_cic.predict_proba(x_rit_all_for_cic)[:, 1]
    rf_cic_rit_preds = (rf_cic_rit_probs >= 0.5).astype(int)
    m_rf_cic_to_rit = compute_metrics(y_rit_all, rf_cic_rit_preds, rf_cic_rit_probs)
    print(f"CIC -> RIT All 24,337 samples: Acc {m_rf_cic_to_rit['accuracy']*100:.2f}% | Recall {m_rf_cic_to_rit['recall']*100:.2f}% | F1 {m_rf_cic_to_rit['f1']:.4f}")

    mlp_cic = train_pytorch_mlp(x_cic_train, y_cic_train, x_cic_val, y_cic_val, in_features=len(feature_cols), epochs=30, device=device)
    mlp_cic_indomain_preds, mlp_cic_indomain_probs = predict_pytorch_mlp(mlp_cic, x_cic_test, device=device)
    m_mlp_cic_indomain = compute_metrics(y_cic_test, mlp_cic_indomain_preds, mlp_cic_indomain_probs)

    mlp_cic_rit_preds, mlp_cic_rit_probs = predict_pytorch_mlp(mlp_cic, x_rit_all_for_cic, device=device)
    m_mlp_cic_to_rit = compute_metrics(y_rit_all, mlp_cic_rit_preds, mlp_cic_rit_probs)
    print(f"CIC MLP -> RIT All 24,337 samples: Acc {m_mlp_cic_to_rit['accuracy']*100:.2f}% | Recall {m_mlp_cic_to_rit['recall']*100:.2f}% | F1 {m_mlp_cic_to_rit['f1']:.4f}")

    print("\n--- 3. De-biasing Study: Excluding StartXref & Xref ---")
    rit_df_noxref, cic_df_noxref = load_aligned_datasets(REPO, include_ratios=True, exclude_startxref=True)
    noxref_cols = [c for c in rit_df_noxref.columns if c not in {"label", "split"}]

    scaler_cic_noxref = StandardScaler()
    x_cic_train_noxref = scaler_cic_noxref.fit_transform(cic_df_noxref.loc[cic_train_mask, noxref_cols].values)
    x_cic_val_noxref = scaler_cic_noxref.transform(cic_df_noxref.loc[cic_val_mask, noxref_cols].values)
    x_cic_test_noxref = scaler_cic_noxref.transform(cic_df_noxref.loc[cic_test_mask, noxref_cols].values)
    x_rit_all_noxref = scaler_cic_noxref.transform(rit_df_noxref[noxref_cols].values)

    mlp_cic_noxref = train_pytorch_mlp(x_cic_train_noxref, y_cic_train, x_cic_val_noxref, y_cic_val, in_features=len(noxref_cols), epochs=30, device=device)
    mlp_noxref_indomain_preds, mlp_noxref_indomain_probs = predict_pytorch_mlp(mlp_cic_noxref, x_cic_test_noxref, device=device)
    m_mlp_noxref_indomain = compute_metrics(y_cic_test, mlp_noxref_indomain_preds, mlp_noxref_indomain_probs)

    mlp_noxref_rit_preds, mlp_noxref_rit_probs = predict_pytorch_mlp(mlp_cic_noxref, x_rit_all_noxref, device=device)
    m_mlp_noxref_to_rit = compute_metrics(y_rit_all, mlp_noxref_rit_preds, mlp_noxref_rit_probs)
    print(f"CIC MLP (No StartXref) -> RIT: Acc {m_mlp_noxref_to_rit['accuracy']*100:.2f}% | Recall {m_mlp_noxref_to_rit['recall']*100:.2f}% | F1 {m_mlp_noxref_to_rit['f1']:.4f}")

    results = {
        "direction_A_RIT_to_CIC": {
            "random_forest": {
                "in_domain_rit_test": m_rf_rit_indomain,
                "zero_shot_cic_test": m_rf_rit_to_cic,
            },
            "tabular_mlp": {
                "in_domain_rit_test": m_mlp_rit_indomain,
                "zero_shot_cic_test": m_mlp_rit_to_cic,
            },
        },
        "direction_B_CIC_to_RIT": {
            "random_forest": {
                "in_domain_cic_test": m_rf_cic_indomain,
                "zero_shot_rit_all": m_rf_cic_to_rit,
            },
            "tabular_mlp_standard": {
                "in_domain_cic_test": m_mlp_cic_indomain,
                "zero_shot_rit_all": m_mlp_cic_to_rit,
            },
            "tabular_mlp_no_startxref": {
                "in_domain_cic_test": m_mlp_noxref_indomain,
                "zero_shot_rit_all": m_mlp_noxref_to_rit,
            },
        },
    }

    with (REPORT_DIR / "bidirectional_transfer_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved Bidirectional Transfer Results to: {REPORT_DIR / 'bidirectional_transfer_results.json'}")


if __name__ == "__main__":
    main()

