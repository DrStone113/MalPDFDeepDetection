import argparse
import json
import math
import os
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parents[2]
PARQUET_PATH = REPO / "data/processed/cic_full/cic_features_1452.parquet"
REPORT_DIR = REPO / "reports/experiments/cic_protocol_g_full"


class MLP(nn.Module):
    def __init__(self, in_features):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


def compute_metrics(y_true, y_pred, y_prob):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier": float(brier_score_loss(y_true, y_prob)),
    }


def prepare_data(include_evasion=True):
    df = pd.read_parquet(PARQUET_PATH)
    meta_cols = {"index", "sample_id", "pdf_sha256", "split", "duplicate_group_id", "Label", "status"}
    evasion_cols = {
        "evasive_timeout_anomaly",
        "flag_decompression_ratio_exceeded",
        "is_truncated_stream",
        "flag_spec_violation_flood",
        "flag_excessive_object_graph",
        "flag_ast_complexity_truncated",
    }
    feature_cols = [c for c in df.columns if c not in meta_cols]
    if not include_evasion:
        feature_cols = [c for c in feature_cols if c not in evasion_cols]
    train_mask = df["split"] == "train"
    val_mask = df["split"] == "validation"
    test_mask = df["split"] == "test"
    x_train_raw = df.loc[train_mask, feature_cols].values
    train_stds = np.nanstd(x_train_raw, axis=0)
    valid_feat_idx = [i for i, std in enumerate(train_stds) if not np.isnan(std) and std > 1e-8]
    selected_cols = [feature_cols[i] for i in valid_feat_idx]
    train_medians = df.loc[train_mask, selected_cols].median()
    df_imputed = df[selected_cols].fillna(train_medians).fillna(0.0)
    x_train = df_imputed.loc[train_mask].values.astype(np.float32)
    x_val = df_imputed.loc[val_mask].values.astype(np.float32)
    x_test = df_imputed.loc[test_mask].values.astype(np.float32)
    y_train = df.loc[train_mask, "Label"].values.astype(int)
    y_val = df.loc[val_mask, "Label"].values.astype(int)
    y_test = df.loc[test_mask, "Label"].values.astype(int)
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_val_scaled = scaler.transform(x_val)
    x_test_scaled = scaler.transform(x_test)
    return {
        "cols": selected_cols,
        "x_train": x_train,
        "x_val": x_val,
        "x_test": x_test,
        "x_train_scaled": x_train_scaled,
        "x_val_scaled": x_val_scaled,
        "x_test_scaled": x_test_scaled,
        "y_train": y_train,
        "y_val": y_val,
        "y_test": y_test,
    }


def train_xgboost(data):
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
    )
    clf.fit(data["x_train"], data["y_train"])
    val_prob = clf.predict_proba(data["x_val"])[:, 1]
    val_pred = (val_prob >= 0.5).astype(int)
    test_prob = clf.predict_proba(data["x_test"])[:, 1]
    test_pred = (test_prob >= 0.5).astype(int)
    val_metrics = compute_metrics(data["y_val"], val_pred, val_prob)
    test_metrics = compute_metrics(data["y_test"], test_pred, test_prob)
    importances = dict(zip(data["cols"], clf.feature_importances_.tolist()))
    top_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True)[:20])
    return {"val": val_metrics, "test": test_metrics, "top_features": top_importances}


def train_random_forest(data):
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(data["x_train"], data["y_train"])
    val_prob = clf.predict_proba(data["x_val"])[:, 1]
    val_pred = (val_prob >= 0.5).astype(int)
    test_prob = clf.predict_proba(data["x_test"])[:, 1]
    test_pred = (test_prob >= 0.5).astype(int)
    val_metrics = compute_metrics(data["y_val"], val_pred, val_prob)
    test_metrics = compute_metrics(data["y_test"], test_pred, test_prob)
    importances = dict(zip(data["cols"], clf.feature_importances_.tolist()))
    top_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True)[:20])
    return {"val": val_metrics, "test": test_metrics, "top_features": top_importances}


def train_pytorch_mlp(data):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(42)
    in_features = data["x_train_scaled"].shape[1]
    model = MLP(in_features).to(device)
    criterion = nn.BCELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    x_tr = torch.tensor(data["x_train_scaled"], dtype=torch.float32, device=device)
    y_tr = torch.tensor(data["y_train"], dtype=torch.float32, device=device).unsqueeze(1)
    x_va = torch.tensor(data["x_val_scaled"], dtype=torch.float32, device=device)
    y_va = torch.tensor(data["y_val"], dtype=torch.float32, device=device).unsqueeze(1)
    x_te = torch.tensor(data["x_test_scaled"], dtype=torch.float32, device=device)
    dataset = torch.utils.data.TensorDataset(x_tr, y_tr)
    loader = torch.utils.data.DataLoader(dataset, batch_size=32, shuffle=True)
    best_loss = float("inf")
    best_weights = None
    for epoch in range(40):
        model.train()
        for batch_x, batch_y in loader:
            optimizer.zero_grad()
            out = model(batch_x)
            loss = criterion(out, batch_y)
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            val_out = model(x_va)
            val_loss = criterion(val_out, y_va).item()
            if val_loss < best_loss:
                best_loss = val_loss
                best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
    if best_weights is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    model.eval()
    with torch.no_grad():
        val_prob = model(x_va).squeeze().cpu().numpy()
        val_pred = (val_prob >= 0.5).astype(int)
        test_prob = model(x_te).squeeze().cpu().numpy()
        test_pred = (test_prob >= 0.5).astype(int)
    val_metrics = compute_metrics(data["y_val"], val_pred, val_prob)
    test_metrics = compute_metrics(data["y_test"], test_pred, test_prob)
    return {"val": val_metrics, "test": test_metrics, "device": str(device)}


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    full_data = prepare_data(include_evasion=True)
    xgb_full = train_xgboost(full_data)
    rf_full = train_random_forest(full_data)
    mlp_full = train_pytorch_mlp(full_data)
    ablation_data = prepare_data(include_evasion=False)
    xgb_ablation = train_xgboost(ablation_data)
    rf_ablation = train_random_forest(ablation_data)
    results = {
        "dataset": "CIC Evasive-PDFMal2022 (1,452 samples)",
        "protocol": "Protocol G deterministic split (seed 42)",
        "splits": {"train": 870, "validation": 291, "test": 291},
        "models": {
            "xgboost_full": xgb_full,
            "random_forest_full": rf_full,
            "pytorch_mlp_full": mlp_full,
            "xgboost_without_evasion_flags": xgb_ablation,
            "random_forest_without_evasion_flags": rf_ablation,
        },
    }
    with (REPORT_DIR / "benchmark_results.json").open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    print("SUCCESS: Full Protocol G benchmark completed!")
    print("\n=== VALIDATION METRICS (WITH EVASION FLAGS) ===")
    for mname, mres in [("XGBoost", xgb_full), ("Random Forest", rf_full), ("PyTorch MLP", mlp_full)]:
        vm = mres["val"]
        print(f"{mname:15s} | F1: {vm['f1']:.4f} | Acc: {vm['accuracy']:.4f} | MCC: {vm['mcc']:.4f} | AUC: {vm['roc_auc']:.4f} | Brier: {vm['brier']:.4f}")
    print("\n=== TEST METRICS (WITH EVASION FLAGS) ===")
    for mname, mres in [("XGBoost", xgb_full), ("Random Forest", rf_full), ("PyTorch MLP", mlp_full)]:
        tm = mres["test"]
        print(f"{mname:15s} | F1: {tm['f1']:.4f} | Acc: {tm['accuracy']:.4f} | MCC: {tm['mcc']:.4f} | AUC: {tm['roc_auc']:.4f} | Brier: {tm['brier']:.4f}")
    print("\n=== ABLATION STUDY: IMPACT OF EVASION FLAGS ON TEST SET ===")
    print(f"XGBoost F1 with evasion:    {xgb_full['test']['f1']:.4f} vs without: {xgb_ablation['test']['f1']:.4f} (Delta: {xgb_full['test']['f1'] - xgb_ablation['test']['f1']:+.4f})")
    print(f"Random Forest F1 with evasion: {rf_full['test']['f1']:.4f} vs without: {rf_ablation['test']['f1']:.4f} (Delta: {rf_full['test']['f1'] - rf_ablation['test']['f1']:+.4f})")


if __name__ == "__main__":
    main()

