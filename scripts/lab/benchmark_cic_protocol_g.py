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
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parents[2]
PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
REPORT_DIR = REPO / "reports/experiments/cic_protocol_g_full"


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


def load_fused_data():
    df_ours = pd.read_parquet(PARQUET_OURS)
    df_cic = pd.read_parquet(PARQUET_CIC)
    merged = pd.merge(df_ours, df_cic, left_on="pdf_sha256", right_on="FileName", how="inner", suffixes=("_ours", "_cic"))
    cic_cols = [c for c in df_cic.columns if c not in {"FileName", "Class"}]
    for c in cic_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").fillna(-1.0)
    evasion_cols = [
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
    for c in evasion_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").fillna(0.0)
    combined_cols = cic_cols + evasion_cols
    train_mask = merged["split"] == "train"
    val_mask = merged["split"] == "validation"
    test_mask = merged["split"] == "test"
    return {
        "df": merged,
        "combined_cols": combined_cols,
        "cic_cols": cic_cols,
        "evasion_cols": evasion_cols,
        "train_mask": train_mask,
        "val_mask": val_mask,
        "test_mask": test_mask,
        "y_train": merged.loc[train_mask, "Label"].values.astype(int),
        "y_val": merged.loc[val_mask, "Label"].values.astype(int),
        "y_test": merged.loc[test_mask, "Label"].values.astype(int),
    }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    data = load_fused_data()
    m = data["df"]
    tr, va, te = data["train_mask"], data["val_mask"], data["test_mask"]
    y_tr, y_va, y_te = data["y_train"], data["y_val"], data["y_test"]
    x_tr = m.loc[tr, data["combined_cols"]].values
    x_va = m.loc[va, data["combined_cols"]].values
    x_te = m.loc[te, data["combined_cols"]].values
    xgb = XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
    )
    xgb.fit(x_tr, y_tr)
    xgb_va_prob = xgb.predict_proba(x_va)[:, 1]
    xgb_va_pred = (xgb_va_prob >= 0.5).astype(int)
    xgb_te_prob = xgb.predict_proba(x_te)[:, 1]
    xgb_te_pred = (xgb_te_prob >= 0.5).astype(int)
    xgb_val_metrics = compute_metrics(y_va, xgb_va_pred, xgb_va_prob)
    xgb_test_metrics = compute_metrics(y_te, xgb_te_pred, xgb_te_prob)
    xgb_importances = dict(zip(data["combined_cols"], xgb.feature_importances_.tolist()))
    xgb_top = dict(sorted(xgb_importances.items(), key=lambda item: item[1], reverse=True)[:15])
    rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(x_tr, y_tr)
    rf_va_prob = rf.predict_proba(x_va)[:, 1]
    rf_va_pred = (rf_va_prob >= 0.5).astype(int)
    rf_te_prob = rf.predict_proba(x_te)[:, 1]
    rf_te_pred = (rf_te_prob >= 0.5).astype(int)
    rf_val_metrics = compute_metrics(y_va, rf_va_pred, rf_va_prob)
    rf_test_metrics = compute_metrics(y_te, rf_te_pred, rf_te_prob)
    rf_importances = dict(zip(data["combined_cols"], rf.feature_importances_.tolist()))
    rf_top = dict(sorted(rf_importances.items(), key=lambda item: item[1], reverse=True)[:15])
    ens_va_prob = 0.5 * xgb_va_prob + 0.5 * rf_va_prob
    ens_va_pred = (ens_va_prob >= 0.5).astype(int)
    ens_te_prob = 0.5 * xgb_te_prob + 0.5 * rf_te_prob
    ens_te_pred = (ens_te_prob >= 0.5).astype(int)
    ens_val_metrics = compute_metrics(y_va, ens_va_pred, ens_va_prob)
    ens_test_metrics = compute_metrics(y_te, ens_te_pred, ens_te_prob)
    results = {
        "dataset": "CIC Evasive-PDFMal2022 (1,452 samples)",
        "protocol": "Protocol G deterministic split (seed 42)",
        "splits": {"train": 870, "validation": 291, "test": 291},
        "features": {
            "total_count": len(data["combined_cols"]),
            "canonical_cic_count": len(data["cic_cols"]),
            "evasion_anomaly_count": len(data["evasion_cols"]),
        },
        "models": {
            "xgboost_fused": {"val": xgb_val_metrics, "test": xgb_test_metrics, "top_features": xgb_top},
            "random_forest_fused": {"val": rf_val_metrics, "test": rf_test_metrics, "top_features": rf_top},
            "ensemble_fused": {"val": ens_val_metrics, "test": ens_test_metrics},
        },
    }
    with (REPORT_DIR / "benchmark_results.json").open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    print("SUCCESS: Full Protocol G benchmark completed!")
    print("\n=== VALIDATION METRICS ===")
    for mname, mres in [("XGBoost Fused", xgb_val_metrics), ("Random Forest Fused", rf_val_metrics), ("Ensemble Soft Voting", ens_val_metrics)]:
        print(f"{mname:22s} | Acc: {mres['accuracy']:.4f} | F1: {mres['f1']:.4f} | MCC: {mres['mcc']:.4f} | AUC: {mres['roc_auc']:.4f} | Brier: {mres['brier']:.4f}")
    print("\n=== TEST METRICS (FROZEN EVALUATION) ===")
    for mname, mres in [("XGBoost Fused", xgb_test_metrics), ("Random Forest Fused", rf_test_metrics), ("Ensemble Soft Voting", ens_test_metrics)]:
        cm = mres["confusion_matrix"]
        print(f"{mname:22s} | Acc: {mres['accuracy']:.4f} | F1: {mres['f1']:.4f} | MCC: {mres['mcc']:.4f} | AUC: {mres['roc_auc']:.4f} | TP: {cm['tp']} FP: {cm['fp']} TN: {cm['tn']} FN: {cm['fn']}")


if __name__ == "__main__":
    main()
