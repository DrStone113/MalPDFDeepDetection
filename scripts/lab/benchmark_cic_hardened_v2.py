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
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parents[2]
PARQUET_OURS = REPO / "data/processed/cic_full/cic_features_1452.parquet"
PARQUET_CIC = REPO / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"
REPORT_DIR = REPO / "reports/experiments/cic_protocol_g_full"


def safe_div(a: pd.Series, b: pd.Series) -> pd.Series:
    res = a.astype(float) / np.maximum(b.astype(float).abs(), 1.0)
    return res.replace([np.inf, -np.inf, np.nan], 0.0)


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


def stage1_triage(df: pd.DataFrame) -> np.ndarray:
    trap_mask = (
        (df["evasive_timeout_anomaly"] == 1)
        | (df["flag_decompression_ratio_exceeded"] == 1)
        | (df["is_truncated_stream"] == 1)
        | (df["flag_spec_violation_flood"] == 1)
        | (df["flag_excessive_object_graph"] == 1)
    )
    return trap_mask.astype(int).values


def predict_two_stage(df: pd.DataFrame, model, features: list[str]) -> tuple[np.ndarray, np.ndarray]:
    flags = stage1_triage(df)
    stage2_probs = model.predict_proba(df[features])[:, 1]
    stage2_preds = (stage2_probs >= 0.5).astype(int)
    final_preds = np.zeros(len(df), dtype=int)
    final_probs = np.zeros(len(df), dtype=float)
    for i in range(len(df)):
        if flags[i] == 1:
            final_preds[i] = 1
            final_probs[i] = max(0.95, float(stage2_probs[i]))
        else:
            final_preds[i] = stage2_preds[i]
            final_probs[i] = float(stage2_probs[i])
    return final_preds, final_probs


def load_dataset() -> tuple[pd.DataFrame, list[str], list[str]]:
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
    v1_features = cic_cols + evasion_cols + entropy_cols
    hardened_cic = [c for c in cic_cols if "startxref" not in c.lower()]
    v2_features = hardened_cic + pillar_engineered_cols + entropy_cols
    return merged, v1_features, v2_features


def main():
    merged, v1_cols, v2_cols = load_dataset()
    train = merged[merged["split"] == "train"]
    val = merged[merged["split"] == "validation"]
    test = merged[merged["split"] == "test"].copy()
    y_tr = train["Label"].values
    y_va = val["Label"].values
    y_te = test["Label"].values
    rf_v1 = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    rf_v1.fit(train[v1_cols], y_tr)
    v1_te_pred = rf_v1.predict(test[v1_cols])
    v1_te_prob = rf_v1.predict_proba(test[v1_cols])[:, 1]
    v1_te_metrics = compute_metrics(y_te, v1_te_pred, v1_te_prob)
    rf_v2 = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    rf_v2.fit(train[v2_cols], y_tr)
    xgb_v2 = XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.08, subsample=0.8, colsample_bytree=0.8, random_state=42, n_jobs=-1)
    xgb_v2.fit(train[v2_cols], y_tr)
    rf_v2_te_pred, rf_v2_te_prob = predict_two_stage(test, rf_v2, v2_cols)
    rf_v2_te_metrics = compute_metrics(y_te, rf_v2_te_pred, rf_v2_te_prob)
    xgb_v2_te_pred, xgb_v2_te_prob = predict_two_stage(test, xgb_v2, v2_cols)
    xgb_v2_te_metrics = compute_metrics(y_te, xgb_v2_te_pred, xgb_v2_te_prob)
    stage1_flags = stage1_triage(test)
    ens_base_prob = 0.5 * rf_v2.predict_proba(test[v2_cols])[:, 1] + 0.5 * xgb_v2.predict_proba(test[v2_cols])[:, 1]
    ens_v2_te_pred = np.zeros(len(test), dtype=int)
    ens_v2_te_prob = np.zeros(len(test), dtype=float)
    for i in range(len(test)):
        if stage1_flags[i] == 1:
            ens_v2_te_pred[i] = 1
            ens_v2_te_prob[i] = max(0.95, float(ens_base_prob[i]))
        else:
            ens_v2_te_pred[i] = int(ens_base_prob[i] >= 0.5)
            ens_v2_te_prob[i] = float(ens_base_prob[i])
    ens_v2_te_metrics = compute_metrics(y_te, ens_v2_te_pred, ens_v2_te_prob)
    test_adv = test.copy()
    mal_mask = test_adv["Label"] == 1
    test_adv.loc[mal_mask, "StartXref"] = 2
    test_adv.loc[mal_mask, "Xref"] = 2
    test_adv.loc[mal_mask, "XrefLength"] = 2
    v1_adv_pred = rf_v1.predict(test_adv[v1_cols])
    v1_adv_prob = rf_v1.predict_proba(test_adv[v1_cols])[:, 1]
    v1_adv_metrics = compute_metrics(y_te, v1_adv_pred, v1_adv_prob)
    rf_v2_adv_pred, rf_v2_adv_prob = predict_two_stage(test_adv, rf_v2, v2_cols)
    rf_v2_adv_metrics = compute_metrics(y_te, rf_v2_adv_pred, rf_v2_adv_prob)
    xgb_v2_adv_pred, xgb_v2_adv_prob = predict_two_stage(test_adv, xgb_v2, v2_cols)
    xgb_v2_adv_metrics = compute_metrics(y_te, xgb_v2_adv_pred, xgb_v2_adv_prob)
    stage1_adv_flags = stage1_triage(test_adv)
    ens_adv_base_prob = 0.5 * rf_v2.predict_proba(test_adv[v2_cols])[:, 1] + 0.5 * xgb_v2.predict_proba(test_adv[v2_cols])[:, 1]
    ens_v2_adv_pred = np.zeros(len(test_adv), dtype=int)
    ens_v2_adv_prob = np.zeros(len(test_adv), dtype=float)
    for i in range(len(test_adv)):
        if stage1_adv_flags[i] == 1:
            ens_v2_adv_pred[i] = 1
            ens_v2_adv_prob[i] = max(0.95, float(ens_adv_base_prob[i]))
        else:
            ens_v2_adv_pred[i] = int(ens_adv_base_prob[i] >= 0.5)
            ens_v2_adv_prob[i] = float(ens_adv_base_prob[i])
    ens_v2_adv_metrics = compute_metrics(y_te, ens_v2_adv_pred, ens_v2_adv_prob)
    results = {
        "benchmark_id": "v2_four_pillars_hardened_robustness",
        "protocol": "Protocol G (seed 42: 870 Train / 291 Val / 291 Test)",
        "features": {
            "v1_baseline_count": len(v1_cols),
            "v2_hardened_count": len(v2_cols),
            "startxref_included_in_v2": False,
        },
        "evaluation_standard_test": {
            "model_v1_baseline_rf": v1_te_metrics,
            "model_v2_hardened_rf": rf_v2_te_metrics,
            "model_v2_hardened_xgb": xgb_v2_te_metrics,
            "model_v2_hardened_ensemble": ens_v2_te_metrics,
        },
        "evaluation_adversarial_reverse_mimicry": {
            "attack_description": "Incremental update forgery: faking StartXref=2, Xref=2, XrefLength=2 on all malware samples",
            "model_v1_baseline_rf": v1_adv_metrics,
            "model_v2_hardened_rf": rf_v2_adv_metrics,
            "model_v2_hardened_xgb": xgb_v2_adv_metrics,
            "model_v2_hardened_ensemble": ens_v2_adv_metrics,
        },
        "top_features_model_v2": {
            "random_forest": dict(sorted(zip(v2_cols, rf_v2.feature_importances_.tolist()), key=lambda x: x[1], reverse=True)[:15]),
            "xgboost": dict(sorted(zip(v2_cols, xgb_v2.feature_importances_.tolist()), key=lambda x: x[1], reverse=True)[:15]),
        },
    }
    with (REPORT_DIR / "v2_hardened_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("SUCCESS: V2 Hardened 4-Pillar Robustness Benchmark complete!")
    print(f"\nStandard Test - Model V1 RF (with StartXref)       : Acc={v1_te_metrics['accuracy']:.4f} | Recall={v1_te_metrics['recall']:.4f} | F1={v1_te_metrics['f1']:.4f}")
    print(f"Standard Test - Model V2 RF (ZERO StartXref)       : Acc={rf_v2_te_metrics['accuracy']:.4f} | Recall={rf_v2_te_metrics['recall']:.4f} | F1={rf_v2_te_metrics['f1']:.4f}")
    print(f"Standard Test - Model V2 Ensemble (ZERO StartXref) : Acc={ens_v2_te_metrics['accuracy']:.4f} | Recall={ens_v2_te_metrics['recall']:.4f} | F1={ens_v2_te_metrics['f1']:.4f}")
    print(f"\nAdversarial Attack - Model V1 RF (with StartXref)      : Acc={v1_adv_metrics['accuracy']:.4f} | Recall={v1_adv_metrics['recall']:.4f} (TP: {v1_adv_metrics['confusion_matrix']['tp']}/160)")
    print(f"Adversarial Attack - Model V2 RF (ZERO StartXref)      : Acc={rf_v2_adv_metrics['accuracy']:.4f} | Recall={rf_v2_adv_metrics['recall']:.4f} (TP: {rf_v2_adv_metrics['confusion_matrix']['tp']}/160)")
    print(f"Adversarial Attack - Model V2 Ensemble (ZERO StartXref): Acc={ens_v2_adv_metrics['accuracy']:.4f} | Recall={ens_v2_adv_metrics['recall']:.4f} (TP: {ens_v2_adv_metrics['confusion_matrix']['tp']}/160)")


if __name__ == "__main__":
    main()

