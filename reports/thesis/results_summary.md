# Results Summary

All values below are generated from the committed source artifacts listed in `tables/evidence_source_checksums.csv`. `precision_malicious`, `recall_malicious`, and `f1_malicious` use Label=1 as the positive class; macro metrics are named explicitly.

## Dataset / audit

**Measured:** RIT-PDFMal-2026 contains 24,337 rows, 41 predictive static features and Label; Label=0 has 13,235 rows and Label=1 has 11,102 rows. The audit found 15,371 feature-equivalent groups. These are identical 41-dimensional feature vectors, not proven duplicate PDF files, because the local CSV lacks original per-PDF hashes.

**Interpretation:** Acroform, Colors, and BaseEncoding are constant zero; RichMedia is near-constant. Documented values such as `contains_text=-1`, `pages=0`, and unusual `pdf_ver` values remain semantic source values rather than missing-data replacements.

## Classical ML and leakage-aware evaluation

**Measured:** Protocol P is a paper-aligned 75/25 stratified row-level seed-42 reproduction attempt; Protocol G is a deterministic 60/20/20 feature-vector-disjoint evaluation with zero identical-feature-vector overlap. The primary leakage-aware table is below and the full P/G tables are in `tables/protocol_p_models.csv` and `tables/protocol_g_models.csv`.

| model | accuracy | precision_malicious | recall_malicious | f1_malicious | f1_macro | roc_auc | pr_auc | mcc |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| logistic_regression | 0.903226 | 0.949614 | 0.831982 | 0.886915 | 0.901170 | 0.965876 | 0.963026 | 0.808348 |
| random_forest | 0.974728 | 0.997155 | 0.947297 | 0.971587 | 0.974415 | 0.997856 | 0.997762 | 0.949869 |
| decision_tree | 0.965893 | 0.983067 | 0.941441 | 0.961804 | 0.965497 | 0.963921 | 0.952210 | 0.931732 |
| gaussian_naive_bayes | 0.707417 | 0.616306 | 0.950000 | 0.747607 | 0.699806 | 0.773518 | 0.659442 | 0.494884 |
| xgboost | 0.976988 | 0.995301 | 0.954054 | 0.974241 | 0.976723 | 0.997079 | 0.997354 | 0.954161 |

**Interpretation:** XGBoost P-drop3constant has f1_malicious=0.991852; its Protocol G counterpart has f1_malicious=0.974241. Protocol G reduces identical-feature-vector leakage but does not establish temporal, file-identity, external-dataset, or real-world generalization.

## Multi-seed robustness

**Measured:** Across seeds 42–46, LR, RF, DT, and XGBoost have G<P f1_malicious and MCC in all five seed-labelled comparisons; GNB is opposite/model-specific. Exact means, sample standard deviations, and paired G−P deltas are in `tables/multiseed_summary.csv`.

**Interpretation:** This is directionally stable across five split seeds, not a statistical-significance result.

## Paper-aligned XGBoost CV10

**Measured:** Full-dataset non-stratified `KFold(10, shuffle=True, random_state=42)` completed 20/20 fits with OOF integrity. CV-all41 macro precision/recall/f1 are 0.993319, 0.992705, and 0.992995; accuracy is 0.993056.

**Interpretation:** Table 6 comparison uses macro Precision/Recall/F1 because the paper values are consistent with macro averaging. It is a paper-aligned reproduction attempt, not exact reproduction or feature-vector-disjoint evaluation.

## Explainability

**Measured:** A fixed retrain reproduced the historical Protocol G XGBoost metrics before native TreeSHAP on 4,867 test rows and 38 features. The largest global mean absolute contribution is JavaScript (3.532577); the ranked top ten are in `tables/xgb_shap_top10.csv`.

**Interpretation:** JavaScript, pdfsize, URI, contains_text, and metadata size are influential to this local model. SHAP describes model contributions, not causal malware mechanisms.

## Deep-learning comparison

**Measured:** On one fixed Protocol G seed-42 split, FT-Transformer has f1_malicious=0.977169 and MCC=0.958795, above the historical XGBoost reference for these two metrics; its ROC-AUC and PR-AUC are lower. Exact three-model values, training times, and neural parameter counts are in `tables/deep_learning_comparison.csv`.

**Interpretation:** This one fixed-architecture, one-split comparison does not establish general superiority over XGBoost; CUDA deterministic limitations are recorded in the original run.

## Static detector and dynamic architecture

**Measured/implemented:** the static extractor progressed from 31 verified / 7 provisional / 3 ambiguous definitions and a 28/38 failing Protocol G gate to 41/41 verified definitions and a 38/38 passing schema gate. The deployment model `xgb-rit-full-drop3constant-v1` is a 38-feature, full-data static detector with threshold 0.5, compatibility gate, probability/verdict, and local TreeSHAP.

**Boundary:** deployment adds no new accuracy evidence. Dynamic-schema-v1, its 21 offline behavioral features, routing policies, and the isolated CAPE design are implemented/design artifacts only: no live dynamic, hybrid, or sandbox performance result exists.
