# XGBoost 10-Fold Cross-Validation Analysis

## 1. Objective

This official experiment is a paper-aligned reproduction attempt of the random ten-fold XGBoost procedure described by Algorithm 1 in *RIT-PDFMal-2026: A Comprehensive Benchmark Dataset for PDF Malware Detection*. It evaluates the full local numerical dataset once under the committed design. It is not an exact reproduction and it does not change, replace, or evaluate Protocol P or Protocol G.

## 2. Relationship to the paper

The implementation uses the paper's described full-dataset random ten-fold structure: a row is held out once and the other nine folds are used for training. The project uses `KFold(n_splits=10, shuffle=True, random_state=42)`. The paper does not publish the CV seed, so `cv_split_seed=42` is a project reproducibility decision, not a paper setting.

For Table 6 comparison, paper Accuracy is compared with local Accuracy. The paper's Precision, Recall, and F1 are compared with local macro Precision, macro Recall, and macro F1 respectively, according to the separately documented metric-semantics correction. Table 6 itself does not independently specify that averaging convention.

## 3. Dataset, provenance, and feature variants

- Dataset: `rit-pdfmal-2026.csv`, 24,337 rows, 41 predictive non-hash static features, Label 0 = benign and Label 1 = malicious.
- Dataset SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Benchmark-generating code commit: `e5cb9bce8eef7bc26ea189d80fdd597fbecc3b43` (`feat(validation): add paper-aligned XGBoost 10-fold CV runner`). The worktree was clean at experiment start.
- Model randomness: `model_random_state=42` for every fit.
- CV-all41: all 41 predictive features.
- CV-drop3constant: exactly 38 features, removing only `Acroform`, `Colors`, and `BaseEncoding`.

No values were imputed, clipped, normalized, or reinterpreted. This includes documented semantic signals such as `contains_text=-1`, `pages=0`, and out-of-specification `pdf_ver` values. XGBoost was unscaled and used the established IEEE `NaN` missing-sentinel compatibility handling.

## 4. Cross-validation methodology and integrity

The official command was:

```powershell
.venv\Scripts\python.exe scripts\run_xgb_cv10.py --execute --run-id seed42
```

It performed exactly 20 fits: ten folds for each of two feature variants. The recorded integrity checks passed: all 24,337 rows were assigned to one and only one test fold, the union of test folds was the full dataset, labels were preserved, and every train/test pair was disjoint. No Protocol P holdout, Protocol G group, or feature-vector-disjoint condition was used.

| Fold | Train rows | Test rows | Train benign | Train malicious | Test benign | Test malicious |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 21,903 | 2,434 | 11,918 | 9,985 | 1,317 | 1,117 |
| 2 | 21,903 | 2,434 | 11,880 | 10,023 | 1,355 | 1,079 |
| 3 | 21,903 | 2,434 | 11,913 | 9,990 | 1,322 | 1,112 |
| 4 | 21,903 | 2,434 | 11,887 | 10,016 | 1,348 | 1,086 |
| 5 | 21,903 | 2,434 | 11,916 | 9,987 | 1,319 | 1,115 |
| 6 | 21,903 | 2,434 | 11,930 | 9,973 | 1,305 | 1,129 |
| 7 | 21,903 | 2,434 | 11,889 | 10,014 | 1,346 | 1,088 |
| 8 | 21,904 | 2,433 | 11,916 | 9,988 | 1,319 | 1,114 |
| 9 | 21,904 | 2,433 | 11,948 | 9,956 | 1,287 | 1,146 |
| 10 | 21,904 | 2,433 | 11,918 | 9,986 | 1,317 | 1,116 |

The primary splitter is deliberately non-stratified. Consequently, test benign counts range from 1,287 to 1,355 and malicious counts from 1,079 to 1,146; each fold nevertheless contains both classes.

## 5. Metric-semantics convention

`Label=1` is the malicious-positive class. Operational Precision, Recall, and F1 therefore use the malicious class. Macro metrics average the benign and malicious class metrics and are reported separately. ROC-AUC and PR-AUC use continuous malicious probabilities from `predict_proba`, never hard class labels. Confusion matrices use the fixed layout `[[TN, FP], [FN, TP]]`.

## 6. Fold-level results

Classification results are exactly identical between CV-all41 and CV-drop3constant for every fold; the runner still preserves a separate complete per-fold CSV for each variant. The table below is therefore shared by both variants. Full rows, including separate timing records, are saved in `reports/experiments/xgb_cv10/seed42/cv_all41_fold_metrics.csv` and `cv_drop3constant_fold_metrics.csv`.

| Fold | Accuracy | P malicious | R malicious | F1 malicious | P macro | R macro | F1 macro | ROC-AUC | PR-AUC | MCC | TN | FP | FN | TP |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.990961 | 0.998180 | 0.982095 | 0.990072 | 0.991599 | 0.990288 | 0.990888 | 0.998708 | 0.998969 | 0.981887 | 1,315 | 2 | 20 | 1,097 |
| 2 | 0.991372 | 0.988909 | 0.991659 | 0.990282 | 0.991126 | 0.991401 | 0.991262 | 0.999392 | 0.999379 | 0.982528 | 1,343 | 12 | 9 | 1,070 |
| 3 | 0.993426 | 0.998182 | 0.987410 | 0.992767 | 0.993844 | 0.992949 | 0.993371 | 0.999122 | 0.999302 | 0.986792 | 1,320 | 2 | 14 | 1,098 |
| 4 | 0.990961 | 0.993506 | 0.986188 | 0.989834 | 0.991222 | 0.990497 | 0.990849 | 0.998999 | 0.998973 | 0.981719 | 1,341 | 7 | 15 | 1,071 |
| 5 | 0.994248 | 0.999093 | 0.988341 | 0.993688 | 0.994663 | 0.993791 | 0.994202 | 0.998173 | 0.998720 | 0.988454 | 1,318 | 1 | 13 | 1,102 |
| 6 | 0.989729 | 0.991979 | 0.985828 | 0.988894 | 0.989892 | 0.989466 | 0.989670 | 0.999154 | 0.999122 | 0.979357 | 1,296 | 9 | 16 | 1,113 |
| 7 | 0.995481 | 0.999073 | 0.990809 | 0.994924 | 0.995847 | 0.995033 | 0.995426 | 0.999757 | 0.999734 | 0.990879 | 1,345 | 1 | 10 | 1,078 |
| 8 | 0.995890 | 0.997297 | 0.993716 | 0.995504 | 0.996003 | 0.995721 | 0.995859 | 0.999350 | 0.999429 | 0.991724 | 1,316 | 3 | 7 | 1,107 |
| 9 | 0.995479 | 0.999120 | 0.991274 | 0.995182 | 0.995702 | 0.995248 | 0.995462 | 0.999753 | 0.999738 | 0.990951 | 1,286 | 1 | 10 | 1,136 |
| 10 | 0.993013 | 0.996387 | 0.988351 | 0.992353 | 0.993291 | 0.992657 | 0.992960 | 0.999252 | 0.999281 | 0.985948 | 1,313 | 4 | 13 | 1,103 |

## 7. Aggregate results

Values are mean +/- sample standard deviation across ten folds (`ddof=1`). The two variants have identical classification and score metrics to the reported precision. Runtime is shown descriptively and is not compared directly with the paper because hardware and software differ.

| Metric | CV-all41 | CV-drop3constant |
|---|---:|---:|
| Accuracy | 0.993056 +/- 0.002212 | 0.993056 +/- 0.002212 |
| Precision malicious | 0.996173 +/- 0.003535 | 0.996173 +/- 0.003535 |
| Recall malicious | 0.988567 +/- 0.003414 | 0.988567 +/- 0.003414 |
| F1 malicious | 0.992350 +/- 0.002456 | 0.992350 +/- 0.002456 |
| Precision macro | 0.993319 +/- 0.002243 | 0.993319 +/- 0.002243 |
| Recall macro | 0.992705 +/- 0.002239 | 0.992705 +/- 0.002239 |
| F1 macro | 0.992995 +/- 0.002233 | 0.992995 +/- 0.002233 |
| ROC-AUC | 0.999166 +/- 0.000473 | 0.999166 +/- 0.000473 |
| PR-AUC | 0.999265 +/- 0.000329 | 0.999265 +/- 0.000329 |
| MCC | 0.986024 +/- 0.004462 | 0.986024 +/- 0.004462 |
| Training seconds | 0.864796 +/- 0.133536 | 0.742500 +/- 0.022456 |
| Test inference seconds | 0.033258 +/- 0.007311 | 0.037222 +/- 0.028212 |
| Test inference ms/sample | 0.013665 +/- 0.003003 | 0.015296 +/- 0.011597 |

The aggregate CSV additionally records `n=10`, median, minimum, and maximum for every metric and timing value.

## 8. Paper Table 6 comparison

| Variant | Comparison | Paper mean | Local mean | Signed mean delta | Paper reported std | Local sample std | Signed std delta |
|---|---|---:|---:|---:|---:|---:|---:|
| CV-all41 | Accuracy | 0.993878 | 0.993056 | -0.000822 | 0.000789 | 0.002212 | +0.001423 |
| CV-all41 | Precision macro | 0.995663 | 0.993319 | -0.002344 | 0.001382 | 0.002243 | +0.000861 |
| CV-all41 | Recall macro | 0.990901 | 0.992705 | +0.001804 | 0.002012 | 0.002239 | +0.000227 |
| CV-all41 | F1 macro | 0.993274 | 0.992995 | -0.000279 | 0.000841 | 0.002233 | +0.001392 |
| CV-drop3constant | Accuracy | 0.993878 | 0.993056 | -0.000822 | 0.000789 | 0.002212 | +0.001423 |
| CV-drop3constant | Precision macro | 0.995663 | 0.993319 | -0.002344 | 0.001382 | 0.002243 | +0.000861 |
| CV-drop3constant | Recall macro | 0.990901 | 0.992705 | +0.001804 | 0.002012 | 0.002239 | +0.000227 |
| CV-drop3constant | F1 macro | 0.993274 | 0.992995 | -0.000279 | 0.000841 | 0.002233 | +0.001392 |

The local means are in a similar numerical range to the paper's reported XGBoost ten-fold values. In particular, the absolute F1 macro mean difference is 0.000279. This supports a paper-aligned reproduction attempt under the available methodology, not a claim of exact reproduction. The paper does not state whether its standard deviations use sample or population normalization; local standard deviations use the project's sample convention and must not be treated as definitionally identical to the paper's values.

## 9. Feature-variant comparison

For every fold, all classification metrics, ROC-AUC, PR-AUC, MCC, predicted labels, and malicious scores are exactly equal between CV-all41 and CV-drop3constant. The maximum absolute per-fold difference is 0.0 for each reported classification/score metric, there are zero differing OOF predicted labels, and the maximum absolute OOF score difference is 0.0.

Within this fixed XGBoost experiment, the three documented constant-zero features therefore have negligible effect on classification outcomes. This result does not establish that those feature names are universally irrelevant outside this dataset, configuration, and protocol. Wall-clock timings differ and are not evidence of a classification difference.

## 10. Fold variability

Using macro F1 as the paper-aligned performance reference, fold 8 is the highest-performing fold (macro F1 0.995859, Accuracy 0.995890, MCC 0.991724). Fold 6 is the lowest-performing fold (macro F1 0.989670, Accuracy 0.989729, MCC 0.979357).

Across performance metrics, the largest observed fold range is MCC: 0.012367 (0.979357 to 0.991724). The macro F1 range is 0.006189, Accuracy range is 0.006161, ROC-AUC range is 0.001584, and PR-AUC range is 0.001018. These values describe this single fixed random KFold assignment; they are not a separate multi-seed sensitivity study.

## 11. Threats to validity

- The paper's CV random seed is unavailable; this project uses `cv_split_seed=42`.
- The paper does not fully specify XGBoost hyperparameters, all software defaults, preprocessing details, or its exact zero-variance feature-removal state. The project uses the frozen prior XGBoost configuration and reports both approved variants.
- This row-level KFold design allows identical static feature vectors in different folds. It does not measure feature-vector-disjoint generalization; that is the separate Protocol G question.
- The experiment does not measure temporal generalization, cross-dataset generalization, calibration, or threshold sensitivity.
- Paper standard-deviation normalization is not documented in the available reference. Local values use sample standard deviation (`ddof=1`).
- Runtime reflects Windows 10, Python 3.11.0, XGBoost 3.2.0, Intel Core i5-14400F, NVIDIA GeForce RTX 5060 Ti (8,151 MiB detected), and 16,948,178,944 bytes of RAM; it is not directly comparable with paper runtime.

## 12. Findings

All 20 fixed fits completed with no failed folds or reported warnings. Both feature variants give a mean macro F1 of 0.992995 +/- 0.002233 and a mean MCC of 0.986024 +/- 0.004462. The project reproduces the paper's reported XGBoost ten-fold performance to a similar high-0.99 numerical range under the available paper-aligned methodology, but cannot demonstrate exact reproduction because key paper details remain unavailable.

This result must not be used to invalidate or supersede Protocol G. CV10 is row-level paper-aligned cross-validation; Protocol G is a separate feature-vector-disjoint generalization evaluation.

## 13. Implications for later experiments

The stored OOF records provide one prediction and malicious probability per dataset row and variant for future preregistered calibration, threshold, or error analyses without rerunning this official CV. Those analyses are not performed here. Any future generalization conclusion should continue to keep the CV10, Protocol P, and Protocol G designs distinct.
