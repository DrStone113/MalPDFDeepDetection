# Protocol P versus Protocol G comparative analysis

## 1. Objective

Research question: *How much does malicious-PDF classification performance change when identical static feature representations are prevented from appearing across training and evaluation partitions?*

This report is a deterministic analysis of the committed seed-42 baseline reports. It does not train, refit, tune, threshold-adjust, or regenerate any split.

## 2. Experimental protocols

- **Protocol P** is a paper-aligned, stratified row-level 75/25 train/test split. Its seed 42 is a project choice, not a published paper seed.
- **Protocol G** is a saved 60/20/20-style train/validation/test split whose feature-equivalent groups are partition-disjoint. It prevents identical static feature vectors from crossing partitions.
- Protocol G is not file-level deduplication: the local CSV has no per-PDF SHA-256 field, so PDF-file identity cannot be established.

## 3. Comparison methodology

- Dataset SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`; seed: `42`.
- Protocol P result commit/tag: `ed50bd9e4e9cd0268c9e2359a89a1867dad68095` / `v0.3.0-protocol-p-baseline`; benchmark-generating code: `3e970ef2df0460fb4a51b10418c9af7564339419`.
- Protocol G result commit/tag: `30b4e1b676a674424e004035fc8ffb8d9c615ad6` / `v0.4.0-protocol-g-baseline`; benchmark-generating code: `c2aefaaca8cd2257ed610efeba88f24a7cbbb460`.
- Each comparison pairs P-all41 with G-all41 and P-drop3constant with G-drop3constant. Signed deltas are Protocol G test minus Protocol P test; absolute differences discard direction.
- Error rates use class-specific denominators: FPR = FP / (TN + FP), FNR = FN / (FN + TP), TPR = TP / (FN + TP), and TNR = TN / (TN + FP). Raw counts are retained but are not compared alone because test-set sizes differ.

## 4. Overall P versus G results

| Model | Variant | P F1 | G test F1 | Delta F1 | P MCC | G test MCC | Delta MCC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Logistic Regression | all 41 | 0.924700 | 0.886647 | -0.038052 | 0.862799 | 0.807959 | -0.054840 |
| Logistic Regression | drop 3 constants | 0.924700 | 0.886915 | -0.037785 | 0.862799 | 0.808348 | -0.054451 |
| Random Forest | all 41 | 0.990379 | 0.970874 | -0.019506 | 0.982523 | 0.948671 | -0.033853 |
| Random Forest | drop 3 constants | 0.990016 | 0.971587 | -0.018429 | 0.981860 | 0.949869 | -0.031991 |
| Decision Tree | all 41 | 0.983842 | 0.965802 | -0.018040 | 0.970223 | 0.938668 | -0.031555 |
| Decision Tree | drop 3 constants | 0.983671 | 0.961804 | -0.021867 | 0.969901 | 0.931732 | -0.038169 |
| GaussianNB | all 41 | 0.687852 | 0.747607 | +0.059755 | 0.348129 | 0.494884 | +0.146755 |
| GaussianNB | drop 3 constants | 0.687852 | 0.747607 | +0.059755 | 0.348129 | 0.494884 | +0.146755 |
| XGBoost | all 41 | 0.991852 | 0.974241 | -0.017611 | 0.985128 | 0.954161 | -0.030968 |
| XGBoost | drop 3 constants | 0.991852 | 0.974241 | -0.017611 | 0.985128 | 0.954161 | -0.030968 |

The complete seven-metric paired table, signed deltas, and absolute differences are in `reports/tables/protocol_p_vs_g/combined_metrics.csv` and `metric_deltas.csv`. Under this fixed seed-42 configuration, the high-performing conventional models show lower Protocol G test F1 and MCC than their paired Protocol P results; GaussianNB is addressed separately below.

## 5. Model-specific behavior

For the four conventionally high-performing model families, the largest mean absolute F1 change across the two variants is Logistic Regression (0.037919); the smallest is XGBoost (0.017611). For MCC, the largest is Logistic Regression (0.054645) and the smallest is XGBoost (0.030968). GaussianNB is excluded from these degradation rankings because its P-to-G values move in the opposite direction.

## 6. XGBoost analysis

| Variant | P Prec. | G Prec. | P Recall | G Recall | P F1 | G F1 | P ROC | G ROC | P PR | G PR | P MCC | G MCC | P FP | G FP | P FN | G FN | P FPR | G FPR | P FNR | G FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| all 41 | 0.997088 | 0.995301 | 0.986671 | 0.954054 | 0.991852 | 0.974241 | 0.998957 | 0.997079 | 0.999022 | 0.997354 | 0.985128 | 0.954161 | 8 | 10 | 37 | 102 | 0.002418 | 0.003778 | 0.013329 | 0.045946 |
| drop 3 constants | 0.997088 | 0.995301 | 0.986671 | 0.954054 | 0.991852 | 0.974241 | 0.998957 | 0.997079 | 0.999022 | 0.997354 | 0.985128 | 0.954161 | 8 | 10 | 37 | 102 | 0.002418 | 0.003778 | 0.013329 | 0.045946 |

For XGBoost all41, Protocol G test ROC-AUC and PR-AUC remain high (0.997079 and 0.997354), while recall, F1, and MCC are lower than Protocol P by -0.032617, -0.017611, and -0.030968, respectively. The ranking metrics remain high while fixed-threshold classification performance decreases. This analysis does not measure calibration and does not tune a threshold.

## 7. Error-rate analysis

| Model | Variant | P FPR | G FPR | P FNR | G FNR | P TPR | G TPR | P TNR | G TNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Logistic Regression | all 41 | 0.054397 | 0.037023 | 0.084294 | 0.168468 | 0.915706 | 0.831532 | 0.945603 | 0.962977 |
| Logistic Regression | drop 3 constants | 0.054397 | 0.037023 | 0.084294 | 0.168018 | 0.915706 | 0.831982 | 0.945603 | 0.962977 |
| Random Forest | all 41 | 0.001511 | 0.002267 | 0.017291 | 0.054054 | 0.982709 | 0.945946 | 0.998489 | 0.997733 |
| Random Forest | drop 3 constants | 0.001813 | 0.002267 | 0.017651 | 0.052703 | 0.982349 | 0.947297 | 0.998187 | 0.997733 |
| Decision Tree | all 41 | 0.016319 | 0.012467 | 0.012968 | 0.052252 | 0.987032 | 0.947748 | 0.983681 | 0.987533 |
| Decision Tree | drop 3 constants | 0.016924 | 0.013600 | 0.012608 | 0.058559 | 0.987392 | 0.941441 | 0.983076 | 0.986400 |
| GaussianNB | all 41 | 0.745845 | 0.496033 | 0.009726 | 0.050000 | 0.990274 | 0.950000 | 0.254155 | 0.503967 |
| GaussianNB | drop 3 constants | 0.745845 | 0.496033 | 0.009726 | 0.050000 | 0.990274 | 0.950000 | 0.254155 | 0.503967 |
| XGBoost | all 41 | 0.002418 | 0.003778 | 0.013329 | 0.045946 | 0.986671 | 0.954054 | 0.997582 | 0.996222 |
| XGBoost | drop 3 constants | 0.002418 | 0.003778 | 0.013329 | 0.045946 | 0.986671 | 0.954054 | 0.997582 | 0.996222 |

The machine-readable error table includes TN, FP, FN, TP and the denominators for every paired test configuration in `normalized_error_rates.csv`.

## 8. Constant-feature experiment

The comparison removes only Acroform, Colors, and BaseEncoding. The following values are drop3constant minus all41 within each protocol and model:

| Protocol | Model | Delta F1 | Delta MCC | Delta ROC-AUC | Delta PR-AUC |
| --- | --- | --- | --- | --- | --- |
| P | Logistic Regression | +0.000000 | +0.000000 | +0.000000 | +0.000001 |
| P | Random Forest | -0.000363 | -0.000663 | +0.000263 | +0.000154 |
| P | Decision Tree | -0.000171 | -0.000322 | -0.000122 | -0.000497 |
| P | GaussianNB | +0.000000 | +0.000000 | +0.000000 | +0.000000 |
| P | XGBoost | +0.000000 | +0.000000 | +0.000000 | +0.000000 |
| G | Logistic Regression | +0.000267 | +0.000389 | -0.000001 | -0.000001 |
| G | Random Forest | +0.000713 | +0.001199 | +0.000477 | +0.000330 |
| G | Decision Tree | -0.003998 | -0.006936 | -0.003720 | -0.004736 |
| G | GaussianNB | +0.000000 | +0.000000 | +0.000000 | +0.000000 |
| G | XGBoost | +0.000000 | +0.000000 | +0.000000 | +0.000000 |

The observed changes are negligible for several configurations, exactly zero for the recorded GaussianNB and XGBoost classification metrics, and non-zero for Random Forest and Decision Tree. These results support only a statement about this dataset and fixed experiment; they do not establish universal irrelevance of the three features.

## 9. GaussianNB anomaly

GaussianNB has high recall but low precision in both protocols. For all41, Protocol P recall/precision/F1/MCC are 0.990274 / 0.526931 / 0.687852 / 0.348129; Protocol G test values are 0.950000 / 0.616306 / 0.747607 / 0.494884. The Protocol G all41 test has 1313 false positives. Its F1 and MCC improve relative to Protocol P while most other models decline; this is an unresolved model-behavior question, not evidence of superior generalization.

Hypotheses for later, separately authorized investigation (not findings): inspect class-conditional feature distributions and the Naive Bayes independence assumption; inspect score distributions under the fixed threshold; and quantify the pattern across multiple seeds without tuning against the test set.

## 10. Threats to validity

- Protocol P and Protocol G use different split ratios, and Protocol G has a smaller training set.
- Protocol G tests feature-vector disjointness, not temporal drift, cross-dataset shift, or true PDF-file identity.
- Original per-PDF hashes are unavailable in the local published CSV.
- Only seed 42 has been evaluated; statistical uncertainty has not been quantified with multi-seed experiments.
- Where the paper did not specify settings, model hyperparameters and preprocessing are fixed project assumptions.
- These two protocols alone cannot support a claim about real-world malware robustness.

## 11. Findings

Under the fixed seed-42 configuration, preventing identical static feature representations from crossing training and evaluation partitions reduced the Protocol G test performance of most high-performing models. The magnitude is metric- and model-specific and is reported in the paired tables; it must not be attributed to duplicate PDF files because file-level hashes are unavailable.

## 12. Questions for follow-up experiments

- Does the P-to-G difference persist across preregistered additional seeds without changing configurations?
- How stable are the findings under a separately designed cross-validation or external-dataset protocol?
- What explains GaussianNB's contrary directional change under the two saved protocols?
- Do score-distribution and calibration analyses, performed separately, clarify the high ranking metrics and lower fixed-threshold metrics for XGBoost?

## Appendix: Protocol G validation versus test consistency

The full six-metric validation/test delta table is in `validation_test_deltas.csv`. The largest absolute differences observed for each metric are listed below without assigning a statistical-significance threshold.

| Metric | Model | Variant | G validation | G test | Test minus validation |
| --- | --- | --- | --- | --- | --- |
| F1 | Decision Tree | drop 3 constants | 0.937869 | 0.961804 | +0.023935 |
| MCC | Decision Tree | drop 3 constants | 0.893686 | 0.931732 | +0.038046 |
| RECALL | Decision Tree | drop 3 constants | 0.893742 | 0.941441 | +0.047700 |
| PRECISION | GaussianNB | all 41 | 0.626702 | 0.616306 | -0.010396 |
| ROC-AUC | Decision Tree | drop 3 constants | 0.941771 | 0.963921 | +0.022150 |
| PR-AUC | Decision Tree | drop 3 constants | 0.930228 | 0.952210 | +0.021982 |
