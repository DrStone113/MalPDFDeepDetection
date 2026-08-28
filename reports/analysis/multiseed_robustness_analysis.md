# RIT-PDFMal-2026 Protocol P vs Protocol G multi-seed robustness analysis

## 1. Objective

This descriptive robustness experiment evaluates whether the completed seed-42 Protocol P versus Protocol G differences persist across the fixed split seeds 42, 43, 44, 45, and 46. It does not estimate real-world malware robustness, temporal generalization, or cross-dataset generalization.

## 2. Experimental controls

- Benchmark-generating code commit: `2147d0a1e12162ac7092fe797260f0c12a5fe3d6`.
- Dataset SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Split seeds: 42, 43, 44, 45, 46.
- `model_random_state`: 42 for every stochastic model and every split seed.
- Canonical variants only: P-drop3constant and G-drop3constant; only Acroform, Colors, and BaseEncoding are excluded.
- Five fixed baseline configurations: Logistic Regression, Random Forest, Decision Tree, Gaussian Naive Bayes, and XGBoost.
- Completed seed-42 source results were reused (10 records); seed 43-46 produced 40 new fits. All 50 records completed with no failures.
- Label=1 is the malicious-positive class. ROC-AUC and PR-AUC use Label=1 continuous scores. Macro and malicious-positive metrics are reported separately.

## 3. Seed design and protocol distinction

Protocol P uses a row-level stratified 75/25 train/test split. Protocol G uses the established group-aware, approximately 60/20/20 train/validation/test algorithm, ensuring feature-equivalent groups (identical static 41-feature vectors) cannot cross partitions. These are not claims about duplicate PDF files, because the public CSV has no original per-file hash column.

The split seed changes assignment only. Holding model randomness at 42 isolates observed split-assignment sensitivity from model-randomness sensitivity. Protocol G validation is diagnostic only: no threshold, feature, model, or hyperparameter choice was made from it, and models were not retrained on train plus validation.

## 4. Protocol P test results across five seeds

| Model | F1 malicious (mean +/- sample SD) | F1 macro (mean +/- sample SD) | MCC (mean +/- sample SD) |
| --- | --- | --- | --- |
| Logistic Regression | 0.924197 +/- 0.002575 | 0.930806 +/- 0.002549 | 0.861754 +/- 0.005196 |
| Random Forest | 0.991990 +/- 0.001280 | 0.992673 +/- 0.001164 | 0.985408 +/- 0.002308 |
| Decision Tree | 0.985993 +/- 0.001871 | 0.987089 +/- 0.001728 | 0.974192 +/- 0.003453 |
| GaussianNB | 0.695594 +/- 0.009136 | 0.566967 +/- 0.025623 | 0.369622 +/- 0.024949 |
| XGBoost | 0.992588 +/- 0.001214 | 0.993206 +/- 0.001107 | 0.986435 +/- 0.002201 |

## 5. Protocol G validation results across five seeds

| Model | F1 malicious (mean +/- sample SD) | F1 macro (mean +/- sample SD) | MCC (mean +/- sample SD) |
| --- | --- | --- | --- |
| Logistic Regression | 0.884403 +/- 0.014722 | 0.898800 +/- 0.012130 | 0.803245 +/- 0.022732 |
| Random Forest | 0.974111 +/- 0.004510 | 0.976670 +/- 0.003993 | 0.954296 +/- 0.007669 |
| Decision Tree | 0.963436 +/- 0.015116 | 0.967089 +/- 0.013080 | 0.935197 +/- 0.024730 |
| GaussianNB | 0.733708 +/- 0.030468 | 0.666974 +/- 0.065937 | 0.459120 +/- 0.074986 |
| XGBoost | 0.979285 +/- 0.004382 | 0.981228 +/- 0.003886 | 0.962952 +/- 0.007466 |

## 6. Protocol G test results across five seeds

| Model | F1 malicious (mean +/- sample SD) | F1 macro (mean +/- sample SD) | MCC (mean +/- sample SD) |
| --- | --- | --- | --- |
| Logistic Regression | 0.885181 +/- 0.008665 | 0.899248 +/- 0.007347 | 0.803596 +/- 0.014341 |
| Random Forest | 0.971353 +/- 0.005809 | 0.974240 +/- 0.005116 | 0.949635 +/- 0.009763 |
| Decision Tree | 0.968615 +/- 0.006404 | 0.971583 +/- 0.005676 | 0.943714 +/- 0.011046 |
| GaussianNB | 0.737193 +/- 0.032013 | 0.671923 +/- 0.066714 | 0.468212 +/- 0.077691 |
| XGBoost | 0.974451 +/- 0.006691 | 0.976961 +/- 0.005931 | 0.954782 +/- 0.011425 |

All aggregate rows use `n=5` and sample standard deviation (`ddof=1`). Full named-metric tables, including Accuracy, malicious-positive Precision/Recall/F1, macro Precision/Recall/F1, ROC-AUC, PR-AUC, MCC, and confusion counts, are in `reports/experiments/multiseed/official-seeds42-46/aggregate/aggregate_metrics.csv`.

## 7. Paired-by-seed Protocol G test minus Protocol P test deltas

The following are comparisons paired by the seed label across distinct protocol splits, not sample-level paired observations.

| Model | Mean Delta F1 malicious +/- sample SD | Mean Delta F1 macro +/- sample SD | Mean Delta MCC +/- sample SD | G < P (F1 seeds) |
| --- | --- | --- | --- | --- |
| Logistic Regression | -0.039015 +/- 0.006320 | -0.031558 +/- 0.005107 | -0.058158 +/- 0.010048 | 5 |
| Random Forest | -0.020637 +/- 0.006187 | -0.018432 +/- 0.005465 | -0.035773 +/- 0.010464 | 5 |
| Decision Tree | -0.017378 +/- 0.005799 | -0.015506 +/- 0.005120 | -0.030478 +/- 0.009946 | 5 |
| GaussianNB | 0.041599 +/- 0.026610 | 0.104956 +/- 0.052994 | 0.098590 +/- 0.063736 | 0 |
| XGBoost | -0.018137 +/- 0.007151 | -0.016245 +/- 0.006352 | -0.031653 +/- 0.012260 | 5 |

Direction counts by F1 and MCC:

| Model | F1: G<P | F1: G>P | MCC: G<P | MCC: G>P |
| --- | --- | --- | --- | --- |
| Logistic Regression | 5 | 0 | 5 | 0 |
| Random Forest | 5 | 0 | 5 | 0 |
| Decision Tree | 5 | 0 | 5 | 0 |
| GaussianNB | 0 | 5 | 0 | 5 |
| XGBoost | 5 | 0 | 5 | 0 |

## 8. XGBoost robustness

| Metric | Protocol P test | Protocol G test | G - P | Direction |
| --- | --- | --- | --- | --- |
| f1_malicious | 0.992588 +/- 0.001214 | 0.974451 +/- 0.006691 | -0.018137 +/- 0.007151 | G<P: 5/5 |
| f1_macro | 0.993206 +/- 0.001107 | 0.976961 +/- 0.005931 | -0.016245 +/- 0.006352 | G<P: 5/5 |
| mcc | 0.986435 +/- 0.002201 | 0.954782 +/- 0.011425 | -0.031653 +/- 0.012260 | G<P: 5/5 |
| recall_malicious | 0.989121 +/- 0.002462 | 0.953067 +/- 0.012823 | -0.036054 +/- 0.013693 | G<P: 5/5 |
| roc_auc | 0.999052 +/- 0.000425 | 0.995107 +/- 0.003334 | -0.003945 +/- 0.003657 | G<P: 5/5 |
| pr_auc | 0.999189 +/- 0.000310 | 0.995948 +/- 0.002399 | -0.003241 +/- 0.002643 | G<P: 5/5 |

Per-seed XGBoost deltas:

| Seed | Delta F1 malicious | Delta F1 macro | Delta MCC |
| --- | --- | --- | --- |
| 42 | -0.017611 | -0.015818 | -0.030968 |
| 43 | -0.025858 | -0.023060 | -0.044690 |
| 44 | -0.017406 | -0.015644 | -0.030545 |
| 45 | -0.022753 | -0.020338 | -0.039566 |
| 46 | -0.007056 | -0.006363 | -0.012496 |

XGBoost G-test F1 and MCC are below P-test values for all five observed seeds (`G<P: 5/5` for both metrics). This is a descriptive five-seed direction pattern, not a significance result.

## 9. Model sensitivity and GaussianNB behavior

For malicious-positive F1 and MCC, Random Forest and Decision Tree both have G<P on all five seeds. Logistic Regression has the largest mean absolute P-versus-G F1 and MCC changes among the non-GNB models in this fixed study (F1 0.039015; MCC 0.058158).

GaussianNB behaves differently: its G-test F1 malicious, F1 macro, and MCC exceed the P-test values on all five seeds, while its variability is materially larger than the other models for these measures. This is reported as model behavior under the fixed configurations, not as an implementation defect or a tuning target.

## 10. Is seed 42 representative of the observed five-seed range?

Seed 42 lies within every reported five-seed range by construction; the relevant descriptive question is whether it has the same direction and a similar magnitude. The seed-42 deltas and observed ranges are:

| Model | Seed-42 Delta F1 | Five-seed Delta F1 range | Seed-42 Delta MCC | Five-seed Delta MCC range |
| --- | --- | --- | --- | --- |
| Logistic Regression | -0.037785 | [-0.048747, -0.032438] | -0.054451 | [-0.072701, -0.048515] |
| Random Forest | -0.018429 | [-0.027815, -0.011541] | -0.031991 | [-0.047975, -0.020405] |
| Decision Tree | -0.021867 | [-0.022031, -0.010123] | -0.038169 | [-0.038169, -0.018066] |
| GaussianNB | 0.059755 | [0.008060, 0.071074] | 0.146755 | [0.015632, 0.165512] |
| XGBoost | -0.017611 | [-0.025858, -0.007056] | -0.030968 | [-0.044690, -0.012496] |

For LR, RF, DT, and XGBoost, seed 42 has the same G<P direction as all five F1/MCC observations. GNB has the opposite G>P direction on all five. Magnitudes vary across the five splits, so seed 42 should be treated as one representative directional observation, not as a complete estimate of split uncertainty.

## 11. Stability questions

- **A/B - XGBoost:** G-test F1 and MCC remain below P-test on all five seeds.
- **C - RF and DT:** their F1 and MCC degradations are directionally stable (G<P on all five seeds).
- **D - LR sensitivity:** LR has larger mean absolute F1/MCC protocol differences than RF, DT, and XGBoost in this fixed experiment.
- **E - GNB:** GNB remains systematically different, with G>P in F1/MCC and larger seed variability.
- **F - seed 42:** it matches the five-seed direction pattern for every model's F1/MCC comparison, but it does not replace the observed range or variability summary.

## 12. Runtime

Training and inference timings are recorded per run but are secondary. They were not compared across seeds as performance findings and are not directly comparable with paper timings because hardware and software differ.

## 13. Threats to validity

- Only five deterministic split seeds were evaluated.
- Model randomness was intentionally fixed at 42, so split variability and model stochasticity are not jointly estimated.
- Protocol P and G have different train/test proportions, and Protocol G has smaller training partitions.
- Protocol G tests feature-vector disjointness only; it is not temporal or cross-dataset generalization.
- The public CSV lacks original PDF SHA-256 values, so feature-equivalent groups are not proven duplicate PDF files.
- Hyperparameters and several preprocessing details remain fixed project assumptions where the paper is incomplete.
- No statistical significance tests, p-values, bootstrap intervals, or confidence intervals were calculated.

## 14. Main findings and follow-up

Within this frozen five-seed design, the P-to-G decline for LR, RF, DT, and XGBoost is directionally stable for F1/MCC, while GNB changes in the opposite direction and varies more. These findings justify reporting both protocols separately; they do not establish one protocol as more realistic or generalizable in every operational setting.

A future study may separately preregister model-randomness sensitivity, external-dataset evaluation, temporal evaluation, calibration analysis, or an appropriately justified inferential design. It must not retroactively tune this completed baseline matrix.
