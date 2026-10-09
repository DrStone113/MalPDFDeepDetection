# Paired static byte-profile development — 2026-10-04

Adding fixed Markov summaries did not improve CIC discrimination in this locked trial. The structural-only development candidate won macro-cohort Validation MCC. Existing deployed checkpoints are unchanged.

| Variant | Validation cohort | Rows / groups | Accuracy | F1 malicious | MCC | AUROC | Brier | ECE |
|---|---|---|---|---|---|---|---|---|
| structural | raw | 730 / 437 | 0.998630 | 0.998095 | 0.997030 | 1.000000 | 0.013030 | 0.110952 |
| structural | cic | 48 / 29 | 0.562500 | 0.676923 | 0.130551 | 0.547826 | 0.285747 | 0.211882 |
| structural_markov | raw | 730 / 437 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.013852 | 0.098078 |
| structural_markov | cic | 48 / 29 | 0.520833 | 0.676056 | 0.008696 | 0.382609 | 0.309265 | 0.237595 |

Both variants retain all 40 structural inputs and ten missing flags. The augmented variant adds 33 unfitted descriptors of verified conditional byte transitions. Original float32 matrices, established partitions, Train folds, source labels and original Validation-role files were not changed. New deterministic development roles give CIC 29–30 groups per role; checkpoint loss gives equal mass to cohorts and to groups within a cohort.

CIC Train has 870 rows: raw 40-feature vectors collapsed to 501 groups, with 406 rows in mixed-label vectors. Adding summaries gives 870 distinct numeric profiles and no mixed-label profile groups. The 291 CIC Validation rows likewise become 291 distinct profiles. This removes representational collisions but does not make the measurements useful semantic evidence, prove file identity, or establish that any original labels were wrong.

CIC selection has 48 rows (25 malicious, 23 benign), in 29 saved groups. The structural stack produces TN=5, FP=18, FN=3, TP=22; the byte-profile stack gives TN=1, FP=22, FN=1, TP=24. Entropy referral rounds 10% to five rows (10.4167%, static coverage 89.5833%) in both variants and catches zero of their false negatives. Referral is not counted as a corrected decision and no dynamic analysis occurred.

These are retrospective Validation selection diagnostics; selection and Youden tuning use these rows. The earlier 53.125% result used a different 64-row subset and cannot be treated as a direct before/after benchmark. Previously exposed Test sets remain sealed; a future separately authorized independent cohort is needed to confirm generalization.

Kaggle completed 50 fits in 226.604 seconds of study execution, excluding queue/startup and output import. FT-Transformer used CUDA FP16 AMP on the recorded GPU; tree models used two CPU threads. Two bounded processes computed profiles directly from existing numeric inputs without expanding matrix caches or reading PDFs. No new dataset or sample data was uploaded. Fifty checkpoints remain in private Kaggle Output; only numeric evidence was downloaded.

Generating code: `7b3fc619480079024d3de11d6087296bcfddea11`; cloud study: `run_20261004T173738560718Z_7b3fc6194800`. Environment and 89 verified numeric files/96 sealed source files are recorded in `reports/experiments/static_development_validation/run_20261004T174302231060Z_7b3fc6194800/`. All 96 metric rows and 16 routing summaries were independently checked against aligned saved probabilities with round-trip CSV parsing. Label=1 malicious; ECE uses ten equal-width probability bins, p=1 in the last bin.

Next useful hypothesis: bounded decoded-stream and JavaScript AST evidence, or a separately designed domain-specific model. Coarse byte statistics alone were ineffective here; this trial provides no evidence that increasing model size or changing a threshold solves CIC evasion. Any new extraction/upload and study must preserve the existing safety and Validation/Test boundaries.
