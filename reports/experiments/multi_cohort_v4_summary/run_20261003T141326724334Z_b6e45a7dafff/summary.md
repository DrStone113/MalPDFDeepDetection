# Multi-cohort v4: completed retrospective adaptation

Both frozen v4 Test cohorts were evaluated once after the Validation lock.
Test A classification matches v3, while calibration is worse. On CIC Test B,
malicious F1 increases but Accuracy and MCC decline; v4 does not demonstrate
improved evasion discrimination. Brier, ECE and log loss improve on CIC.

| Cohort | Model | N | Accuracy | F1 malicious | MCC | Brier | ECE | Log loss |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| test_A_source_raw_4050 | stacking_v3 | 4050 | 0.999259 | 0.999335 | 0.998500 | 0.000507 | 0.022461 | 0.022718 |
| test_A_source_raw_4050 | stacking_v4 | 4050 | 0.999259 | 0.999335 | 0.998500 | 0.001104 | 0.032856 | 0.033421 |
| test_B_cic_291 | stacking_v3 | 291 | 0.549828 | 0.688836 | 0.033956 | 0.427299 | 0.425997 | 1.693097 |
| test_B_cic_291 | stacking_v4 | 291 | 0.546392 | 0.705357 | -0.023969 | 0.360648 | 0.342949 | 0.975835 |

CIC v4 confusion matrix (rows true [benign, malicious], columns predicted
[benign, malicious]): [[1, 130], [2, 158]]. Thus 288/291 samples are predicted
malicious at the Validation-selected threshold; malicious F1 alone is not
sufficient evidence of better discrimination.

Entropy referrals: source 405/4050, static coverage 90%, no false negatives
(FN catch rate unavailable); CIC 29/291, static coverage 90.034%, FN catch
0/2 = 0%. Referral does not correct predictions or execute a sandbox.

The established acquired raw-PDF source cohort is distinct from the historical
RIT feature table: unchanged source Train/Val/Test = 11931/3977/4050.
CIC split = 870/291/291, seed42, whole input-equivalence groups kept together.
CIC Test B contains only 31 groups across 291 rows. Both source and CIC v3
outcomes had been inspected before v4 design; this is a retrospective study,
not a fresh untouched confirmatory or zero-day benchmark. Published CIC
labels are preserved; no structural-token-based ground-truth reassignment.
The v3 comparison uses saved source metrics and saved CIC probabilities
restricted to the same 291 Test B rows; v3 models are not rerun.

Combined Train = 12801, Validation = 4268. Separate Validation roles:
base selection 1613, stacking fit 884, Platt fit 890, threshold selection881.
20 tree folds completed locally; five FT folds and Vision completed on Tesla T4
with FP16 AMP. FT training total 40.04743 seconds; Vision training 161.75075
seconds, best epoch3 of eight executed epochs, selected by base-selection loss.
All 21414 unchanged float32 Markov matrices were loaded into one RAM block.
Kaggle-managed runtime: Python3.13.15, torch2.11.0+cu128, torchvision0.26.0+cu128,
sklearn1.6.1. Its versions are recorded separately from the local project
Python3.11 environment; GPU bit-identical reproduction is not guaranteed.

Storage: 3.4869 GiB reclaimed from pip download cache and this task's incomplete
ZIP. Raw PDF files, matrix caches, all previous checkpoints and reports retained.
The v4 delta ZIP is 38.706 MiB and reuses the existing 19962-matrix Kaggle input;
upload staging uses hard links, not a duplicate archive. GPU output imports
are retained in ignored checkpoints. The initial read-only-mount bootstrap
failure and transient dataset-readiness failure are recorded separately; neither
produced a model or Test evaluation, and no locked training setting was changed.

Validation threshold: 0.06252524495771992; Label1=malicious.
ECE uses ten equal-width probability bins, p=1 in the last bin.
All 531 offline unit tests pass (two existing synthetic single-class warnings),
pip check clean and Git diff checks pass. Source files match the full-suite
snapshot; existing unrelated main worktree changes are preserved.

Evidence: reports/experiments/multi_cohort_v4_evaluation/run_20261003T140953193222Z_b6e45a7dafff.
The generating committed code is b6e45a7dafff642cca0e4d277882894504d7ea46.
