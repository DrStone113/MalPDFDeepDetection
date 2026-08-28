# Research log

## 2026-08-28 - Protocol P paper-aligned reproduction infrastructure

- Purpose: prepare reproducible, paper-aligned training infrastructure without model training.
- Added: Protocol P row-level split, feature variants, classical model factories, binary evaluation/runtime helpers, environment metadata, immutable run-output setup, CLI, and unit tests.
- Methodology: project-selected seed 42 with a 75/25 stratified row-level train/test split; no duplicate-feature grouping, tuning, multi-seed study, or cross-validation.
- Dataset: `rit-pdfmal-2026.csv`, SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Protocol affected: Protocol P only; Protocol G was not modified.
- Assumptions: paper seed, hyperparameters, full preprocessing details, and exact zero-variance handling are not specified; explicit project configurations are recorded per run.
- Validation: `.\\.venv\\Scripts\\python.exe -m pytest -q` - 20 passed; manifest invariants pass on the local dataset.
- Unresolved: per-PDF hashes are absent from the local CSV, so raw-file identity cannot be verified.
- Next: run a frozen, single-seed Protocol P baseline benchmark only when explicitly requested.

## 2026-08-28 - Protocol P Benchmark Runner

- Purpose: add an executable, provenance-complete baseline runner for the paper-aligned Protocol P matrix.
- Added: saved-manifest resolver/validator, 5-model x 2-variant execution layer, timing and metrics persistence, paper-comparison table generation, failure preservation, clean-Git guard, CLI, and synthetic unit tests.
- Methodology: requires the existing seed-42 row-level 75/25 Protocol P manifest; fits only training rows and evaluates each combination once on its held-out test rows. No split regeneration, tuning, multi-seed run, threshold tuning, or cross-validation.
- Protocol affected: Protocol P only; raw CSV, Protocol G, and the paper-alignment audit are not modified.
- Assumptions: paper seed, complete hyperparameters, preprocessing details, and exact zero-variance feature treatment remain unspecified; both feature variants are reported without claiming either exactly reproduces the paper.
- Validation: `.\.venv\Scripts\python.exe -m pytest -q` - 25 passed; `.\.venv\Scripts\python.exe -m pip check` - no broken requirements; `git diff --check` passed.
- Results: no official 10-run benchmark has been executed; generated result reports will be produced only from the committed runner.
- Next: commit this runner, then execute one clean-worktree seed-42 benchmark when authorized.

## 2026-08-28 - XGBoost execution compatibility correction

- Purpose: correct a blocking XGBoost 3.2.0 runtime incompatibility discovered during the initial official seed-42 execution attempt.
- Evidence: code SHA `925e3a1acf3bf26a17d05fbf3cf1ff3193788f2c` passed all split and checksum checks; eight non-XGB runs completed, while both XGB runs failed because the library rejects `missing=None` as JSON `Null` during prediction.
- Change: preserve the explicit XGBoost missing-value policy as IEEE `NaN`, serialized as `"NaN"` in configuration and converted only at estimator construction. No feature values, split, seed, preprocessing, or hyperparameters are changed.
- Validation: an XGBoost factory test now verifies the serialized and runtime missing-value representations.
- Status: the failed output is retained as execution evidence; a completed official baseline will use a new clean code commit and one fresh run after this correction.

## 2026-08-28 - Protocol P Seed-42 Baseline Results

- Purpose: execute the fixed, single-seed Protocol P paper-aligned reproduction attempt across the 5-model x 2-feature-variant matrix.
- Code and data provenance: code SHA `3e970ef2df0460fb4a51b10418c9af7564339419`; dataset `rit-pdfmal-2026.csv` SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`; seed 42; saved stratified row-level split (18,252 train, 6,085 test).
- Models and variants: Logistic Regression, Random Forest, Decision Tree, Gaussian Naive Bayes, and XGBoost; P-all41 and P-drop3constant. All 10 primary runs completed exactly once.
- Environment: Python 3.11.0; NumPy 2.4.6; pandas 2.3.3; scikit-learn 1.9.0; XGBoost 3.2.0; Intel Core i5-14400F; NVIDIA GeForce RTX 5060 Ti (8151 MiB); 16 GB RAM.
- Main metrics: XGBoost achieved F1 `0.991852` and MCC `0.985128` for both variants; RF P-all41 F1 `0.990379`; DT P-all41 F1 `0.983842`; LR F1 `0.924700`; GNB F1 `0.687852`.
- Variant comparison: dropping Acroform, Colors, and BaseEncoding left LR, GNB, and XGBoost classification metrics unchanged; RF/DT changes were below 0.0007 absolute F1/MCC.
- Paper comparison: XGB F1 differed by `0.003011` and RF F1 by `0.003654` for P-all41; GNB showed the largest divergence (precision `0.226798`, recall `0.339239`, F1 `0.097197`). Neither variant is claimed to be an exact paper configuration because zero-variance handling and other paper settings are incomplete.
- Limitations: this is one project-selected split seed, not a multi-seed study or cross-validation; runtime is hardware/software specific; Protocol G has not been benchmarked.
- Outputs: tracked reports under `reports/experiments/protocol_p/seed42/`; fitted binaries remain ignored under `artifacts/`. The pre-fix XGBoost failure record is retained separately for provenance.
- Next: inspect Protocol P results, then run the pre-existing Protocol G benchmark under its separate duplicate-feature-disjoint protocol.

## 2026-08-28 - Protocol G Benchmark Runner

- Purpose: add an executable fixed-baseline runner for feature-vector-disjoint generalization without running the official benchmark yet.
- Methodology: reuse the immutable seed-42 Protocol G manifest (train 14,602 rows/8,600 groups; validation 4,868/3,386; test 4,867/3,385; 24,337 rows and 15,371 groups total). Models fit only train; validation and test are each evaluated once without tuning, threshold selection, or model selection.
- Terminology: groups represent identical static feature vectors (feature-equivalent groups), not proven duplicate PDF files; the local CSV lacks per-PDF SHA-256 hashes.
- Reuse: Protocol P model factories, preprocessing, missing-value compatibility handling, binary metrics, timing, environment metadata, and fixed configurations are used unchanged.
- Leakage protections: hard preflight verifies manifest checksum/provenance, all rows and sample IDs, labels, group label purity, group overlap, and exact feature-vector partition disjointness before any fit.
- Validation: `.\.venv\Scripts\python.exe -m pytest -q` - 34 passed; `.\.venv\Scripts\python.exe -m pip check` - no broken requirements; `git diff --check` passed. Static preflight also verified the saved manifest SHA-256 `802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21` and all expected leakage/split invariants.
- Results: no official Protocol G metrics have been generated.
- Next: commit this runner, then run the seed-42 Protocol G baseline from the resulting clean code commit when explicitly requested.

## 2026-08-28 - Protocol G Seed-42 Baseline Results

- Purpose: execute the fixed feature-vector-disjoint generalization baseline and measure the effect of preventing identical static feature representations from crossing train, validation, and test partitions.
- Benchmark-generating code commit: `c2aefaaca8cd2257ed610efeba88f24a7cbbb460` (`feat(protocol-g): add feature-disjoint benchmark runner`); clean Git state at experiment start. Dataset: `rit-pdfmal-2026.csv`, SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`; seed 42; manifest SHA-256 `802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21`.
- Split: train 14,602 rows / 8,600 feature-equivalent groups (Label 0: 7,941; Label 1: 6,661); validation 4,868 / 3,386 (2,647; 2,221); test 4,867 / 3,385 (2,647; 2,220); total 24,337 rows / 15,371 groups. All hard manifest, label-purity, row-coverage, and feature-vector-disjointness checks passed.
- Matrix: Logistic Regression, Random Forest, Decision Tree, Gaussian Naive Bayes, and XGBoost with G-all41 and G-drop3constant; all 10 fixed configurations completed once. Models fit only train; validation and test were evaluated with the same fitted model; no tuning, threshold selection, split regeneration, cross-validation, or retraining occurred.
- Environment: Python 3.11.0; NumPy 2.4.6; pandas 2.3.3; scikit-learn 1.9.0; XGBoost 3.2.0; Intel Core i5-14400F; NVIDIA GeForce RTX 5060 Ti (8151 MiB); 16 GB RAM. Full seven-metric validation/test tables, confusion matrices, timings, and P-vs-G comparisons are recorded under `reports/experiments/protocol_g/seed42/`.
- Main validation/test results (F1 / MCC): LR all41 `0.897362 / 0.826399` -> `0.886647 / 0.807959`; LR drop3 `0.897362 / 0.826399` -> `0.886915 / 0.808348`; RF all41 `0.977727 / 0.960340` -> `0.970874 / 0.948671`; RF drop3 `0.973945 / 0.953946` -> `0.971587 / 0.949869`; DT all41 `0.944575 / 0.904299` -> `0.965802 / 0.938668`; DT drop3 `0.937869 / 0.893686` -> `0.961804 / 0.931732`; GNB both variants `0.756206 / 0.515290` -> `0.747607 / 0.494884`; XGB both variants `0.978032 / 0.960580` -> `0.974241 / 0.954161`.
- Protocol P versus G test F1 / MCC change (G minus P): LR all41 `-0.038052 / -0.054840`, LR drop3 `-0.037785 / -0.054451`; RF all41 `-0.019506 / -0.033853`, RF drop3 `-0.018429 / -0.031991`; DT all41 `-0.018040 / -0.031555`, DT drop3 `-0.021867 / -0.038169`; GNB both variants `+0.059755 / +0.146755`; XGB both variants `-0.017611 / -0.030968`.
- Observations: XGB G-all41 had the highest test F1 (`0.974241`) and MCC (`0.954161`). Removing the three zero-variance features gave identical XGB/GNB classification metrics, small LR/RF changes, and lower DT F1/MCC. No configuration failed and the runner reported probability-based scores for all metrics requiring continuous scores. Feature-equivalent groups denote identical static vectors, not duplicate PDF files.
- Limitations: one project-selected seed and one saved feature-vector-disjoint split; runtime is environment-specific; Protocol G is not file-identity analysis because the CSV lacks per-PDF hashes. Protocol P and Protocol G are distinct evaluation protocols, so their comparison is descriptive rather than an exact reproduction claim.
- Next: review this locked baseline before authorizing any separate multi-seed, cross-validation, or further protocol study.

## 2026-08-28 - Protocol P vs Protocol G Comparative Analysis

- Purpose: formally compare the completed seed-42 Protocol P row-level and Protocol G feature-vector-disjoint baselines without running a new experiment.
- Sources: Protocol P result commit/tag `ed50bd9e4e9cd0268c9e2359a89a1867dad68095` / `v0.3.0-protocol-p-baseline` (benchmark code `3e970ef2df0460fb4a51b10418c9af7564339419`); Protocol G result commit/tag `30b4e1b676a674424e004035fc8ffb8d9c615ad6` / `v0.4.0-protocol-g-baseline` (benchmark code `c2aefaaca8cd2257ed610efeba88f24a7cbbb460`); dataset SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Methodology: the analysis script verifies committed source-report identities, seed 42, dataset provenance, model/variant pairings, and benchmark-generating commits, then derives deltas, normalized confusion-matrix rates, tables, figures, and the formal Markdown report. No model fitting, refitting, split regeneration, tuning, threshold adjustment, or baseline-result modification occurred.
- Main findings: relative to Protocol P test, Protocol G test F1/MCC declined for LR, RF, DT, and XGB pairings; XGB had the smallest mean absolute F1/MCC change among those models (0.017611 / 0.030968), while LR had the largest (0.037919 / 0.054645). GaussianNB instead increased from F1/MCC 0.687852 / 0.348129 to 0.747607 / 0.494884, while retaining high recall and 1,313 false positives on Protocol G test.
- Constant features: removing Acroform, Colors, and BaseEncoding produced exact recorded classification-metric equality for GNB/XGB, small changes for LR/RF, and a lower G Decision Tree F1/MCC by 0.003998 / 0.006936. This is limited to the fixed dataset and experiment.
- Limitations: Protocol P/G have different split ratios and training-set sizes; Protocol G concerns identical static feature vectors rather than PDF-file identity, temporal shift, or external generalization; only seed 42 is available; paper-unspecified model settings are project assumptions; no statistical uncertainty has been quantified.
- Outputs: `reports/analysis/protocol_p_vs_g_analysis.md`, five CSV tables under `reports/tables/protocol_p_vs_g/`, and six thesis figures under `reports/figures/protocol_p_vs_g/`.
- Next: review the fixed-protocol findings before authorizing a separately designed multi-seed, cross-validation, score-distribution, calibration, or external-dataset investigation.

## 2026-08-28 - Paper Metric Semantics Correction

- Discovery: local completed experiments correctly use Label=1 (malicious) as the operational positive class, but numerical reconstruction of the paper's GNB evidence shows that Table 5 Precision, Recall, and F1 are macro-averaged across benign and malicious classes.
- Numerical evidence: paper test counts 3,309 benign / 2,776 malicious and reconstructed GNB counts TN=1,052, FP=2,257, FN=44, TP=2,732 yield macro Precision `0.753729`, Recall `0.651035`, and F1 `0.590655` within `1e-6` of Table 5. The corresponding malicious-positive values (`0.547605`, `0.984150`, `0.703670`) do not match Table 5.
- Correction: paper Accuracy remains compared with local Accuracy; paper Table 5 Precision/Recall/F1 are now compared with local macro metrics. Historical local `precision`/`recall`/`f1` are retained as backward-compatible malicious-positive aliases, with explicit `*_malicious` and `*_macro` fields available for future result schemas.
- GNB impact: Protocol P all41 local macro Precision/Recall/F1 are `0.747913` / `0.622215` / `0.545267`, yielding paper-aligned local-minus-paper deltas `-0.005816` / `-0.028820` / `-0.045388`; the former malicious-positive comparison conflated metric semantics with residual experimental differences.
- Scope: no model was refit, no prediction or split was changed, and the committed Protocol P/G baseline result files were verified unchanged. The local P-versus-G comparison remains valid because both sides use the same malicious-positive definition.
- Outputs: supplemental correction report under `reports/analysis/paper_metric_semantics_correction.md` and five tables under `reports/tables/metric_semantics/`.
- Next: use the corrected mapping for future paper-aligned reporting, then separately investigate residual differences with preregistered multi-seed or external-evaluation designs only when authorized.

## 2026-08-28 - Multi-seed Robustness Infrastructure

- Purpose: prepare a fixed, reproducible split-sensitivity study for the completed Protocol P versus Protocol G baselines without executing a new official benchmark.
- Added: committed five-seed configuration, preflight-only-by-default CLI, immutable output paths, Protocol P/G seed-manifest generation for future seeds, seed-42 baseline reuse, explicit malicious and macro metric schema, aggregation, paired G-minus-P deltas, and synthetic tests.
- Methodology: official split seeds are `42, 43, 44, 45, 46`; only split assignment varies. `model_random_state` remains fixed at `42` for stochastic models. The canonical matrix is five classical models with P-drop3constant and G-drop3constant; P evaluates test and G evaluates validation/test after train-only fitting.
- Dataset: future execution requires `rit-pdfmal-2026.csv` SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623` and revalidates immutable seed-42 P/G manifests and reports.
- Protocol affected: planned Protocol P/G robustness comparison only; existing completed Protocol P/G baseline reports and manifests remain unchanged.
- Assumptions: the five deterministic seeds and fixed model random state are project choices, not paper settings. Protocol G concerns identical static feature vectors, not proven duplicate PDF files.
- Validation: infrastructure tests use synthetic numerical fixtures; no official multi-seed models, metrics, or result reports have been generated.
- Unresolved: multi-seed findings are intentionally unavailable until a separately authorized clean-worktree `--execute` run completes.
- Next: review and commit the fixed infrastructure; later, if authorized, execute the exact committed matrix once and retain failed-run evidence without rerunning for favorable results.

## 2026-08-28 - Official Multi-seed P-vs-G Robustness Results

- Purpose: descriptively assess split-assignment sensitivity of the completed Protocol P versus Protocol G baselines without tuning or changing their fixed model configurations.
- Benchmark provenance: generating code commit `2147d0a1e12162ac7092fe797260f0c12a5fe3d6`; dataset `rit-pdfmal-2026.csv` SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`; clean worktree at start.
- Design: split seeds `42, 43, 44, 45, 46`; `model_random_state=42` for every supported stochastic model; canonical P-drop3constant and G-drop3constant variants only; five fixed classical model families. Label=1 remains malicious-positive and macro metrics are retained separately.
- Execution: dry-run command `\.venv\Scripts\python.exe scripts\run_multiseed_robustness.py --dry-run`; official command `\.venv\Scripts\python.exe scripts\run_multiseed_robustness.py --execute --run-id official-seeds42-46`. Ten completed seed-42 records were reused unchanged; 40 new seed-43--46 models were fit; all 50 records completed with no failures.
- Aggregate test F1 malicious / MCC (mean +/- sample SD), P -> G: LR `0.924197 +/- 0.002575 / 0.861754 +/- 0.005196` -> `0.885181 +/- 0.008665 / 0.803596 +/- 0.014341`; RF `0.991990 +/- 0.001280 / 0.985408 +/- 0.002308` -> `0.971353 +/- 0.005809 / 0.949635 +/- 0.009763`; DT `0.985993 +/- 0.001871 / 0.974192 +/- 0.003453` -> `0.968615 +/- 0.006404 / 0.943714 +/- 0.011046`; GNB `0.695594 +/- 0.009136 / 0.369622 +/- 0.024949` -> `0.737193 +/- 0.032013 / 0.468212 +/- 0.077691`; XGB `0.992588 +/- 0.001214 / 0.986435 +/- 0.002201` -> `0.974451 +/- 0.006691 / 0.954782 +/- 0.011425`.
- Key paired G-test minus P-test deltas: LR F1/MCC `-0.039015 +/- 0.006320 / -0.058158 +/- 0.010048`; RF `-0.020637 +/- 0.006187 / -0.035773 +/- 0.010464`; DT `-0.017378 +/- 0.005799 / -0.030478 +/- 0.009946`; GNB `+0.041599 +/- 0.026610 / +0.098590 +/- 0.063736`; XGB `-0.018137 +/- 0.007151 / -0.031653 +/- 0.012260`. LR/RF/DT/XGB have G<P F1 and MCC on all five seeds; GNB has G>P on all five.
- XGBoost focus: P-test F1 malicious/F1 macro/MCC means are `0.992588 / 0.993206 / 0.986435`; G-test means are `0.974451 / 0.976961 / 0.954782`. Its F1 and MCC directions are G<P for `5/5` split seeds; no threshold tuning occurred.
- Limitations: only five split seeds; model randomness is fixed rather than jointly varied; P/G have different partition proportions and G has smaller training partitions; G enforces feature-vector disjointness, not file identity, temporal, or cross-dataset generalization; public CSV lacks per-file hashes; no significance testing was performed.
- Outputs: immutable per-seed reports, aggregate tables, formal analysis, and five thesis figures are under `reports/experiments/multiseed/official-seeds42-46/`, `reports/analysis/`, and `reports/figures/multiseed/`. Historical P/G seed-42 reports and the metric-semantics correction remain unchanged.
- Next: review the descriptive multi-seed result set before deciding on a separately preregistered model-randomness, temporal, calibration, or external-dataset study.

## 2026-08-28 - XGBoost 10-Fold CV Infrastructure

- Purpose: prepare a reproducible XGBoost-only runner aligned to the paper's Algorithm 1 random 10-fold structure and Table 6 comparison, without executing an official CV experiment.
- Added: fixed YAML design, full-dataset KFold assignment/validation, CV-all41 and CV-drop3constant feature views, per-fold metrics/runtime/OOF report serialization, Table 6 comparison support, immutable output paths, clean-Git preflight CLI, and synthetic tests.
- Methodology: `KFold(n_splits=10, shuffle=True, random_state=42)` over all 24,337 rows; every row is test-held-out exactly once. The split seed and per-fold XGBoost `model_random_state=42` are project choices, not paper-reported settings. Protocol P and Protocol G manifests are neither read nor modified.
- Dataset: future execution requires `rit-pdfmal-2026.csv` SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623` and preserves all documented special feature values without scaling, clipping, imputation, or extra feature removal.
- Protocol affected: planned paper-aligned XGBoost CV only; existing Protocol P, Protocol G, comparative-analysis, and multi-seed outputs remain unchanged.
- Assumptions: the paper specifies random 10-fold CV but not its seed, CV stratification, full hyperparameters, or complete preprocessing details. The runner uses existing fixed XGBoost project settings and maps Table 6 Precision/Recall/F1 to explicitly reported local macro metrics under the documented metric-semantics correction.
- Validation: `.\.venv\Scripts\python.exe -m pytest -q` - 66 passed; new tests use synthetic numerical fixtures only.
- Results: no official folds, model binaries, metric results, or paper-reproduction claims were generated by this milestone.
- Next: commit the frozen runner; only a later explicit authorization may run the immutable 20-fit CV matrix from a clean benchmark-generating commit.

## 2026-08-28 - Official XGBoost 10-Fold CV Results

- Purpose: execute the committed paper-aligned XGBoost cross-validation attempt following the paper's Algorithm 1 random ten-fold structure and compare the aggregate results with Table 6.
- Provenance: benchmark-generating code commit `e5cb9bce8eef7bc26ea189d80fdd597fbecc3b43`, clean worktree at start; dataset `rit-pdfmal-2026.csv` SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Design: full 24,337-row row-level `KFold(n_splits=10, shuffle=True, random_state=42)`; `cv_split_seed=42`, fixed `model_random_state=42`, and 20 fits spanning CV-all41 and CV-drop3constant. This is neither Protocol P nor Protocol G.
- Results: all 20 fits completed; both variants have identical mean +/- sample SD Accuracy `0.993056 +/- 0.002212`, malicious F1 `0.992350 +/- 0.002456`, macro F1 `0.992995 +/- 0.002233`, ROC-AUC `0.999166 +/- 0.000473`, PR-AUC `0.999265 +/- 0.000329`, and MCC `0.986024 +/- 0.004462`.
- Paper comparison: local macro F1 is `-0.000279` below the Table 6 mean, Accuracy `-0.000822`, macro Precision `-0.002344`, and macro Recall `+0.001804`; paper P/R/F1 are compared with local macro metrics under the documented correction. Local sample standard deviations are larger, but the paper's standard-deviation normalization is not specified.
- Variant effect and variability: all classification/score metrics, OOF labels, and OOF scores are exactly equal between variants; fold 8 has the highest macro F1 (`0.995859`) and fold 6 the lowest (`0.989670`); the largest performance-metric fold range is MCC (`0.012367`).
- Outputs: lightweight reports and 24,337-row OOF records per variant are under `reports/experiments/xgb_cv10/seed42/`; formal analysis is `reports/analysis/xgb_cv10_analysis.md`; no fitted models were retained.
- Limitations: paper seed, full hyperparameters, zero-variance handling, preprocessing details, and standard-deviation normalization remain incomplete; row-level KFold permits equal feature vectors across folds and does not measure feature-disjoint, temporal, or external-dataset generalization; runtime is environment-specific.
- Next: review the CV result independently from Protocol G before authorizing any separate calibration, threshold, external-dataset, or generalization experiment.

## 2026-08-28 - CIC-Evasive-PDFMal2022 Dataset Audit and RIT Schema Alignment

- Purpose: perform a read-only audit of the local CIC-Evasive-PDFMal2022 tabular mirror and document an evidence-qualified future RIT-to-CIC feature schema alignment; no PDFs were opened and no model was trained or evaluated.
- Added: inert CIC CSV/Parquet discovery, loading, schema/quality validation, feature dictionary, audit CLI, RIT/CIC alignment utilities, alignment CLI, synthetic tests, tracked reports/tables, and `pyarrow>=14,<20` as a direct reproducible dependency.
- Dataset/provenance: local `PDFMalware2022.parquet`, SHA-256 `25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65`, third-party Kaggle mirror. Actual shape is 10,023 x 33 with `Class`: Benign 4,468 and Malicious 5,555. This differs from the official CIC page's 10,025 total / 5,557 malicious / 4,468 benign and is not claimed byte-identical to the official release.
- Methodology/findings: `FileName` is identifier-like; the local schema has 31 candidate predictors. No actual NaN, blank strings, exact duplicate rows, duplicate predictor vectors, label conflicts, constant columns, or near-constant columns were found. Observed negative/sentinel-like values and malformed categorical tokens remain unmodified and are explicitly reported. The future-only mapping has 6 EXACT, 0 documented-transform, 24 AMBIGUOUS, and 11 NO_MATCH RIT features; strict/transformable common space is `metadata_size`, `xref_length`, `title_length`, `embedded_files`, `trailer`, and `objstm` only.
- Protocol affected: no existing Protocol P, Protocol G, multi-seed, or CV protocol was changed. The mapping is documentation/provenance evidence, not authorization for cross-dataset evaluation, categorical encoding, label conversion, or feature selection.
- Assumptions/unresolved issues: proposed CIC `Benign -> 0`, `Malicious -> 1` is documentation-only; official CIC prose is internally inconsistent about feature count; the local mirror has a two-row/malicious-count discrepancy; RIT's local CSV lacks per-PDF hashes, so cross-dataset file identity/overlap cannot be proven. Ambiguous semantic mappings require documented review before any future experiment.
- Validation: `./.venv/Scripts/python.exe -m pytest -q` - 77 passed; `./.venv/Scripts/python.exe -m pip check` - no broken requirements. Tests use synthetic tabular fixtures only.
- Next: review the mirror discrepancy and conservative schema map before authorizing any separate, preregistered cross-dataset evaluation design.

## 2026-08-28 - CIC Source Fidelity and RIT Mapping Resolution

- Purpose: compare every local CIC tabular mirror read-only, assess source fidelity against CIC documentary invariants, and revisit the prior RIT-to-CIC ambiguous mappings without fitting a model or changing a source.
- Sources: `PDFMalware2022.csv`, SHA-256 `61686c9b323cb41bf8c048e5e4fe1e43eaf7d8d634667dc256a1349d6242b489`, 10,026 physical rows / 10,025 recognized-label rows (Benign 4,468; Malicious 5,557; one all-textual-`nan` row); and `PDFMalware2022.parquet`, SHA-256 `25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65`, 10,023 rows (Benign 4,468; Malicious 5,555). Both remain third-party mirrors; CSV platform metadata is unavailable and Parquet remains recorded as Kaggle.
- Fidelity: normalized schemas match, identifiers show all 10,023 Parquet records occur in CSV, and the two CSV-only records are malicious. The Parquet is not a strict record-wise subset: 893 shared rows differ semantically across 15 columns. CSV is `TRANSFORMED` because of its unexpected textual-`nan` pseudo-row; Parquet is `TRANSFORMED` with a `SUBSET_OR_TRUNCATED` population indicator because it is missing two malicious records and differs in shared values. No local copy has full source-fidelity qualification.
- Recommendation: CSV is only a provisional future candidate because its recognized labels reproduce the documentary class totals and it is the identifier superset, but the extra raw row and third-party provenance must be explicitly resolved in a separate methodology decision. No project data source was switched.
- Mapping resolution: previous counts 6 EXACT / 0 transformable / 24 AMBIGUOUS / 11 NO_MATCH; v2 is 6 / 0 / 19 / 16. `pdf_ver`, `obj`, `page_command`, `Encrypt`, and `EmbeddedFile` were reclassified to NO_MATCH from documented semantic differences or lack of CIC definitions. COMMON_STRICT and COMMON_TRANSFORMABLE remain the same six features: `metadata_size`, `xref_length`, `title_length`, `embedded_files`, `trailer`, and `objstm`.
- Methodology: malformed CIC tokens and sentinel-like values remain raw; no target-based or learned transform, coercion, imputation, encoding, model fitting, within-CIC evaluation, or cross-dataset classification occurred. A future six-feature strict baseline can be conservative/scientifically valid but is limited and cannot represent full detector capability.
- Validation: `./.venv/Scripts/python.exe -m pytest -q` - 84 passed; `./.venv/Scripts/python.exe -m pip check` - no broken requirements; `git diff --check` passed. Synthetic tests cover discovery, classifications, redaction, subset/value-difference evidence, mapping retention, deterministic ordering, and target-independent transforms.
- Next: review/resolve the CSV pseudo-row and obtain stronger publisher/source provenance before authorizing a separately committed strict six-feature cross-dataset protocol.
