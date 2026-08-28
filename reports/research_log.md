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
