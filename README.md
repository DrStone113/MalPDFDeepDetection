# MalPDFDeepDetection

A minimal Python 3.11 research project for reproducible malicious PDF detection experiments.

## Setup

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
malpdf --seed 42
```

Datasets are intentionally not downloaded by this project. Place approved samples under `data/` and follow the safety rules in `AGENTS.md`. Never execute or manually open suspicious PDFs.

## Research workflows

Create the paper-aligned Protocol P infrastructure without training models:

```powershell
.venv\Scripts\python.exe scripts\prepare_protocol_p.py --seed 42
```

Each invocation creates a new immutable run directory under `data/processed/protocol_p/` and `artifacts/protocol_p/`. Protocol P is a 75/25 row-level stratified split selected by the project; it is not an exact paper reproduction because the paper does not specify every seed, hyperparameter, or preprocessing decision. The existing Protocol G feature-vector-disjoint split remains separate.

Run the frozen 5-model x 2-variant Protocol P benchmark only from a clean, committed worktree. It reuses a saved matching Protocol P manifest and refuses to generate a replacement split:

```powershell
.venv\Scripts\python.exe scripts\run_protocol_p_benchmark.py --seed 42
```

The runner writes lightweight, commit-ready CSV/JSON/Markdown research reports to `reports/experiments/protocol_p/<run-id>/`; fitted model binaries are written only under ignored `artifacts/`. It does not tune hyperparameters, run multi-seed experiments, or perform cross-validation.

Run the feature-vector-disjoint Protocol G baseline only from a clean, committed worktree. It validates and reuses the saved train/validation/test manifest; it never regenerates the split:

```powershell
.venv\Scripts\python.exe scripts\run_protocol_g_benchmark.py --seed 42
```

Protocol G keeps identical static feature vectors within one partition. This is not evidence that PDF files themselves are duplicates, because the local CSV has no per-PDF hash field. The runner fits only train rows, evaluates validation and test once each, reuses Protocol P model configurations, and writes tracked reports to `reports/experiments/protocol_g/<run-id>/`; binary models remain ignored under `artifacts/`.

Create the formal, report-only Protocol P versus Protocol G comparison from the committed seed-42 result reports:

```powershell
.venv\Scripts\python.exe scripts\analyze_protocol_p_vs_g.py
```

The analysis validates source commits, dataset provenance, seeds, model/feature-variant pairings, and baseline report immutability before writing thesis tables under `reports/tables/protocol_p_vs_g/`, figures under `reports/figures/protocol_p_vs_g/`, and a Markdown report under `reports/analysis/`. It never reads raw PDFs, refits a model, regenerates a split, tunes, or changes Protocol P/G result files.

Audit paper Table 5 metric semantics from the committed P/G confusion matrices:

```powershell
.venv\Scripts\python.exe scripts\audit_metric_semantics.py
```

This report-only audit retains Label=1 malicious-positive metrics for operations, derives macro metrics from saved confusion matrices, and writes corrected paper-comparison tables under `reports/tables/metric_semantics/`. It does not alter historical Protocol P/G result files or refit models.

Preflight the fixed five-seed Protocol P versus Protocol G robustness study:

```powershell
.venv\Scripts\python.exe scripts\run_multiseed_robustness.py
```

The command is dry-run by default: it requires a clean worktree, verifies the dataset and completed seed-42 baselines, and creates no manifests, models, or results. The committed design varies only the split seed (`42, 43, 44, 45, 46`) while model stochasticity remains fixed at `42`; it evaluates the five frozen model configurations with P-drop3constant and G-drop3constant. A future, explicitly authorized official execution must add `--execute` and uses a new immutable `reports/experiments/multiseed/<run-id>/` directory. It reuses seed-42 baseline metrics rather than regenerating them, and writes new derived manifests only under ignored `data/processed/multiseed/`.

Preflight the separate paper-aligned XGBoost ten-fold cross-validation design:

```powershell
.venv\Scripts\python.exe scripts\run_xgb_cv10.py --dry-run
```

This command requires a clean committed worktree, uses the full verified 24,337-row numerical CSV, and checks a shuffled row-level `KFold(n_splits=10, random_state=42)` assignment. It is intentionally not Protocol P's 75/25 split or Protocol G's feature-vector-disjoint split, and seed 42 is a project choice rather than a paper-reported seed. The default is preflight-only and creates no results or fitted models. A future, explicitly authorized `--execute` run performs exactly 20 fixed XGBoost fits (ten folds for each of CV-all41 and CV-drop3constant), then writes immutable lightweight reports below `reports/experiments/xgb_cv10/<run-id>/`. It preserves documented semantic feature values, applies no scaling or tuning, and never writes model binaries.
