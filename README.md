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
