# AGENTS.md

## Context Check

This repository is a Python 3.11 research project for malicious PDF detection.

- Before changing code, run `git status`, read `pyproject.toml` and `README.md`, and inspect the relevant package, scripts, configs, tests, and existing experiment reports. Preserve unrelated local changes.
- Check Python and declared dependencies with `python --version` and `python -m pip check`. Use Python 3.11 and install the project from `pyproject.toml` in a fresh virtual environment: `python -m pip install -e '.[dev]'`.

## Modular Boundaries

- Keep reusable loading, validation, static inspection, models, evaluation, and experiment logic inside `src/malpdf/`.
- Put small repeatable entry points in `scripts/` and versioned configuration without secrets in `configs/`. Never create standalone scripts at the project root. Keep notebooks exploratory and thin.
- Tests belong in `tests/` and use synthetic bytes, synthetic tables, or clearly benign fixtures only; they must not depend on network access, external datasets, execution order, or local machine state.

## Fail-Closed Safety

- Treat every unknown PDF as malicious. Inspect only untrusted bytes through binary reads such as `open(path, "rb")`, with resource limits and explicit validation failures. Never open a viewer, browser, office tool, or preview pane; never render PDFs or execute embedded files, JavaScript, macros, commands, URLs, or actions.
- **Never `git add`, force-add, or commit raw PDFs, datasets, matrix caches (`*.npy`), secrets, checkpoints, or binary model/generated artifacts.** Keep them under ignored `data/` or `artifacts/`; ensure `.gitignore` blocks `data/raw/`, `artifacts/`, `*.pdf`, and `*.npy` (empty `.gitkeep` placeholders are allowed). Check ignore coverage before staging.
- Never silently modify source data; write derived outputs under `data/processed/` or `artifacts/`. Dataset acquisition must be an explicit, documented human action; never download datasets automatically.
- Never upload samples, sample hashes, extracted content, or metadata to third-party services without explicit authorization.
- Dynamic analysis requires explicit approval of an isolated disposable sandbox with no shared folders, credentials, clipboard, or unrestricted network access. Referral recommendations do not authorize execution.

## YAGNI Decision Ladder

Before writing new code, apply this order: (1) YAGNI: establish that the task needs it; (2) reuse code in `src/malpdf/`; (3) use the standard library, scikit-learn, or the already declared PyTorch stack; (4) write only the minimum necessary code. Do not add frameworks without an explicit task requirement. Never remove validation, security checks, or error handling to simplify an implementation.

## Protocol G & Validation Lock

- Reuse and validate the saved Protocol G manifest: seed `42`, deterministic group-aware, approximately stratified train/validation/test partitions. Never regenerate an established split or allow identical feature-vector groups, known duplicate files, or related samples to cross partitions. Feature equivalence alone does not prove PDF-file identity.
- Route stochastic setup through `malpdf.reproducibility.set_random_seed`; use the existing deep-learning seed helper for PyTorch and record all seeds. Separately specified Protocol P, CV, or multiseed studies retain their own locked designs.
- Fit base models and preprocessing on **train only**. Use **validation only** for hyperparameter selection, early stopping, Isotonic/Platt calibration fitting, stacking meta-learner fitting/weights, and threshold/routing selection. Keep calibration/meta fitting and candidate selection on disjoint deterministic subsets of validation; select by validation MCC with the documented tie-breaker.
- Persist the methodology and validation decisions before test evaluation. Test remains independent and is evaluated once after the lock; never use test metrics to tune, choose, calibrate, or trigger favorable reruns.

## Immutable Provenance

- Never overwrite previous reports or run directories, especially `reports/experiments/selective_ensemble/`. New experiment invocations must automatically create a unique `reports/experiments/<study>/run_<UTC timestamp>_<commit hash>/` directory and refuse collisions.
- Every new run must contain `locked_methodology.json` and `model_comparison.csv`, plus config, package/environment versions, authorized dataset/split provenance and checksums, seeds, generating code commit, metrics, status/errors, and output paths. For a failed or interrupted run, preserve partial evidence and mark unavailable results explicitly.
- Official experiments start from a clean committed worktree. Record `git rev-parse HEAD`; maintenance checks on uncommitted changes must also record the dirty state. A commit cannot contain its own final hash; record the generating revision and use Git history for the later results commit.

## Living Docs (Definition of Done)

- Before handing off a task, run `pytest tests/`, `python -m pip check`, `git diff --check`, and `git status`. All tests must pass and dependencies must be consistent; report failures or blockers truthfully.
- Automatically append to `reports/research_log.md` after every experiment invocation, including completed, failed, and interrupted attempts, and after each maintenance task. Use its run-register schema: UTC timestamp, run ID, kind/status, protocol/seed, model, partition, malicious F1, MCC, ECE, Brier score, generating commit/worktree state, evidence paths, and checks/notes.
- Append one row per model and evaluated partition. Copy metrics only from saved evidence; use `N/A` with a reason for unavailable or inapplicable values. Define Label=1 as malicious and record the ECE binning convention. Never invent metrics, replace historical entries, or rerun experiments just to populate the log.
- Keep code, tests, relevant documentation, and the appended research log consistent. Inspect changed and staged paths for unsafe artifacts before any authorized commit; `git status` must show only intended task changes before handoff.

## GitHub Codespaces Boundary

- Codespaces is only a reproducible code-and-test environment. Its devcontainer installs dependencies solely from `pyproject.toml` and runs tests without datasets.
- Do not upload, download, decrypt, open, render, execute, or dynamically analyse untrusted PDFs there without separate explicit authorization. Keep credentials, tokens, raw samples, sample hashes, and extracted sample metadata out of Codespaces and Git history unless separately authorized.
- Containerisation is not proof of containment, and GPU availability is not guaranteed.
