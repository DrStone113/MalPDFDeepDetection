# AGENTS.md

## Context Check & VM Environment

This repository is a Python research project for malicious PDF detection running on a dedicated Virtual Machine (VM) with full support for local and GPU-accelerated workflows (Python 3.11–3.13).

- Before changing code, run `git status`, read `pyproject.toml`, `README.md`, and the relevant files in `docs/` and `plans/`, and inspect the target modules in `src/malpdf/`, `scripts/`, `configs/`, `tests/`, and `reports/`. Preserve unrelated local changes.
- Verify Python and declared dependencies with `python --version` and `python -m pip check`. Use the active VM environment (`.venv/`) configured from `pyproject.toml`, installing CPU or CUDA PyTorch wheels appropriate for the host hardware. Record effective Python, library, and hardware/CUDA versions in experiment outputs.

## Modular Boundaries & Workspace Organization

Respect the established roles of the repository's top-level directories instead of mixing outputs or creating parallel structures:

- `src/malpdf/`: Reusable loading, validation, static inspection, feature extraction, models, evaluation, reproducibility, and experiment logic.
- `scripts/` & `configs/`: Repeatable CLI entry points in `scripts/` and versioned configuration without secrets in `configs/`. Never create standalone scripts at the project root.
- `tests/`: Deterministic tests using synthetic bytes, synthetic tables, or clearly benign fixtures only; they must not depend on network access or external execution order.
- `docs/` & `plans/`: Maintain technical documentation, development guides, workflow specs, migration notes, and project status in `docs/`, and design/feature plans in `plans/`. Keep the root `README.md` as a concise, stable overview; record ongoing technical changes and architectural rationale in `docs/` rather than modifying `README.md`.
- `notebooks/`: Exploratory and training notebooks (kept thin, delegating reusable logic to `src/malpdf/`).
- `data/` & `checkpoints/`: Ignored storage for datasets (`data/raw/`, `data/processed/`, `data/external/`) and model checkpoints/weights (`checkpoints/`).
- `reports/`: Structured research outputs (`experiments/`, `analysis/`, `tables/`, `figures/`, `progress/`, `deployment/`, `thesis/`, `checklists/`) and the append-only run register `reports/research_log.md`.
- `artifacts/`: Ignored local runtime storage for reusable binary/matrix caches (such as `markov_cache`) and temporary scratch data (`tmp/`).
  - Route notebooks, checkpoints, processed datasets, documentation, and formal experiment/evaluation outputs to their dedicated top-level directories (`notebooks/`, `checkpoints/`, `data/`, `docs/`, `reports/`) rather than duplicating them into `artifacts/`.
  - Group local runtime outputs cleanly under stable domain subdirectories or configured cache paths instead of spawning ad-hoc top-level `artifacts/` folders. Never create virtual environments or full source-tree copies inside `artifacts/`.

## Code Hygiene & Zero-Comment Policy

- **No Comments in Code**: Never write inline comments, block comments, or commented-out code (`# ...`) in `src/malpdf/`, `scripts/`, or `tests/`. Code must be self-documenting through clear variable/function naming, explicit type annotations, and small modular functions. Place all design rationale, tricky parser details, and workflow explanations in `docs/` or `plans/`.
- **YAGNI Decision Ladder**: Before writing new code, apply this order: (1) confirm the task requires it; (2) reuse or refactor code in `src/malpdf/`; (3) use the standard library, scikit-learn, or the declared PyTorch stack; (4) write concise, self-explanatory code. Do not add external frameworks without an explicit requirement.
- **Continuous Synchronization**: Whenever implementation or workflow behavior changes in `src/malpdf/`, `scripts/`, or `configs/`, update the corresponding tests in `tests/` and technical documentation in `docs/` in the same task.

## Static Binary Safety & Git Hygiene

- Treat unknown PDFs as untrusted binary inputs. Inspect bytes only via static binary reads such as `open(path, "rb")`. Never open a PDF viewer, browser, office tool, or preview pane, and never render PDFs or execute embedded files, JavaScript, macros, commands, URLs, or actions.
- **Never `git add`, force-add, or commit raw PDFs, datasets, matrix caches (`*.npy`), secrets, checkpoints, or binary model/generated artifacts.** Keep them under ignored `data/`, `checkpoints/`, or `artifacts/`; ensure `.gitignore` blocks `data/raw/`, `artifacts/`, `checkpoints/`, `*.pdf`, and `*.npy` (empty `.gitkeep` placeholders are allowed).
- Never silently overwrite raw source files in `data/raw/`; write derived features and processed outputs under `data/processed/` or `artifacts/`.

## Iterative Development & Split Integrity

- **Unblocked Iteration**: Historical results, previously saved `locked_methodology.json` files, and earlier baseline configurations must **never** block developing, refactoring, replacing, or experimenting with new feature extractors, feature selection/pruning, preprocessing pipelines, model architectures, calibration methods, thresholds, or ensemble designs.
- **Canonical Partition Boundary**: Reuse the Protocol G split manifest (seed `42`, deterministic group-aware, approximately stratified train/validation/test partitions) so new improvements remain directly comparable against historical baselines. Route stochastic setup through `malpdf.reproducibility.set_random_seed` and record active seeds. New splitting protocols or cross-validation schemes may be introduced when explicitly exploring new experimental designs.
- **Leakage Prevention**: Fit base models and preprocessing transforms on **train** only. Use **validation** for hyperparameter tuning, feature ablation, early stopping, calibration fitting, stacking meta-learner fitting, and routing/threshold optimization. Keep calibration/meta fitting and candidate selection on disjoint validation subsets when training stacked ensembles. Evaluate **test** cleanly without leaking test statistics into training or validation transforms.

## Experiment Provenance & Non-Blocking Execution

- **Active Worktree Execution**: Experiments, ablations, and development runs may execute directly from an active VM worktree without requiring a clean git commit beforehand. Record `git rev-parse HEAD` alongside a worktree dirty flag in run metadata so provenance remains transparent during rapid iteration.
- **Run Output Organization**: Official benchmark runs create a timestamped `reports/experiments/<study>/run_<UTC timestamp>_<commit hash>/` directory containing `locked_methodology.json` (recording the active run's configuration) and `model_comparison.csv`, preserving prior benchmark folders for comparison. During iterative development, scratch runs and cache updates may freely overwrite temporary files under `artifacts/` or designated dev output paths.

## Full-Performance VM Execution & Threat Analysis

- **No Artificial Performance Limits**: Because development and experiments run on a dedicated VM, do not impose restrictive CPU core quotas, process-count caps, memory throttles, single-thread BLAS locks, or artificial per-file byte/timeout limits that bottleneck static extraction, matrix caching, or model training.
- **Maximize Hardware Utilization**:
  - Run full datasets, feature extraction, tabular models, stacking ensembles, and deep-learning pipelines directly on the VM using all available CPU cores and GPU hardware.
  - Scale static extraction and cache generation across available CPU cores with multiprocessing while preserving parser exception isolation so malformed PDFs fail gracefully without crashing worker pools.
  - For vision and deep-learning runs, preload verified `float32` matrices into RAM, use persistent workers (`num_workers > 0`), pinned memory, non-blocking device transfers, and mixed precision (FP16/BF16 AMP with gradient scaling) when GPU acceleration is available. Preserve raw Markov `float32` probabilities without `uint8` casting or secondary normalization.
- **Flexible Feature Engineering & Threat Coverage**:
  - Security, structural, and statistical features may be freely added, combined, transformed, or pruned based on validation metrics and ablation studies.
  - When analyzing specific PDF threat vectors (JavaScript, embedded payloads, launch/actions, forms, font/image decoders, RichMedia, URI phishing, steganography), ground coverage claims in labeled evaluation evidence.

## Living Docs (Definition of Done)

- Before handing off a task, run `pytest tests/`, `python -m pip check`, `git diff --check`, and `git status`. All tests must pass, dependencies must be consistent, and all modified code files must contain zero comments.
- Verify that `tests/` and `docs/` reflect current implementation changes and that `git status` shows no untracked binary artifacts or raw data files.
- Append completed benchmark results to `reports/research_log.md` using its schema (UTC timestamp, run ID, kind/status, protocol/seed, model, partition, malicious F1, MCC, ECE, Brier score, commit/worktree state, evidence paths, and notes), copying only measured metrics from saved outputs (`Label=1` as malicious).

## Static Binary Safety, Lab Isolation & Agent Execution Guardrails

- **Untrusted Malware Handling**: Treat all files in `data/raw/` and `data/external/` as live, hostile malware payloads. Inspect bytes solely via pure-Python static binary reads (`open(path, "rb")`) inside `src/malpdf/`. Never invoke external PDF viewers, browsers, office suites, thumbnailers, Ghostscript, Poppler, `pdftotext`, `qpdf`, or shell utilities on PDF files, and never execute embedded payloads, JavaScript, macros, shell commands, URLs, or launch actions.
- **Strict Lab Isolation Gate for Live Samples**:
  - **NEVER autonomously run extraction, scanning, preprocessing, or debugging commands against `data/raw/`, `data/external/`, or any real `.pdf` corpus during code editing or verification.**
  - All automated verification by the agent MUST run exclusively against in-memory synthetic byte fixtures via `pytest tests/`.
  - Executing scripts that touch `data/raw/` or real PDF corpora is ONLY permitted when:
    1. The user explicitly instructs the agent to run a specific extraction/experiment command in the current prompt, AND
    2. Lab isolation is confirmed via `MALPDF_LAB_ISOLATED=1` in the environment (offline/sandboxed VM state verified).
  - Never inspect or sample random files from `data/raw/` using ad-hoc `python -c` snippets or shell commands to "see what the data looks like".
- **Git & Artifact Hygiene**:
  - **Never `git add`, force-add, or commit raw PDFs, datasets, matrix caches (`*.npy`), secrets, checkpoints, or binary model/generated artifacts.** Keep them under ignored `data/`, `checkpoints/`, or `artifacts/`; ensure `.gitignore` blocks `data/raw/`, `artifacts/`, `checkpoints/`, `*.pdf`, and `*.npy` (empty `.gitkeep` placeholders are allowed).
  - Never silently overwrite raw source files in `data/raw/`; write derived features and processed outputs under `data/processed/` or `artifacts/`.