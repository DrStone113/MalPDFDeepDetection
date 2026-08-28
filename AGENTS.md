# AGENTS.md

## Scope and architecture

This repository is a Python 3.11 research project for malicious PDF detection.

- `src/malpdf/data/`: inert data loading, validation, and feature extraction code.
- `src/malpdf/models/`: classical machine-learning models and training code.
- `src/malpdf/evaluation/`: metrics and evaluation utilities.
- `configs/`: version-controlled experiment configuration without secrets.
- `scripts/`: small, repeatable entry points built on package APIs.
- `tests/`: fast unit tests that use synthetic, benign fixtures only.
- `data/`, `artifacts/`, and generated report outputs: local-only, ignored storage.

Keep reusable logic inside `src/malpdf`. Keep notebooks exploratory and thin. Do not add deep-learning frameworks unless a later task explicitly requires them.

## Reproducibility rules

1. Use Python 3.11 and install the project from `pyproject.toml` in a fresh virtual environment.
2. Route stochastic behavior through `malpdf.reproducibility.set_random_seed`; record the seed in every experiment.
3. Record config, package versions, dataset provenance/hash, code revision, metrics, and output paths for each experiment.
4. Never silently modify source data. Derive outputs into `data/processed/` or `artifacts/`.
5. Keep train/validation/test splits deterministic and prevent duplicate files or related samples from crossing splits.
6. Tests must not depend on network access, external datasets, execution order, or local machine state.
7. Do not download datasets automatically. Dataset acquisition must be an explicit, documented human action.

## Malware-safety rules

1. Treat every unknown PDF as malicious. Never open it in a desktop PDF viewer, browser, office tool, or preview pane.
2. Never execute embedded files, scripts, macros, JavaScript, shell commands, URLs, or actions extracted from a PDF.
3. Analysis code must treat samples as untrusted bytes and perform static inspection only. Do not render PDFs in this baseline project.
4. Do not upload samples, hashes, extracted content, or metadata to third-party services without explicit authorization.
5. Keep samples outside Git under the ignored `data/` tree; never commit PDFs, datasets, secrets, checkpoints, or generated artifacts.
6. Unit tests must use synthetic byte strings or clearly benign fixtures, never live malware.
7. If dynamic analysis is later required, stop and obtain explicit approval for an isolated, disposable sandbox with no shared folders, credentials, clipboard, or unrestricted network access.
