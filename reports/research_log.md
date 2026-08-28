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
