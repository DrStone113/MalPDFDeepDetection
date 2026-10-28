# Agent Dataset Protocols and Provenance

This document specifies the dataset partitioning standards, data leakage prevention constraints, experiment tracking formats, and research logging requirements for `MalPDFDeepDetection`.

## 1. Dataset Partitioning Discipline (Protocol G)

- **Canonical Split:** Maintain the canonical **Protocol G** partition manifest (deterministic group-aware split, seed `42`) for historical consistency unless explicitly directed otherwise.
- **Strict Leakage Prevention:** Preprocessing and feature normalizers must fit **exclusively on the training split**. Validation splits are reserved for thresholding, calibration, and hyperparameter tuning. Test data remains untouched until final evaluation.

---

## 2. Experiment Tracking and Run Artifacts

All experimental runs must be recorded in an immutable run directory:

```
reports/experiments/<study>/run_<timestamp>_<commit>/
├── locked_methodology.json
├── metrics.json
└── ...
```

- Each run directory must contain `locked_methodology.json` capturing the full configuration, hyperparameters, feature set version, and Git commit hash.
- Run outputs must provide schema-validated metric files.

---

## 3. Benchmark Logging and Research Provenance

- **Append-Only Research Log:** Record verified benchmark outcomes, performance shifts, and model milestones in `reports/research_log.md`.
- **Integrity:** Never rewrite past benchmark entries or alter historical results without explicitly documenting the methodology correction.
