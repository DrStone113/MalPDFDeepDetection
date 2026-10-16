# MalPDFDeepDetection

A Python research project for reproducible malicious PDF detection, combining
static feature models, byte Markov vision models, and validation-locked ensembles.

The project includes bounded static inspection, frozen-model inference,
calibration, explainability, and experiment provenance. Dynamic-analysis support
covers offline sandbox-report parsing and routing research.

Python 3.11 is the local/Codespace test baseline. Python 3.13 is also supported
for the authorized Kaggle GPU runtime.

## Documentation

Start with the [documentation index](docs/README.md).

| Topic | Reference |
| --- | --- |
| Installation, Codespaces, and verification | [Development guide](docs/development.md) |
| Pipelines, CLI commands, and configuration contracts | [Research workflows](docs/workflows.md) |
| Research progress, measured outcomes, and limitations | [Research status](docs/research_status.md) |
| Vietnamese progress presentation | [Offline HTML report](reports/progress/progress_report_2026-10-11.html) |
| Thesis methodology and saved evidence | [Thesis evidence index](reports/thesis/thesis_evidence_index.md) |
| Experiment and maintenance history | [Research log](reports/research_log.md) |
| Contribution and safety rules | [AGENTS.md](AGENTS.md) |

## Repository layout

| Directory | Purpose |
| --- | --- |
| `src/malpdf/` | Reusable loading, inspection, models, and experiment logic |
| `scripts/` | CLI entry points |
| `configs/` | Versioned experiment configurations |
| `tests/` | Deterministic tests using synthetic or benign fixtures |
| `docs/` | Technical guides, specifications, and development progress |
| `reports/` | Saved experiment evidence and the append-only run register |
| `data/`, `artifacts/` | Ignored local datasets, caches, models, and runtime outputs |

## Safety and reproducibility

Treat unknown PDFs as malicious and inspect only bounded, untrusted bytes.
Dataset acquisition, external uploads, and dynamic execution require explicit
authorization under [AGENTS.md](AGENTS.md). Preserve saved splits, validation
locks, single-shot Test evaluations, and immutable experiment reports.
