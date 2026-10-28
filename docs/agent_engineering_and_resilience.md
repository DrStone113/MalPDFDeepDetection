# Agent Engineering Conventions and Extractor Resilience

This document specifies repository structure, coding standards, comments policy, testing boundaries, extractor resilience contracts, and deserialization safety rules for `MalPDFDeepDetection`.

## 1. Repository Layout

Respect existing project paths and directory ownership:

- `src/malpdf/`: Reusable PDF inspection, safe extraction, modeling, inference, evaluation, and reproducibility code.
- `scripts/` and `configs/`: Reproducible entry points, lab helpers (`scripts/lab/`), and non-secret configuration. No loose scripts at repository root.
- `tests/`: Deterministic, offline, synthetic or reviewed benign fixtures.
- `docs/` and `plans/`: Technical documentation, bug fix documentation, safety workflows, and architecture plans.
- `notebooks/`: Thin training/exploration notebooks using reusable `src/malpdf/` logic; never embed malicious samples.
- `data/`, `checkpoints/`, and `artifacts/`: Ignored datasets, model outputs, caches, and scratch data.
- `reports/`: Documented experiments, benchmark metrics, figures, and `reports/research_log.md`.

---

## 2. Engineering Rules

- **Strict Zero Comments in Python Code:** Retain the strict no-comment policy across `src/malpdf/`, `scripts/`, and `tests/`. Express intent via explicit variable naming, strict type annotations, focused single-responsibility functions, and external markdown documentation.
- **Bug Documentation & Anti-Regression Registry:** When an extractor bug, environment incompatibility, or parser edge case is identified and fixed, record the root cause (5 Whys), deep mechanics, resolution, anti-regression invariant, and regression test contract in the [Bug Knowledge Base](bugs/README.md) using [TEMPLATE.md](bugs/TEMPLATE.md).
- **Clean Tracking:** Never stage or commit PDFs, binary blobs, pickles, `.npy` arrays, credentials, or runtime artifacts.

---

## 3. Testing, Features, and GPU Training

### Environment Compute Allocation
- **Windows Environment:** Executes unit tests with synthetic safe fixtures, static typing/linting checks, and CUDA model training on verified sanitized feature datasets.
- **REMnux Environment:** Executes structural inspection, safe-corpus edge-case extraction, and approved real-PDF parsing. Compute budgets are capped (CPU limits, file handle caps, explicit timeouts per PDF).

### Extractor Resilience Requirements
- **Outcome Classification:** Parsers must classify all extraction attempts into one of three explicit states:
  - `complete`: Full extraction succeeded without parse or schema errors.
  - `partial`: Recovered partial structures or features while gracefully recording soft errors.
  - `failed`: Extraction failed fatally due to structural damage or unrecoverable syntax.
- **Robustness Against Malformed Syntax:** Parsers must gracefully catch and flag corrupt cross-reference streams, circular object references, recursive compression filters, and malformed header/trailer markers without crashing the worker process.

### Deserialization Security
- **Strict Ban on Insecure Pickling:** Strict ban on `pickle.load`, `joblib.load`, `dill`, and `numpy.load(..., allow_pickle=True)`.
- **Safe Array Loading:** Load numeric features exclusively using `numpy.load(..., allow_pickle=False)` with explicit shape and dtype validation.
- **Preferred Storage Formats:** Prefer Parquet/Arrow for tabular metadata and Safetensors for neural network weights.
