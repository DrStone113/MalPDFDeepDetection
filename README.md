# MalPDFDeepDetection

A minimal Python 3.11 research project for reproducible malicious PDF detection experiments.

## Current research status

Completed, versioned evidence covers the local RIT-PDFMal-2026 audit; paper-aligned Protocol P; feature-vector-disjoint Protocol G; a five-seed descriptive P/G comparison; paper-aligned XGBoost CV10; TreeSHAP; a fixed deep-learning comparison; safe static extraction and a static deployment artifact. Dynamic work is offline report-schema/routing infrastructure only; the isolated CAPEv2 laboratory is a design, not a live sandbox evaluation. The consolidated thesis package is under `reports/thesis/`.

Rebuild its lightweight tables from committed reports only (no data loading, PDF access, model fitting, or benchmark rerun):

```powershell
.venv\Scripts\python.exe scripts\build_thesis_evidence.py
```

See `reports/thesis/thesis_evidence_index.md` for source provenance and `reports/thesis/limitations.md` before interpreting any result.

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

## Prepare acquired local datasets

Prepare the explicitly acquired RIT ZIP, Kaggle CIC ZIP/Parquet, and CVE-T4PDF
files without changing their sources:

```bash
python scripts/prepare_source_datasets.py
```

The script verifies each source against its single completed acquisition manifest
under `artifacts/dataset_acquisition/`, safely extracts only the reviewed table
members, and copies CVE PDFs as opaque bytes. Resource caps are declared in
`configs/source_preparation.yaml`. Each invocation creates new ignored directories
under `data/processed/source_preparation/` and `artifacts/source_preparation/`, saves
schema/count/label/checksum/provenance reports, and appends `reports/research_log.md`.
CIC retains its independent cohort and source values. CVE PDFs have no tabular
feature schema; their separate `cve_t4pdf/source_pdf_manifest.csv` records sample
IDs, labels, repository-relative PDF paths, SHA-256 checksums, and label provenance.
Labels are unavailable by default. To assign Malicious (`Label=1`) to the CVE PDF
inventory according to an explicit user instruction, run:

```bash
python scripts/prepare_source_datasets.py --label-cve-malicious
```

The manifest, methodology, and research log record `user_requested_malicious` as
the label source. CVE samples remain separate from the locked RIT split, and the
new run preserves earlier unlabeled runs.

The saved RIT Protocol G manifest is checked against the historical dataset and
manifest SHA-256 locks, sample identities, labels, groups, partition counts, and
zero overlap. An absent manifest gives exit code 2 while preserving preparation
reports. To explicitly recreate an absent seed-42 manifest, use:

```bash
python scripts/prepare_source_datasets.py --create-missing-manifest
```

This option reuses the existing group-aware 60/20/20 splitting logic, preserves
the historical CRLF CSV bytes, and publishes the canonical manifest only after
its checksum and invariants match. Existing manifests and reports are never
overwritten. Processing failures give exit code 1 and preserve failure evidence.

## Build the byte Markov cache

Build the single-channel byte-transition probabilities from the explicitly
locked manifest in `configs/markov_cache.yaml`:

```bash
python scripts/02_build_markov_cache.py
```

The current configuration pins the prepared, user-labeled CVE-T4PDF manifest
(five PDFs). Its preparation report supplies the manifest checksum and acquired
raw-file inventory. The script maps each PDF to `data/raw/` by its unique locked
SHA-256, verifies every source before creating caches, and only reads binary
bytes with a 10 MiB per-file cap. It never invokes a PDF parser, renderer, viewer,
or embedded action. RIT/CIC feature tables do not supply corresponding raw PDFs;
this cache does not create a RIT Protocol G vision dataset or change its split.

Each `data/processed/markov_cache/<pdf_sha256>.npy` contains an uncompressed
float32 matrix of shape `(256, 256)`, representing one channel. A tensor loader
can add the axis to obtain `(1, 256, 256)`. Each observed row sums to one, and
unobserved rows stay zero. JSON sidecars record the algorithm and cache checksum.
Existing caches are reused only after bounded header, checksum and probability
checks with `allow_pickle=False`; corrupted or incomplete caches are refused.

Every invocation creates a new `reports/experiments/markov_cache/run_.../`
directory and appends the research log. Detailed per-PDF identities and hashes
remain under ignored `artifacts/markov_cache/` and `data/`; reported model metrics
are explicitly unavailable because this step performs no model evaluation.
To use another authorized preparation, pass both `--manifest` and
`--preparation-report` explicitly. The script preserves existing caches, splits
and run directories.

## Single-channel vision ResNet-18

`src/malpdf/models/vision_resnet.py` defines a scratch-initialized ResNet-18 with
a one-channel stem, `(B,1,256,256)` inputs and one binary logit per sample.
`predict_proba` applies sigmoid for malicious `Label=1`. No pretrained weights
are downloaded. Run the cache smoke check with:

```bash
python scripts/03_train_vision_model.py --dry-run
```

`configs/vision_resnet18.yaml` locks the source manifest, RIT table and saved
Protocol G split by SHA-256. The loader reuses the existing Protocol G validator,
joins the source PDF index by exact sample ID and label, and prevents duplicate
PDF hashes or known related groups from crossing partitions. It reads only cache
matrices and table metadata; NPY headers, checksums and row probabilities are
checked on every access. There is no fitted scaling or image augmentation.

The current five CVE caches are all user-labeled malicious and have no ID mapping
to the 24,337 RIT rows. Dry-run checks their untrained forward pass and finite BCE
diagnostic loss; it performs zero optimizer steps and saves no checkpoint.
Accuracy/F1/MCC and calibration metrics remain unavailable for this smoke run.

To exercise backward passes, AdamW updates and checkpoint save/reload on the
existing caches, use the bounded technical training check:

```bash
python scripts/03_train_vision_model.py --smoke-train --smoke-epochs 2 --smoke-batch-size 2
```

This mode allows 1–2 epochs, batches of 1, 2 or 4, and at most eight samples in
saved manifest order. It saves the final epoch as `smoke_model.pt` under ignored
`artifacts/`, checks finite gradients and changed parameters, and verifies a fresh
model reload with `weights_only=True`. Accuracy/F1/MCC/Loss, Brier and ECE describe
the same samples used for fitting; they are technical diagnostics, not held-out
Protocol G results. The five current samples contain only Label=1, so MCC=0 is
the scikit-learn zero-denominator convention and cannot show discrimination.
Smoke training performs no validation/test evaluation, early stopping, tuning,
calibration or split regeneration. Its reports record the dirty worktree and
scope separately from official training.

Once an authorized, complete RIT PDF/cache index exists, point the configuration
to its locked manifest and use `--execute` from a clean committed worktree.
Training reuses AdamW, BCEWithLogitsLoss and validation-loss early stopping.
The best checkpoint stays under ignored `artifacts/vision_resnet/run_.../` and
is reloaded with `weights_only=True`. Its validation decision is persisted before
a single test evaluation. Reports include Accuracy, malicious F1, MCC, BCE loss,
Brier score and 10-bin ECE. Every invocation creates a new immutable report run
and appends the research log, preserving existing splits, caches and reports.

## Validation-locked late fusion v2

`src/malpdf/models/late_fusion.py` combines raw malicious-class probabilities
from the historical train-only XGBoost/FT models. The thin evaluation entry point
defaults to preflight without fitting or decoding test predictions:

```bash
python scripts/04_evaluate_late_fusion.py --dry-run
```

`configs/late_fusion_stacking.yaml` pins the dataset, saved Protocol G manifest,
historical probability tables and generating provenance by SHA-256. Legacy safe
IDs are mapped back to the manifest and joined by exact ID/label; row positions,
v1 calibrated columns and v1 validation roles are never reused for fitting.
Validation groups are deterministically stratified into approximately 25%
meta-fit, 25% Platt calibration-fit and 50% selection. Feature-equivalent groups
remain together, as do known PDF/family components when Vision is enabled.
Logistic Regression stacking learns coefficients only on meta-fit. Its candidate
C values and convex-average candidates are predeclared; Platt fits fused raw
malicious probabilities only on calibration-fit. Selection maximizes MCC, then
malicious F1; exact ties retain declared order. Selected models/calibrators are
retained without refitting on selection or the full validation set.

After code is committed and the worktree is clean, official evaluation uses:

```bash
python scripts/04_evaluate_late_fusion.py --execute
```

The script persists methodology and learned coefficients/weights in
`validation_lock.json` before decoding or evaluating test predictions once.
Reports include malicious F1, MCC, Brier, log loss and ECE (10 equal-width bins
of malicious probability, with p=1 in the last bin). Selective routing refers
`round(0.1*n)` samples with greatest binary entropy in bits, breaking ties by
sample ID. The 10% budget is fixed before test access; no test labels select the
policy. Coverage, false-negative catch rate, retained metrics and referral counts
are reported. FN catch rate is N/A when there are no false negatives. Referrals
are abstentions and are never counted as corrected or dynamically executed.
Each invocation creates a new `reports/experiments/late_fusion_v2/run_.../`,
appends `reports/research_log.md`, and preserves historical v1 reports. Detailed
roles and derived prediction tables stay under ignored `artifacts/`.

Vision is explicitly optional and currently unavailable for Protocol G: the
five CVE smoke samples/checkpoint cannot supply RIT predictions. With `vision:
null`, nonzero Vision-weight candidates are recorded as unavailable; no scores
are fabricated. To enable it, configure checksum-locked `validation`, `test` and
`provenance` inputs. Vision CSV/Parquet tables need canonical Protocol G
`sample_id`, `true_label`, `vision_probability` columns. Its JSON provenance must
contain `protocol: G`, `seed: 42`, `model: vision_resnet18`, `official_model: true`,
`base_fit_partition: train`, `checkpoint_selection_partition: validation`,
`worktree: clean`, matching `dataset_sha256` and `split_manifest_sha256`,
`source_manifest: {path, sha256}`, and `predictions: {validation: {path, sha256},
test: {path, sha256}}` matching configuration. The source manifest must completely
match Protocol G IDs/labels and pass duplicate-file/family leakage checks.
Experimental convex weights use `[(1-v)*w, (1-v)*(1-w), v]` for XGB/FT/Vision;
three-branch stacking learns its separate coefficients on meta-fit only.

## GitHub Codespaces

The repository includes a Python 3.11 devcontainer for reproducible source development and synthetic-test execution. Create a Codespace from a committed revision, allow its post-create command to install the project from `pyproject.toml`, then run:

```bash
python -m pytest -q
python -m pip check
```

The devcontainer installs the declared PyTorch and torchvision versions, but it does not promise GPU availability. Codespaces is not an approved malware-execution sandbox and does not authorize uploading or downloading raw PDFs, sample hashes, or extracted sample metadata. No configuration in this repository fetches, decrypts, opens, renders, or executes samples; follow `AGENTS.md` before any separately authorized sample handling.

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

Audit local CIC-Evasive-PDFMal2022 feature-table mirrors before any cross-dataset work. Place approved `.parquet` and/or `.csv` tables under `data/external/cic_evasive_pdfmal2022/`.

```powershell
.venv\Scripts\python.exe scripts\audit_cic_source_fidelity.py
.venv\Scripts\python.exe scripts\inspect_cic_pdfmal.py --dataset data\external\cic_evasive_pdfmal2022\PDFMalware2022.parquet
.venv\Scripts\python.exe scripts\resolve_rit_cic_mappings.py --cic-dataset data\external\cic_evasive_pdfmal2022\PDFMalware2022.parquet
```

Run `audit_cic_source_fidelity.py` first: it inventories every local CSV/Parquet mirror without selecting one, compares schemas and rows safely, and writes no raw identifiers. `resolve_rit_cic_mappings.py` requires an explicit mirror path so a source is never selected implicitly; it only rebuilds conservative feature-space evidence. The audit supports Parquet through the declared `pyarrow` dependency and never converts, alters, or opens source samples. Local CIC copies are treated as third-party mirrors, not official or byte-identical CIC files. None of these commands encodes data, trains a model, or calculates cross-dataset performance.

Preflight the future strict six-feature RIT-to-CIC transfer design (no model is fitted by default):

```powershell
.venv\Scripts\python.exe scripts\run_cross_dataset_strict6.py --dry-run
```

The fixed `STRICT6` space is `metadata_size`, `xref_length`, `title_length`, `embedded_files`, `trailer`, and `objstm`, selected solely from the committed v2 schema-alignment metadata. The planned tracks are RIT six-feature within-domain, canonical-CIC six-feature within-domain, primary RIT→CIC transfer, and secondary CIC→RIT transfer: 20 future fixed results across the five established model families. The command requires the selected `PDFMalware2022.csv` third-party mirror and its reviewed Parquet companion, verifies source checksums, canonical CIC target validity, strict numeric inputs, and mirror stability before fitting. It stops rather than adapting/cleaning data if any invariant fails. Future outputs use a new immutable `reports/experiments/cross_dataset_strict6/<run-id>/` directory; models remain ignored under `artifacts/`.

Preflight the fixed Protocol G XGBoost TreeSHAP analysis:

```powershell
.venv\Scripts\python.exe scripts\run_xgb_explainability.py
```

The explicit `--execute --run-id protocol-g-seed42` command retrains only the established G-drop3constant XGBoost configuration on the immutable Protocol G training partition, verifies the committed test metrics before explaining the 4,867 test rows with native XGBoost `pred_contribs=True`, and writes a new immutable explainability report. SHAP is descriptive only: it never changes the split, model, feature schema, or historical benchmark results.

## Safe static PDF inspection

The project can inspect one local PDF as untrusted bytes without opening a viewer, executing JavaScript or attachments, following links, extracting payloads, invoking external programs, or loading an ML model:

```powershell
.venv\Scripts\python.exe -m malpdf inspect path\to\untrusted.pdf
.venv\Scripts\python.exe -m malpdf inspect path\to\untrusted.pdf --json
```

Inspection is bounded by a 50 MiB file limit, 1,000 pages, and 10,000 structural objects by default; each can be configured on the CLI. The JSON result reports a fixed 41-feature RIT-schema-oriented static vector, raw lexical counts separately from parser-confirmed structural indicators, warnings, and a strict Protocol G 38-feature compatibility gate. Canonical RIT metadata features use the released PDFMalExtract v0.1 methodology with its pinned PyMuPDF 1.26.7 dependency; pypdf remains a separate read-only structural-diagnostics parser.

The Protocol G schema-level compatibility gate is satisfied (38 required feature definitions), but each actual PDF must still pass the per-file gate with all finite extracted values; no missing value is imputed. The local RIT CSV has no matching raw PDFs, so record-level feature equality remains unverified. Generate the historical v1 coverage documentation only from a clean committed extractor revision:

```powershell
.venv\Scripts\python.exe scripts\generate_static_feature_coverage.py
```

Generate the separate, immutable v2 compatibility-resolution report (it preserves the v1 report):

```powershell
.venv\Scripts\python.exe scripts\generate_static_compatibility_resolution.py
```

## Static deployment/demo detector

The separately versioned deployment detector is a full-RIT, static-only XGBoost artifact. It reuses the fixed evaluated model family/configuration and `G-drop3constant` 38-feature order, but is **not** a Protocol G model and does not create a new performance result. Build its local, ignored model artifact exactly once from a clean committed checkout:

```powershell
.venv\Scripts\python.exe scripts\build_deployment_model.py
.venv\Scripts\python.exe scripts\build_deployment_model.py --execute
```

The default command is a no-write preflight. The `--execute` command validates the approved RIT checksum and full-data row/class invariants, then saves the JSON model under ignored `artifacts/models/` and an immutable tracked manifest under `reports/deployment/`. It refuses overwrite. The model artifact must be built locally before scanning.

```powershell
.venv\Scripts\python.exe -m malpdf inspect path\to\untrusted.pdf
.venv\Scripts\python.exe -m malpdf scan path\to\untrusted.pdf
.venv\Scripts\python.exe -m malpdf scan path\to\untrusted.pdf --json
```

`inspect` remains extractor-only and never loads a model. `scan` requires the strict 38-feature per-file gate before inference, returns the frozen model's malicious probability and binary model verdict at threshold `0.5`, and attempts a mathematically checked local native XGBoost TreeSHAP explanation. Neither command executes PDF content, follows links, opens viewers, or extracts attachments. A score is an ML prediction, not proof that a PDF is malicious; malformed/encrypted PDFs and dataset shift can prevent reliable static analysis.

## Protocol G tabular deep-learning comparison

The focused thesis comparison uses the existing immutable Protocol G seed-42 feature-vector-disjoint split, exact 38-feature `G-drop3constant` order, train-only `StandardScaler`, fixed MLP and FT-Transformer architectures, unweighted `BCEWithLogitsLoss`, AdamW, and validation-loss early stopping. It does not regenerate the split, tune on test results, retrain XGBoost, use the deployment model, or process raw PDFs.

```powershell
.venv\Scripts\python.exe scripts\run_deep_learning_protocol_g.py
.venv\Scripts\python.exe scripts\run_deep_learning_protocol_g.py --execute --run-id seed42
```

The first command is a clean-worktree, no-write preflight. The official execute command trains each fixed neural model once, saves only ignored checkpoints under `artifacts/deep_learning/`, then records lightweight histories, metrics, provenance, figures, and a comparison against the committed historical Protocol G XGBoost result. CUDA is selected automatically when PyTorch can use it; CPU remains supported.

## Selective static ensemble and hypothetical dynamic routing

The fixed Protocol G seed-42 study combines the established XGBoost and FT-Transformer probabilities only after a validation-only lock: calibration fitting and candidate selection use disjoint deterministic halves of validation, while test is evaluated once after the lock. It retains the 38-feature `G-drop3constant` schema and does not replace the static deployment model.

```powershell
.venv\Scripts\python.exe scripts\run_selective_static_ensemble.py
.venv\Scripts\python.exe scripts\run_selective_static_ensemble.py --execute
```

The default command is clean-worktree preflight only. The official execute command writes safe hashed sample IDs, prediction tables, calibration/ensemble/routing tables, and figures under `reports/experiments/selective_ensemble/protocol_g_seed42/`. Referral is hypothetical: referred rows are abstained rather than corrected. No PDF is opened, no CAPE or sandbox is contacted, no dynamic value is fabricated, and no hybrid model is trained. A report-only recovery command, `--finalize-reports`, can render a missing analysis from already-created lightweight outputs without fitting or predicting.

## Dynamic behavioural-report preparation

Dynamic analysis is currently **offline sandbox-report parsing only**. The project cannot submit PDFs to a sandbox, execute malware, call CAPE APIs, or retrieve live reports. An already-produced, harmless/sanitized CAPEv2-like JSON report can be normalized into `dynamic-schema-v1` behavioural counts and indicators:

```powershell
.venv\Scripts\python.exe -m malpdf dynamic parse path\to\sandbox_report.json
.venv\Scripts\python.exe -m malpdf dynamic parse path\to\sandbox_report.json --json
```

The output is descriptive only and preserves `null` for unavailable data rather than replacing it with zero. Static-to-dynamic routing policies are configurable library infrastructure; no final uncertainty threshold, sandbox client, dynamic classifier, fusion score, or hybrid verdict exists yet.

An isolated CAPEv2 laboratory has been designed for future review, but live sandbox execution remains disabled. The design requires a dedicated Ubuntu/KVM host, an isolated Windows guest, offline default networking, controlled JSON-only report egress, and a formal containment approval gate. It does not provide a malware-submission command or install CAPE in this repository.
