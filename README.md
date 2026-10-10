# MalPDFDeepDetection

A Python research project for reproducible malicious PDF detection experiments. Python 3.11 remains the Codespace/test baseline; the authorized Kaggle GPU runtime also supports Python 3.13.

## Static evidence and inference speed

The October 2026 P0/P1 maintenance separates unknown structural/AST totals from
observed partial evidence. JSON diagnostics use `static-diagnostics-v3` and code
inspection uses `pdf-code-inspection-v5`: bounded PDFDocEncoding/Unicode text
decoding, action traversal priority, and explicit partial xref recovery alongside
ASCIIHex/ASCII85/Flate filters. Failed/incomplete PDF parsing refuses
deployment inference even when all numeric model inputs happen to be present.
Canonical 41-feature RIT measurements, source-defined sentinels, model artifacts
and locked partitions keep their established definitions.
See [the metadata audit, feature groups and offline commands](reports/analysis/static_p0_p1.md).
This maintenance uses benign synthetic fixtures and reads dataset metadata only.

Static inspection now reads one size-capped, stable byte snapshot.
`malpdf.inference.StaticScanSession` reuses a verified frozen XGBoost deployment
model and predicts compatible rows in bounded batches, with optional TreeSHAP.
`malpdf code-inspect /explicit/local/sample.pdf` adds redacted JavaScript AST
evidence from literal/Flate/ASCIIHex/ASCII85 streams in a disposable resource-limited process;
unsupported/failed analysis recommends referral. It never executes JavaScript.
Use `malpdf scan /explicit/local/sample.pdf --json --no-explanation
--code-inspection` for combined output. This does not change v3/v4 models or labels.
See [design and limitations](reports/analysis/static_acceleration_design.md).
`scripts/14_benchmark_static.py` measures synthetic ingestion/inference timings
from clean committed code without touching external datasets or Test partitions.
`scripts/16_benchmark_cic_static.py prepare` locks a small CIC Train/dev subset
from saved manifests without reading PDFs. Its `run` action requires the offline
console LAB, records every parser/AST failure and times the actual pipeline.
Profile v2 separates inference gate/refusal time from actual `predict_proba`,
which is null when no model call occurs. `prepare --baseline-run <profile_id>`
locks the same64 inputs/configuration and writes a paired status comparison.
For the original Windows estimator at
`artifacts/models/xgboost__G-drop3constant.joblib`, add that path as
`prepare --model-file ...`. Preparation checks its binary 38-feature contract,
fixed configuration and native-JSON probability parity, then pins a private
snapshot and source checksum without fitting. This supplied Protocol G model
has its own identity; it does not replace the full-RIT deployment manifest.
See [offline job and measurement limits](reports/analysis/cic_static_offline.md).

On the current Lubuntu VM, double-click **Chạy CIC offline** on the Desktop
after completing the selected disconnected console LAB procedure, then press
Enter. The shortcut invokes the locked v5 same-64 job through the existing
guarded CLI and keeps the terminal open after completion or failure.
Type `q` to cancel before starting. Its VM-specific desktop entry is versioned
in `configs/cic_offline_launcher.desktop`; the thin entry point is
`scripts/18_launch_cic_offline.py`. This shortcut does not change network settings.

The fixed CPU study `scripts/17_train_cic_static.py` compares the supplied frozen
RIT model against one XGBoost candidate fit on the saved CIC Train partition
using the controlled cached feature table. Its 40 predictors retain measured
`script_ratio` and `ObfuscationCount`; dropping them creates cross-partition
feature-equivalent groups. The three exclusions must be zero constants on
Train, and all Test identities are discarded before numeric conversion.
Threshold0.5 and the established XGBoost configuration are fixed before fitting.
Numeric Validation classification and missing-row denominators are reported
separately from PDF parser coverage. This does not replace deployment artifacts
or establish independent Test accuracy. See
[the accuracy diagnosis](reports/analysis/cic_static_accuracy.md).
The completed fixed candidate reduced false positives but lost malicious recall
on the 291 previously exposed CIC Validation rows; it remains a development
artifact. The frozen model stays in use. Extractor v5 fixture corrections still
require the paired offline PDF measurement before any full-pipeline gain is
claimed. Previous prepared jobs must be prepared again because their code
fingerprints are locked.

## Retrospective multi-cohort stacking v4

`scripts/13_multi_cohort_stacking_v4.py` adds a separately locked adaptation study.
It preserves the acquired raw-PDF cohort's Protocol G partitions (11,931 Train,
3,977 Validation, 4,050 Test), which are distinct from the historical RIT table.
The verified 1,452-row CIC cohort is split into 870/291/291 rows, seed 42, retaining
whole model-input-equivalence groups and 480/160/160 published malicious labels.
Both cohorts' v3 outcomes were previously inspected: v4 is retrospective,
not a fresh confirmatory holdout or independent evidence of zero-day resilience.

Run the `prepare`, `train-trees --prepared-run <id>`, then
`export-gpu --prepared-run <id> --tree-run <id>` actions from clean committed code,
passing `--data-root /path/to/authorized/data/repository`. Four tree families
use five combined-Train folds each. The numeric GPU ZIP and notebook train five
FT-Transformer folds and Vision from scratch, with base-selection-only stopping,
FP16 AMP, verified RAM matrices and persistent pinned loaders. The ZIP includes
opaque tabular measurements and matrices; upload requires explicit authorization.
The ZIP reuses the pinned existing `nguyenkhang294/malpdf-markov-cache` input and
contains only the 1,452 new CIC matrices; attach both private datasets on Kaggle.
This avoids recompressing the 19,962 source matrices in Codespace.
Auto-expanded Kaggle inputs are copied with checksum verification into a writable
temporary directory before restoring the reused source matrices.
The private original-ID lookup stays local. No PDFs or original PDF hashes/paths
are exported. Parser nulls, security features and forced referrals are preserved.

Download the entire new GPU output run into ignored `checkpoints/`, including all
five FT checkpoints/statistics, Vision checkpoint, probabilities, selection locks
and checksums. `evaluate --handoff-run <id> --gpu-directory <output-run>` fits the
stack, Platt calibration and Youden threshold on separate combined Validation
roles, persists the lock, then scores Test A and Test B once. It rejects repeated
Test invocations. v3 comparisons aggregate saved predictions; v3 is not retrained.
All stages append the research log and preserve failed/interrupted evidence.

## Current research status

Completed, versioned evidence covers the local RIT-PDFMal-2026 audit; paper-aligned Protocol P; feature-vector-disjoint Protocol G; a five-seed descriptive P/G comparison; paper-aligned XGBoost CV10; TreeSHAP; a fixed deep-learning comparison; safe static extraction and a static deployment artifact. Dynamic work is offline report-schema/routing infrastructure only; the isolated CAPEv2 laboratory is a design, not a live sandbox evaluation. The consolidated thesis package is under `reports/thesis/`.

RIT is available locally as CSV only. The authors report malicious samples from
VirusTotal during 2017–2025 and benign samples collected by their crawler
([dataset source](https://github.com/Mo-Alani/RIT-PDFMal-2026)). CIC PDFs support
future extractor development; RIT CSV cannot supply new JS/AST or byte features.

Rebuild its lightweight tables from committed reports only (no data loading, PDF access, model fitting, or benchmark rerun):

```powershell
.venv\Scripts\python.exe scripts\build_thesis_evidence.py
```

See `reports/thesis/thesis_evidence_index.md` for source provenance and `reports/thesis/limitations.md` before interpreting any result.

## Setup

The authorized raw-PDF cohort uses a separate saved Protocol G manifest; it is
not matched to the historical RIT table by filename or feature similarity.
`scripts/07_prepare_raw_pdf_cohort.py --execute-authorized` performs capped
static extraction in disposable resource-limited parser processes. A separate
`--finalize-from <completed preparation run_summary.json>` invocation retains
all 19,958 labeled rows and four unlabeled S3 rows, verifies actual byte-derived
security features, and locks a new group-aware split without rewriting an
earlier cohort. Metadata that could not be extracted remains null in the raw
table, with a parser-failure flag. No PDF is rendered or executed.

Markov extraction supports `--workers auto` with bounded spawn process batches,
using process CPU affinity and the container quota (up to 16 workers). Jobs with
the same verified PDF hash share one cache writer. The entry point sets OpenMP,
OpenBLAS and MKL threads to one per process. Source validation still completes
before any output matrix is created, and failures preserve partial evidence.
Existing completed caches are reused; GPU handoff requires only numeric data.

After building all Markov caches with `scripts/02_build_markov_cache.py --config
configs/raw_markov_cache.yaml`, use a clean committed code checkout to run:

```bash
python scripts/08_train_raw_tri_modal_v3.py --execute --data-root /path/to/authorized/data/repository
```

`configs/raw_tri_modal_v3.yaml` locks all four cohort checksums, five train-only
CV folds, model settings, and CPU epoch budgets before Test access. XGBoost,
LightGBM and CatBoost retain native NaNs and receive fixed metadata missingness
flags. Random Forest and FT-Transformer fit a median imputer independently on
each fitting Train fold, then transform held Train, Validation, Test and
unlabeled rows. Raw values and measured security counts are never imputed.
ResNet-18 receives complete finite one-channel 256×256 Markov matrices.
Validation has four group-disjoint roles for stopping, stacking, Platt fitting,
and MCC/Youden selection. The six-branch stack evaluates Test once after saving
`validation_lock.json`; parser failures force referral, and entropy fills the
remaining 10% referral budget. Referrals do not execute a sandbox or count as
corrected predictions. Four unlabeled rows receive separate predictions and
no ground-truth metrics. Private matrices, checkpoints, identities and detailed
predictions stay in ignored `data/` and `artifacts/`; public reports and the
append-only research log record aggregate evidence and the generating revision.

For a Kaggle GPU handoff, prepare a local numeric bundle from the clean code
checkout and the completed tabular-fold run:

```bash
python scripts/10_export_kaggle_markov.py --data-root /path/to/authorized/data/repository --tabular-run <saved_raw_tri_modal_v3_run_id>
```

The unique ignored export directory contains `malpdf-markov-cache.zip`, a
generated `kaggle_vision_resnet18.ipynb`, and a **private local** ID lookup that
must stay in Codespace. Upload only the ZIP to a private Kaggle Dataset and
import the generated notebook, whose expected metadata checksum is filled in.
After Kaggle finishes creating the dataset, attach it to the notebook using
**Add Input**. Uploading a dataset alone does not attach it. The notebook searches
`/kaggle/input` recursively for the pinned metadata, accepting either an expanded
bundle or a ZIP with any filename. If multiple matching copies are attached,
set `INPUT_ROOT` to one dataset directory. Missing inputs show the entries found;
retain the generated checksum and verify the attached dataset version.
The ZIP contains 19,962 numeric matrices, an opaque-ID `manifest.csv`, copied
validation roles and the small sealed Vision code package. It contains no PDF,
original PDF hash, original source path, or tabular feature table. Preserve the
existing cohort manifest; `data/processed/manifest.csv` is not assumed to exist.
Uncompressed float32 matrices occupy approximately 5.2 GB, so archive size is
measured after compression rather than assumed smaller than the source PDFs.

Enable GPU in Kaggle settings. The notebook uses `cuda:0`, up to 20 epochs,
and Validation **base_selection only** for checkpoint selection. It exports
`vision_resnet_best.pt`, `vision_probs_val.csv`, `vision_probs_test.csv`, separate
unlabeled probabilities, selection lock, versions, checksums and a local run
log. It does not compute Test metrics. Download the whole output run into
ignored `checkpoints/` and retain its checksums and the private Codespace ID
lookup for the later stacking continuation. Join probability files by verified
ID, never row order. Completed tabular folds can be reused; GPU runtime depends
on the hardware and I/O and is not guaranteed to be 15–20 minutes.

Continue from the same handoff using `scripts/09_resume_raw_tri_modal_v3.py`.
Keep `vision_probs_val.csv`, `vision_probs_test.csv`, `vision_selection_lock.json`,
`output_checksums.json` and `run_summary.json` together in ignored `checkpoints/`
(or a run subdirectory). The selection lock must prove stopping on the saved
Validation `base_selection` role, and the output checksums must match both CSVs.
The continuation verifies opaque IDs against the numeric bundle and private
local lookup, reloads all 25 original tabular folds, and restores their saved
Train-only preprocessing without fitting again. The four saved Validation roles
remain disjoint. Missing provenance stops before fitting or Test evaluation.

```bash
python scripts/09_resume_raw_tri_modal_v3.py --data-root /path/to/authorized/data/repository --handoff-run <saved_kaggle_handoff_run_id>
python scripts/09_resume_raw_tri_modal_v3.py --data-root /path/to/authorized/data/repository --handoff-run <saved_kaggle_handoff_run_id> --execute
```

Official execution requires clean committed generating code. A persisted
validation lock precedes the exclusive cohort Test marker; a failed attempt
after claiming Test keeps its marker and cannot be rerun for favorable metrics.
Both successful and failed invocations append immutable evidence and the
research log. The four unlabeled rows remain excluded from supervised metrics.

Kaggle CLI can retrieve the output of a **saved, completed notebook version**.
Use the notebook owner/slug (and preferably its version), rather than the input
dataset slug. Configure authentication locally through Kaggle's supported
credential mechanism; do not paste tokens into chat or put them in Git. Inspect
the output listing first and download to a fresh ignored directory:

```bash
kaggle kernels files <owner/notebook-slug/version>
kaggle kernels output <owner/notebook-slug/version> -p checkpoints/kaggle_import_<UTC_timestamp>
```

Keep files from one Vision run together. Pass its directory using
`--vision-directory checkpoints/kaggle_import_<UTC_timestamp>/<relative_run_path>`.
For complete provenance, also retain the selected `.pt` checkpoint, separate
unlabeled CSV, training history, locked methodology, environment metadata,
model comparison and Kaggle research log. None of these files is committed.
See the [official Kaggle kernel output commands](https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels.md).

The GPU configuration preloads verified float32 matrices into one RAM tensor,
uses two persistent Linux fork workers, pins batches and enables CUDA FP16 AMP.
Worker reads share the preloaded tensor through copy-on-write; no list/stack
copy or uint8 conversion is made. A 6 GiB cache cap, available-RAM check with
2 GiB reserved working memory, and loader shared-memory check fail before
training if the chosen resources are insufficient. Batch size 256 is a locked
candidate, not a guarantee of GPU utilization or runtime. An OOM attempt retains
its evidence; change batch size only for a new Train/Validation run before Test
export. Epoch duration, loader wait time, rows per second and AMP skipped steps
are saved in `training_history.csv`. The matrices retain their original row
probabilities; no whole-matrix normalization is applied.

For an already uploaded bundle, a generated performance notebook carries two
checksum-pinned code updates and creates a separate verified code directory.
It preserves the uploaded ZIP, manifest and base code and records both base
and updated generating commits. Download the entire output run, including the
checkpoint, prediction CSVs, selection lock and code provenance.

See [Kaggle notebook settings and input documentation](https://www.kaggle.com/docs/notebooks)
and [Kaggle dataset privacy documentation](https://www.kaggle.com/docs/datasets).

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
malpdf --seed 42
```

Dataset access requires an explicit human instruction. Place approved samples under `data/`, or invoke the reviewed acquisition script described below after authorization. Follow the safety rules in `AGENTS.md`; never execute or manually open suspicious PDFs.

## CIC raw-PDF normalization and frozen cross-dataset inference

Download CIC archives manually and place the original `Benign.zip`,
`Malicious.zip` and `Malicious2.zip` under ignored `data/raw/cic_pdf/`.
The normalization entry point makes no network requests:

```bash
python scripts/12_normalize_cic_cross_dataset.py \
  --archive-file data/raw/cic_pdf/Benign.zip \
  --archive-file data/raw/cic_pdf/Malicious.zip
```

It checks archive checksums, safe ZIP directories and extraction budgets, then
requires `%PDF-` magic and matching actual SHA-256 bytes for each CIC table ID.
Caps are 1 GiB per archive, 3 GiB of archives and extracted ZIP containers,
4 GiB of PDF bytes and 10 MiB per PDF. The reviewed CIC packages support at
most two nested ZIP levels and 40,000 cumulative directory entries. Encrypted
or unsupported archives remain unavailable and preserve failure evidence;
passwords are never guessed. `Malicious2.zip` may be an encrypted wrapper:
retain it for audit without attempting unsupported decryption. The entry point
reuses the isolated v3 parser and immutable Markov cache.
All 43 raw features and parser flags remain intact; the saved v3 input order
has 40 features after its original Train-only constant exclusions. Metadata
nulls stay null, and structural measurements are never fabricated.

Both published labels are retained when CIC IDs match source-cohort hashes.
Static signatures cannot establish ground truth. Every source match is
excluded, even when labels agree, as are identical model-input feature groups.
`--audit-conflicts` optionally reparses disputed local source files for separate
evidence; those files never enter external metrics. Identifiers without a
verified SHA-256 mapping remain excluded and are reported explicitly.

Add `--evaluate` only from clean committed generating code to perform frozen
inference after all usable independent CIC identities have raw bytes. It
restores the original 25 tabular folds, their Train-only preprocessing, Vision
checkpoint, meta-learner, Platt coefficients and Youden threshold without any
refit. It locks the external cohort before a single evaluation and saves
metrics, 10% entropy/parser referral results and a comparison CSV in a new run.
The original Protocol G Test is never rerun; any baseline is copied from its
saved evidence. A missing or incomplete corpus produces a blocked report with
metrics marked `N/A`, plus an append-only research-log entry. Unknown family
relationships and publisher-label correctness are not claimed as verified.

Already verified extracted PDFs can be reused by omitting `--archive-file`.
If some independent inputs fail the fixed safety checks, preserve the blocked
full-cohort result. A separately declared study can reuse measured data through
`--evaluate --prepared-run <run_id> --allow-input-referrals`. It locks valid-PDF
inputs before inference, reports metrics only on that cohort, and lists refused
inputs as mandatory unscored referrals. Its additional combined coverage is
reported separately from 10% entropy routing on modelable inputs. No result is
presented as accuracy over the whole CIC table, and no unavailable prediction
is fabricated. The generating checkout must be clean and committed.

## Explicitly authorized public PDF acquisition

```bash
python scripts/download_raw_datasets.py --execute-authorized
```

This command is only for a separately authorized acquisition. Without the flag,
it refuses network/data access. `configs/raw_datasets.yaml` lists reviewed HTTPS
sources, pinned GitHub revisions, publisher byte counts, archive MD5 locks where
available, and resource caps. The current inventory contains two Zenodo archives,
three PDF-related archives listed by Contagio's public S3 bucket, and five
CVE-T4PDF PDFs from the previously reviewed GitHub revision. No downloaded
repository code or embedded content is executed.

The Zenodo archives use independently obtained candidate lists in environment
variables `MALPDF_ZENODO_MALWARE_PASSWORD_CANDIDATES` and
`MALPDF_ZENODO_CLEAN_PASSWORD_CANDIDATES`. Contagio S3 uses separate lists in
`MALPDF_CONTAGIO_S3_CVE_2009_3957_PASSWORD_CANDIDATES`,
`MALPDF_CONTAGIO_S3_OBAMA_PDF_PASSWORD_CANDIDATES` and
`MALPDF_CONTAGIO_S3_PDF_SAMPLE_PASSWORD_CANDIDATES`.
Each value is a JSON array of 1–8 unique,
nonempty strings, ordered for that source. Custom configs may instead use the
existing single-value `password_env` field. The loader validates the entire ZIP
directory, then selects a candidate by reading one bounded encrypted member to
EOF and verifying its CRC before publishing any PDF. Only the supplied list is
tried; all-candidate failure stops the source and preserves evidence. Selection
indices and counts are logged; candidate values remain in memory/environment.
Their ZIP directories were inspected on 2026-10-02: both are encrypted. Without
the corresponding variable, that source is recorded as `blocked_missing_password`
before downloading it. Passwords are never written to config or logs. ZIP64,
multipart archives, symlinks, traversal paths, duplicate member names and
unsupported compression are rejected; each extracted PDF must start with `%PDF-`
and obey byte/compression/output limits. A magic check establishes a file header,
not structural validity or safety. Invalid entries are recorded as rejections.

For an authorized password retry, append `--reuse-run <earlier_run_id>` to the
command. This reads existing payloads without changing the earlier run or using
the network. Source identities, publisher locks, original byte counts, SHA-256
and MD5 must all match before reuse. Any mismatch stops that source; there is no
HTTP fallback. The new run records downloaded bytes separately from reused
bytes and writes a fresh extraction inventory and manifest. Both kinds of input
count toward the configured total input-byte cap.

[Contagio's 2013 post](https://contagiodump.blogspot.com/2013/03/16800-clean-and-11960-malicious-files.html)
lists original archive names ending in `files` and refers to a shared password
scheme. [Netresec](https://www.netresec.com/?page=pcapfiles) documents that scheme
as a fixed prefix followed by the last character before the ZIP extension.
A renamed mirror can retain the original password, so candidate order must be
reviewed for each source rather than inferred solely from its current filename.

As inspected on 2026-10-02, Contagio's blog returned HTTP 429, but the separately
supplied S3 bucket was publicly listable (261 objects, three PDF-related ZIPs).
CIC's official download link required a form; no direct CIC raw-PDF mirror was
verified. CSV/Parquet feature mirrors cannot substitute for PDF bytes. Digital Corpora's first Common
Crawl ZIP was about 1.27 GB and was not selected for this small acquisition.
Source references: [Zenodo](https://zenodo.org/records/3464032),
[CIC](https://www.unb.ca/cic/datasets/pdfmal-2022.html),
[Contagio S3](https://s3.amazonaws.com/contagio.deependresearch.org/index.html),
[CVE-T4PDF](https://github.com/0xCyberY/CVE-T4PDF).

Every authorized invocation creates unique directories under
`data/raw/public_pdf_sources/run_.../`, `artifacts/raw_downloads/run_.../` and
`reports/experiments/raw_downloads/run_.../`. Raw bytes, per-file SHA-256 checksums,
member inventories and the source manifest remain ignored; reports contain only
aggregate status/counts, methodology and environment evidence. Progress and
source outcomes append to `reports/research_log.md`, including failed, interrupted
and partially successful runs. Exit codes are 0 for complete acquisition, 2 for
partial/failed source outcomes, and 1 for invocation refusal or setup failure.
SHA-256 is the local acquisition baseline; publisher SHA-256 verification is
claimed only when a reference digest exists. Labels supplied by an archive
publisher retain their label provenance; Contagio S3 samples remain unlabeled,
and the five CVE-T4PDF files retain the user's explicit Malicious assignment.
Nothing assigns new PDFs to the locked
RIT Protocol G manifest or overwrites previous raw datasets, caches or reports.

The initial recorded 2026-10-02 acquisition
[`run_20261002T123152127309Z_3b68d36a5705`](reports/experiments/raw_downloads/run_20261002T123152127309Z_3b68d36a5705/run_summary.json)
finished with status `partial`: five CVE-T4PDF PDFs (7,139 bytes) passed strict
magic, SHA-256 and previous-source checks. Both complete Zenodo ZIPs matched
their published MD5 digests, and all ten payloads matched their saved local
checksums. No PDFs were exported from the five encrypted archives: both
user-supplied password candidates were rejected. This historical result is
preserved unchanged.

The subsequent read-only password retry
[`run_20261002T131549363589Z_3b68d36a5705`](reports/experiments/raw_downloads/run_20261002T131549363589Z_3b68d36a5705/run_summary.json)
opened both Zenodo archives with their first supplied candidate and exported
10,967 unique publisher-labeled malicious PDFs and 8,986 unique
publisher-labeled benign PDFs, plus the five user-labeled CVE-T4PDF samples.
Fifteen malicious-archive entries were rejected (13 size/compression violations,
two missing strict PDF magic); 14 identical clean-archive members were deduplicated.
The first candidate failed on all three S3 ZIPs. The source-specific follow-up
[`run_20261002T133145838160Z_3b68d36a5705`](reports/experiments/raw_downloads/run_20261002T133145838160Z_3b68d36a5705/acquisition_outcome.json)
opened all three with the scheme-derived suffix for their current filename and
exported four additional unlabeled PDFs; four non-PDF members were rejected.
Across these two runs, 19,962 PDFs passed independent magic, SHA-256, size and
permission checks, with no cross-run duplicates and no new network transfers.
Inputs remain in ignored raw directories and each run has a separate ignored
manifest. The combined outcome is `completed_with_rejections`; the original
partial-run statuses and evidence remain intact. No full CIC raw-PDF acquisition
is claimed, no RIT file identities were inferred, and its canonical split remains unchanged.

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

## Cache-backed tri-modal late fusion

`scripts/05_evaluate_tri_modal_fusion.py` requires all three genuine branches:
historical raw XGBoost/FT probabilities and ResNet-18 predictions inferred from
verified Markov caches. It reuses the v2 validation-only stacking, Platt, metrics
and entropy-routing implementation. Check readiness or request evaluation with:

```bash
python scripts/05_evaluate_tri_modal_fusion.py --dry-run
python scripts/05_evaluate_tri_modal_fusion.py --execute
```

`configs/tri_modal_fusion.yaml` pins the same seed-42 dataset/split/base inputs.
Its `vision_cache.source_manifest` must cover every canonical Protocol G ID and
label, with no file/family leakage; `cache_directory` must contain all matching
SHA-named NPY matrices and verified sidecars. Only cache bytes are read, with
bounded headers, `allow_pickle=False`, and checksums checked on every access.
Raw PDFs are never opened. `batch_size` and `cpu_threads` bound CPU inference.

Set `vision_cache.checkpoint` to `{path: artifacts/vision_resnet/<run>/best_model.pt,
sha256: <checksum>}`. Set `training_run` to checksum-locked `summary`,
`methodology` and `validation_lock` inputs from that same official Vision run:
`run_summary.json`, `locked_methodology.json`, and `validation_lock.json`.
The saved evidence must show completed clean seed-42 training, the exact dataset,
split/source locks, train-only fitting and validation-loss checkpoint selection
before test. The checkpoint is read with a 64 MiB cap and `weights_only=True`;
its metadata and finite tensor state must match the evidence. Smoke checkpoints
are rejected. No model training or downloads are performed by this script.

The fusion candidate grid includes three-input logistic stacking and convex
averages. Validation groups are split into disjoint meta-fit/calibration-fit/
selection roles (~25/25/50); selection uses MCC, then malicious F1, then declared
order, with no refit. Zero-weight candidates are explicitly reported as controls.
Official execution requires clean committed code. Base test prediction decoding
and Vision test inference happen once after the persisted fusion validation lock.
Reports contain Accuracy, malicious F1, MCC, Brier, log loss, ECE (10 equal-width
malicious-probability bins) and the fixed top-10% entropy referral analysis.

The current five CVE caches match **0/24,337** RIT IDs. The configured checkpoint
and training run are deliberately `null`; the CVE smoke checkpoint is ineligible.
Either command currently exits **2** (`blocked_missing_vision`), with no inference,
fitting or test evaluation and explicit N/A metrics. It never falls back to a
two-branch experiment. Every attempt writes a unique
`reports/experiments/tri_modal_fusion/run_.../` with methodology, environment,
readiness/error evidence, comparison/routing tables and an appended research-log
entry. Detailed cache checksums and inferred scores stay in ignored `artifacts/`.

## Safety-First five-model stacking v3

```bash
python scripts/06_optimize_and_stack_v3_safe.py --dry-run
python scripts/06_optimize_and_stack_v3_safe.py --execute
```

`configs/safe_stacking_v3.yaml` pins the existing seed-42 Protocol G dataset,
saved split, and real PDF source manifest. The user explicitly requires measured
`ObfuscationCount`: a complete PDF-to-RIT mapping by canonical ID, Label, and
SHA-256 is mandatory. The current five CVE sources match 0/24,337 RIT IDs, so
execution currently exits 2 (`blocked_missing_pdf_source`) before PDF byte reads,
model fitting, calibration or test evaluation. Missing counts are never replaced
with zero, inferred from feature equivalence, or synthesized from other columns.

The measured feature counts raw PDF name-shaped tokens containing valid `#HH`
hexadecimal escapes, once per escaped token. This lexical byte measurement
includes occurrences in strings/comments/stream bytes; it does not decompress
streams or establish that an escaped name is an active object or malicious.
Files are read only as bounded static bytes (10 MiB per PDF), without rendering,
execution or network access, and must match their locked SHA-256. Train and
validation are measured before fitting; test PDFs are measured only after the
persisted validation lock. Per-file measurements/hashes stay in ignored artifacts.

Only `Acroform`, `Colors` and `BaseEncoding` may be removed, after zero-variance
checks on train and each fitting fold. All other 38 source features survive,
including rare/constant security features and documented semantic sentinel values.
`script_ratio=(JS+JavaScript)/(1+obj)` and the actually measured
`ObfuscationCount` bring the model input to 40 features; neither needs fitting.
Source tables and the saved split remain unchanged.

XGBoost, LightGBM, CatBoost, Random Forest and the existing FT-Transformer each
fit five train-only stratified folds. Feature-equivalent and known PDF/family
components stay together. OOF train metrics are descriptive and never select
hyperparameters or fit the meta model. FT standardization fits only its fitting
fold; its AdamW/BCE checkpoint selection uses a reserved validation group subset.
Tree hyperparameters are predeclared, not searched using CV/test results. All
family predictions on validation/test are equal means of their five fold models;
there is no full-train refit. CatBoost file-writing is disabled, and CPU/thread,
tree-size and epoch budgets are bounded. LightGBM/CatBoost dependencies are
declared in `pyproject.toml`; no datasets are downloaded.

Validation groups are deterministically divided into approximately 25% each for
base early stopping, logistic meta fitting, Platt fitting, and threshold/candidate
selection. Youden J selects the threshold only on the last subset; tied J uses
MCC, malicious F1, distance to 0.5, then the larger threshold. Meta C candidates
are selected by validation MCC, then malicious F1 and declared order, without
refitting. Coefficients, calibration, feature formulas and threshold are saved
before the single independent test inference/evaluation. Official fitting requires
clean committed code. Accuracy, malicious F1, MCC, Brier, log loss, ECE and
entropy-10% retained/referral/FN-catch metrics use the correct locked threshold;
base-family comparisons retain the predeclared 0.5 threshold. ECE uses 10
equal-width malicious-probability bins. Referrals are abstentions, not corrections
or authorization for dynamic execution.

Every attempt creates a unique `reports/experiments/safe_stacking_v3/run_.../`
with methodology, environment, provenance, status/error evidence, comparison and
routing tables, and appends `reports/research_log.md`. Models/checkpoints, detailed
PDF measurements and probability tables remain ignored under `artifacts/`.
Unavailable research metrics are recorded as N/A, including failures and missing
PDF prerequisites. Offline tests exercise all 25 real base fits with benign
synthetic bytes/tables; their metrics are not RIT research results.

## GitHub Codespaces

To move the current private data and saved evidence to a local Lubuntu VMware
machine, follow [the transfer and restore guide](docs/lubuntu_migration.md).
Migration archives remain ignored under `artifacts/migration/`; source datasets,
Markov matrices and checkpoints are never committed. The transfer preserves
existing splits, validation locks and Test markers, and restores a fresh Python
environment rather than copying a Codespace virtual environment.

The repository includes a Python 3.11 devcontainer for reproducible source development and synthetic-test execution. Create a Codespace from a committed revision, allow its post-create command to install the project from `pyproject.toml`, then run:

```bash
python -m pytest -q
python -m pip check
```

The devcontainer installs PyTorch 2.11.0 and torchvision 0.26.0 from the CPU wheel index, with versions declared solely in `pyproject.toml`. This avoids PyTorch's unused CUDA libraries in Codespace. It does not promise GPU availability. Authorized Kaggle GPU runs may use the corresponding CUDA builds (for example, the observed `+cu128` image) and Python 3.13; always record effective versions. XGBoost 3.2 through 3.4 is supported, covering the local baseline and observed Kaggle image. Codespaces is not an approved malware-execution sandbox and does not itself authorize uploading or downloading raw PDFs, sample hashes, or extracted sample metadata. The devcontainer never acquires or processes samples. The separate acquisition CLI requires explicit human authorization; follow `AGENTS.md` before any sample handling.

For a fresh local Linux environment using CPU wheels:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu -e '.[dev]'
.venv/bin/python -m pytest tests/
.venv/bin/python -m pip check
```

Python 3.13 can use the same project declaration in an authorized cloud environment. Kaggle images may omit `ensurepip`; create the virtual environment with `--without-pip` and use the existing pip's `--python /path/to/venv` option to install software into that isolated environment. CUDA training uses the matched PyTorch/torchvision CUDA builds and the current `torch.amp` API. A dependency upgrade does not authorize a new dataset acquisition, split, or Test evaluation.

The upgrade passed all 578 tests on both Python 3.11 and Python 3.13, with clean dependency checks. The [compatibility report](reports/experiments/pytorch_runtime_summary/run_20261004T155638273289Z_e9ae2aee5365/summary.md) records versions, warnings, failed preparation attempts and the older FT checkpoint compatibility check.

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

## Static model development on Kaggle

`scripts/15_train_static_development.py launch --root /path/to/data-workspace` starts a private, internet-disabled Kaggle GPU study from a clean committed code worktree, using the existing authorized v4 numeric dataset. No dataset is uploaded. `collect --root /path/to/data-workspace --launch-run <run_id>` imports checksum-verified numeric evidence after completion; checkpoints remain in private Kaggle Output to save Codespace disk space.

The separately locked retrospective study compares uniform training with cohort/class/group-balanced training over the existing five Train folds. XGBoost, LightGBM, CatBoost and Random Forest run on Kaggle CPU; FT-Transformer uses CUDA FP16 AMP, preloaded tensors and persistent pinned DataLoaders. All 40 measured security features and metadata missing flags remain. Preprocessing fits only on each Train fitting fold. The existing four Validation roles separately control early stopping, meta fitting, Platt fitting and MCC/Youden selection. Selection maximizes macro-cohort Validation MCC with recorded tie-breakers. CIC's base-selection role contains only one equivalence group; this limitation is reported explicitly.

This is a five-branch static ablation; the existing Vision model and previously evaluated Test sets remain unchanged. Test rows are excluded before preprocessing, fitting, weighting and inference. Validation results are development diagnostics, requiring future independent-cohort confirmation, and do not establish new Test accuracy. Historical runs are retained; launch, import, metrics and checks append to the research log.

The completed 50-fit Kaggle study did not improve CIC discrimination: Accuracy stayed 53.125% on the 64-row Validation selection subset, and MCC remained near zero. Cohort balancing improved CIC calibration but worsened source calibration. The candidate has not replaced the deployed model. See the [immutable development summary](reports/experiments/static_development_summary/run_20261004T154256846017Z_e9ae2aee5365/summary.md).

For the paired byte-profile study, pass `--configuration configs/static_markov_development.yaml` to the same launch command. It attaches both existing authorized private numeric datasets without uploading additional sample data. Two variants use identical saved Train folds and new group-diverse roles within the existing Validation partition: the original 40 structural features and those same features plus 33 fixed Markov descriptors. Original split and role files remain immutable. Each Validation role has at least ten groups and both classes per cohort; large indivisible groups can still prevent equal row or class counts. FT checkpoint loss gives each cohort equal total weight and equal weight to groups within a cohort, so large equivalence groups cannot dominate stopping. Meta fitting, Platt fitting, and Youden/MCC selection remain on disjoint Validation roles. No Test matrices, inference, or metrics are used.

The Markov descriptors measure sparsity, conditional entropy and transitions between byte-value bands. They preserve float32 probabilities and require no fitted transform. Two bounded CPU processes read only verified Train/Validation NPY members directly from the existing numeric inputs, without expanding caches to disk or reading PDFs. FT inputs are preloaded into RAM and use the existing CUDA AMP training budget. Compare the paired variants on this study's same Validation selection rows; the earlier 64-row 53.125% result is a different development subset. Validation gains are hypotheses requiring future independent evidence; neither new Validation roles nor byte summaries establish ground-truth labels or JavaScript exploit detection.

The completed paired study trained 50 models on Kaggle in 226.604 seconds, excluding startup and output import. On its same 48-row CIC Validation selection subset, structural-only stacking achieved Accuracy 56.25%, MCC 0.130551, and AUROC 0.547826; adding Markov descriptors achieved 52.0833%, MCC 0.008696, and AUROC 0.382609. The added descriptors separated formerly identical feature vectors but did not improve discrimination. The structural-only development candidate won the locked selection criterion; existing deployed models remain unchanged. All 96 saved metric rows were independently verified, and no Test inference was performed. See the [paired study evidence](reports/experiments/static_markov_development_summary/run_20261004T174737533805Z_7b3fc6194800/summary.md).
