# Fixed CIC development diagnosis

The immediate priority is the private per-file failure inventory. The job
selects 32 CIC Train and 32 CIC Validation rows, 16 of each label per partition,
by seed42 identity rank. It verifies the saved manifest checksums, label joins,
PDF identities and related/equivalent group boundaries without changing any
split. Selection uses no parser results and never selects Test rows. The small,
balanced sample is a diagnostic pilot, not a representative full-CIC benchmark.

`prepare` reads CSV metadata only. It saves identities/paths in ignored
`artifacts/cic_static_prepare/<run>/subset.csv`, a checksum lock and an extractor
fingerprint. The online SSH session does not hash, parse or open actual PDFs.
The offline worker verifies each PDF's actual hash before parsing. A changed
file is an explicit error, never a substituted sample.

```bash
.venv/bin/python scripts/16_benchmark_cic_static.py prepare
```

For the follow-up to the saved first real-PDF run, preparation must retain
its exact subset checksum and configuration:

```bash
.venv/bin/python scripts/16_benchmark_cic_static.py prepare \
  --baseline-run run_20261009T143328562606Z_57544eaea873
```

The user supplied the original Windows estimator as
`artifacts/models/xgboost__G-drop3constant.joblib`. To use that existing model
for inference, prepare with its explicit controlled path:

```bash
.venv/bin/python scripts/16_benchmark_cic_static.py prepare \
  --baseline-run run_20261009T143328562606Z_57544eaea873 \
  --model-file artifacts/models/xgboost__G-drop3constant.joblib
```

This optional preparation reads only the user-trusted local model and CSV
metadata. It verifies XGBClassifier type, Label=1 malicious, exact 38-feature
order, 200-tree structure and every fixed configuration parameter. It writes
a native XGBoost JSON snapshot under the new ignored prepared-run directory
and requires exact probability parity on two synthetic numeric probe rows.
No fitting, PDF processing or Test evaluation occurs. The job lock pins the
source/snapshot SHA-256, threshold0.5 and model contract; run mode reads native
JSON and cannot override the selected model. Changed weights or model contracts
fail preflight before PDF access. Preparing after a code change creates a new
fingerprint while retaining the exact same64 subset and baseline configuration.

The supplied model ID is `xgb-rit-supplied-g-drop3constant-v1`. Filename, structure
and configuration match the historical Protocol G variant. Its original Train
lineage is user-reported: the historical report has no artifact checksum with
which to independently verify it. The source checksum pins the supplied bytes
from this preparation onward. This model remains distinct from the full-RIT
deployment JSON; that manifest and its missing artifact are preserved. Neither
conversion nor synthetic parity produces a new accuracy/generalization result.

Profile v2, static diagnostics v3 and code evidence v4 invalidate older
extraction caches. New parser provenance adds no model predictor and changes
no canonical RIT values, sentinels, split or threshold. The structural parser
still uses `strict=False`; the JS parser still uses `strict=True`. Exceptions
are recorded as bounded fixed type/reason/stage codes, without raw messages.
Pypdf open-time recovery notices are recorded separately: a notice does not
prove a complete repair history or validity. PyMuPDF's native `is_repaired`
flag is recorded when available. No strict failure is silently retried with
looser validation or reported as successful JS inspection.

Run `run` only from VMware console after disconnecting both NAT and host-only
adapters and disabling shared folders, clipboard and drag/drop. The process
must be non-root. `--lab-isolated` attests the hypervisor settings, which cannot
be verified from the guest. The job separately rejects SSH, connected/unknown
NICs and shared filesystem mounts, before PDF access and again for every file.
It does not change NIC state. After preparation, commit the aggregate reports
and appended log before this official run; raw/private artifacts stay ignored.

```bash
.venv/bin/python scripts/16_benchmark_cic_static.py run \
  --prepared-run <completed_prepare_run_id> --lab-isolated
```

If the saved deployment JSON is available as a trusted local copy, add
`--model-file /local/path/xgb_rit_full_drop3constant.json` to that same `run`
command. The worker LAB guard runs first; installation checks the existing
manifest SHA before model loading, then validates all38 feature names/order
and the saved configuration. It neither fits a new model nor overwrites an
existing artifact, and rolls back a newly installed file if validation fails.
The model remains ignored at `artifacts/models/xgb_rit_full_drop3constant.json`.
Missing/wrong models preserve diagnostics and explicit unavailable inference.

For metadata/model-only restoration before an offline run, `restore-model
--model-file /trusted/local/copy.json` records a separate immutable restoration
run. Commit its aggregate report/log before the later official invocation;
using `run --model-file` instead keeps restoration in the profiling run.

Every file uses a fresh Linux spawn process, default one worker, 10 MiB input,
1 GiB address space, 12 CPU seconds and 20 wall seconds. Model/experiment
imports stay inside CLI main; limits precede PDF/JS parser imports and input
reads in the worker. Timeout/cleanup kills the process group. Exit signals are
reported without claiming that SIGKILL proves a particular memory/CPU cause.
JSON contains bounded numeric features and redacted syntax evidence; parser
exception text, payloads, strings and URLs are not exported.

`artifacts/cic_static_profile/<run>/per_file_inventory.csv` identifies every
attempt and its last stage/status/error codes. `per_file.jsonl` retains bounded
details; `failures.jsonl` retains incomplete attempts. No failure is removed
from planned counts. Aggregate `pipeline_summary.json` distinguishes complete,
partial, parser error, wall timeout, resource/signal, input and worker failures;
AST parse errors and error-code counts overlap those exclusive statuses.
Interrupted attempts retain recorded rows and report not-started counts.
The v2 inventory also includes `reasons`, covering warnings that caused
structural incompleteness even when `errors` is empty. Aggregate summaries
report parser failure categories, parser disagreement, repair flags and
prediction-unavailable reasons. `baseline_comparison.json` pairs the fixed
cohort's before/after statuses; private `baseline_file_pairs.csv` retains
individual identities and reasons without rereading old PDFs.

Stage times are exclusive: read/hash, raw token scan, parse, explicit JS stream
decode, AST, inference gate and inference. The analyzer and JS inspector reuse one byte
snapshot; checksum verification and analyzer verification are both measured.
Implicit xref/object/content decoding and reference text extraction inside
pypdf/PyMuPDF are included in parse; they are not falsely reported as separately
measured stream time. Unreached stages are null. Startup, cache and IPC overhead
are reported alongside total per-file p50/p95, sum and measured/unavailable
counts. Frozen verified deployment-model load is recorded separately.
`inference` measures only `predict_proba`. Gate checks, feature/model checks
and probability/response validation are in `inference_gate`; model absence
or parser refusal leaves inference null and `inference_executed=false`.
A called model that fails remains a measured inference attempt but has no
available prediction. Model setup records fixed error codes such as
`deployment_artifact_missing`. Earlier v1 inference timings included refusals
and are not comparable to v2 model-call latency.
For a killed worker, `overhead_seconds` also includes work in its unfinished,
unmeasured stage. This residual is not a pure worker-startup/IPC measurement;
use total time, last stage and null-stage counts when diagnosing timeouts.

Cold means a fresh application feature cache. Warm verifies the PDF bytes/hash
again before reusing a complete profile. Partial/timeout results are not cached;
warm misses are reported explicitly. The OS page cache is uncontrolled: this
does not claim cold-disk latency. Cache keys include PDF SHA, schema/engine
source hashes, backend versions and limits. New config/source versions require
a newly prepared job. Worker peak RSS prefers current-process `/proc/self/status`
VmHWM; the rusage fallback is explicitly tagged. Earlier constant rusage peaks
and new peaks are not an extraction-only memory comparison. Killed-worker RSS and
concurrent parent+worker RSS use polling and are labeled lower bounds. RSS sums
may double count shared pages; RLIMIT_AS is not an RSS cap.

The confirmed fixture-level extractor gap was ASCIIHex/ASCII85 JS streams and
their bounded chains with Flate. The v3 code evidence schema adds support for
these filters with output limits, retaining explicit failures for invalid data
and unsupported parameters/filters. Canonical RIT41 semantics and models are
unchanged. The first64-PDF run completed23, partially analyzed23 and failed
the structural parser on18. The diagnosed timing/report issues and parser
provenance changes await the next disconnected LAB run; no coverage improvement
is claimed from fixture results.

The same job optionally fits two fixed CPU RF models on its selected CIC Train
rows: C0 RIT41 baseline; C1 baseline plus resolved structural counts and JS/AST.
Counts remain null where extraction failed. Train-only median imputation and
missingness indicators apply to numeric training views; raw evidence remains
unchanged. Both models use the same parser eligibility mask and fixed0.5
threshold. There is no tuning, calibration or Test evaluation. Report malicious
recall/FPR on classified dev rows, full-class detection/false-positive fractions,
coverage, refusals and class denominators; no missing row becomes benign.
Insufficient class/coverage data or identical new feature vectors crossing the
saved Train/dev boundary produces an unavailable comparison; no split is
regenerated and no rows are silently dropped. Feature equivalence is not PDF
identity. Previously
exposed Validation and 16 planned benign dev rows limit interpretation. These
are preparation/development capabilities, not demonstrated CIC improvements.

RIT remains CSV-only. No PDF identities, AST, stream or byte features are
invented for it; no RIT/CIC advanced-feature zero-fill or source mixing occurs.
Keep full identities and results in LAB. Only reviewed bounded feature types
and aggregate reports may enter the chosen controlled export process. Do not
transfer payloads or binary model/pickle artifacts to the host for loading.
Retain needed results, restore the clean VM baseline, then reconnect networking
according to the previously chosen LAB procedure.

## Current v5 paired job

The metadata-only job `run_20261010T060459185898Z_03bb11cdea2b` was prepared
from clean committed code. Its subset, configuration and frozen Protocol G
native model checksums match the previous same-64 job. The new code fingerprint
uses `pdf-code-inspection-v5`; older prepared jobs do not match this revision.
No dataset PDF was read during preparation. The full benign fixture suite
passed 706 tests; the dependency and whitespace checks passed. Preparation
verification is saved under the matching `reports/experiments/cic_static_prepare/`
directory.

After using the already selected disconnected non-root VMware console LAB
procedure (NAT and host-only off; shared folders/clipboard/drag-drop off), run:

```bash
.venv/bin/python scripts/16_benchmark_cic_static.py run \
  --prepared-run run_20261010T060459185898Z_03bb11cdea2b \
  --lab-isolated
```

This is the next measurement, not a completed new PDF benchmark. Inspect its
`pipeline_summary.json`, `baseline_comparison.json`, `feature_comparison.json`
and private failure inventory after the run. Recovered xref or traversal-budget
AST evidence remains partial. Changes in usable class counts must accompany
recall/FPR comparisons. The fixed cached-table CIC candidate did not improve
malicious F1/MCC and is not used by this job; see the
[accuracy diagnosis](cic_static_accuracy.md). End-to-end accuracy improvement
has not yet been demonstrated.
