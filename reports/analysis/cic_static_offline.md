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

Stage times are exclusive: read/hash, raw token scan, parse, explicit JS stream
decode, AST and inference. The analyzer and JS inspector reuse one byte
snapshot; checksum verification and analyzer verification are both measured.
Implicit xref/object/content decoding and reference text extraction inside
pypdf/PyMuPDF are included in parse; they are not falsely reported as separately
measured stream time. Unreached stages are null. Startup, cache and IPC overhead
are reported alongside total per-file p50/p95, sum and measured/unavailable
counts. Frozen verified deployment-model load is recorded separately.

Cold means a fresh application feature cache. Warm verifies the PDF bytes/hash
again before reusing a complete profile. Partial/timeout results are not cached;
warm misses are reported explicitly. The OS page cache is uncontrolled: this
does not claim cold-disk latency. Cache keys include PDF SHA, schema/engine
source hashes, backend versions and limits. New config/source versions require
a newly prepared job. Worker peak RSS uses kernel HWM; killed-worker RSS and
concurrent parent+worker RSS use polling and are labeled lower bounds. RSS sums
may double count shared pages; RLIMIT_AS is not an RSS cap.

The confirmed fixture-level extractor gap was ASCIIHex/ASCII85 JS streams and
their bounded chains with Flate. The v3 code evidence schema adds support for
these filters with output limits, retaining explicit failures for invalid data
and unsupported parameters/filters. Canonical RIT41 semantics and models are
unchanged. Impact on real CIC coverage awaits the disconnected LAB run.

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
