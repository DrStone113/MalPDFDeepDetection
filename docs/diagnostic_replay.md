# BUG-007B1 — Diagnostic Replay contract

B1 replays exactly the 74 unresolved identities from the saved graph audit. It does not execute B2, repair parsers, change graph semantics or node cap 200, modify the original corpus/bundles, or train models.

## Locked inputs

`configs/pdf_diagnostic_replay.json` pins the baseline job/result hashes, canonical selection hash, audit cases hash and 74 ordered baseline indices. Each record retains SHA-256, label, split, baseline bundle checksum, legacy worker fields and empty projection counts. The selection is 70 unspecified worker failures and 4 timeouts; index 141 is excluded. The baseline index is distinct from the replay ordinal 0–73.

Preparation validates all 74 baseline bundles, identities and protected source hashes using saved JSON only. Raw PDF paths are checked for containment, symlinks, existence and size using metadata; PDF bytes are first opened during operator-triggered extraction. The replay job kind is `pdf-diagnostic-replay`, offline only. Its limits equal the full baseline limits except `samples=74`: 35 s wall / 30 s CPU / 1 GiB address-space budget / 10 MiB file cap per PDF; 10 outer workers, 7200 s job wall and 2 GiB output budget. Other object/decode/AST limits keep their existing `CodeInspectionLimits` defaults.

`locked_methodology.json` at the new LAB job records the release commit, archive/manifest hashes, lock hash, all 74 identities, unchanged-code hashes, exact limits and staging-time environment (Python/package versions, platform, CPU/memory and thread settings). During execution, shards verify `locked_methodology.json` read-only: all methodology fields, source hashes, sample identities, limits, Python version, machine architecture, package versions and thread settings must match exactly, while boot-varying kernel `/proc/meminfo` `MemTotal` (`memory_bytes >= file_memory_bytes`), kernel platform string and logical CPU count are recorded per shard in `private_outer/environment.<shard>.json` without rewriting `locked_methodology.json` ([BUG-008](bugs/BUG-008-replay-methodology-boot-memtotal-mismatch.md)). No source file is edited on REMnux.

## Execution and preservation

The existing `lab run` console is the only real-sample trigger. Existing isolation, credential, human-attestation and claim checks remain active. SSH staging and metadata validation never invoke the extractor on corpus PDFs.

New results live under `/var/lib/malpdf/jobs/<new_job_id>/`, never inside the baseline job:

- `private_attempts/<ordinal>_<attempt_id>/worker.json` preserves the worker diagnostic snapshot before bundle normalization; errors after the worker cannot erase it.
- `private_attempts/.../bundle.json` and `private_bundles/<ordinal>.json` retain the actual validated bundle, published without overwrite.
- `private_cases/<ordinal>.json` records baseline comparison, diagnostic, parent exception if present, graph counts and evidence classification. Exception messages, source lines and locals are omitted. Raw bounded stderr stays in private LAB artifacts.
- `pdf_summary.<shard>.json` retains the existing runner summary contract.
- `private_outer/exception.<shard>.json` preserves a shard-level exception before its outer process exits. `transport.<shard>.json` keeps bounded stdout/stderr and the exit observation before supervisor cleanup; `cleanup.json` records cleanup exit codes separately. Transport reads use `pread` on LAB so reading diagnostics cannot change a running writer's file offset. Diagnostic write failure cannot prevent supervisor cleanup.

No baseline cache is imported. Resume may reuse only this same replay job's validated case/bundle with matching run/sample identity and checksum. Existing completed shard summaries are verified before reuse. Interrupted attempts are preserved. Cleanup uncertainty halts the shard; protected pre-spawn phases (`validation`, `profile_boundary`, `worker_admission`, `worker_start` when no child PID was created) and `input_error` establish that no worker was started without fabricating `cleanup_complete=true`.

The optional `extract_pdf(..., profile_observer=...)` receives the real profile before normalization. It adds observation only; default extraction behavior and graph builders are unchanged.

## Comparison and classification

Replay stores original and cleanup exit codes separately. The baseline's legacy exit code is explicitly a post-cleanup observation. A nonempty projection after replay is `graph_restored=true`; it does not certify full PDF recovery, semantic correctness or training readiness. Failure before a graph measurement produces `null`, while an actually measured empty projection produces 0 nodes/edges. Node sizes retain the existing definition and unknowns; tensor feature dimension stays `null`.

Mechanisms are reported only from observed diagnostics: wall timeout, allocation failure, MemoryError, unresolved signal/exit, IPC/serialization, admission or worker exception, graph-build exception, post-worker/boundary exception, no observed worker failure, or unresolved. `SIGKILL` is not classified as kernel OOM. A `ValueError` during parsing does not by itself establish a parser defect or corrupt PDF. Root cause remains `null` where the evidence does not establish it. Identical diagnostic signatures form investigation groups, not proven shared root causes.

## Automatic post-run analysis and export

After all shards finish, including an outer-process failure, the runner invokes its fixed `replay-report` command automatically. It writes `analysis/cases.jsonl` with all 74 identities, `analysis/summary.json`, `analysis/report.md`, `analysis/outer_diagnostics.json` and a checksum manifest. Missing or invalid cases keep their denominator and have `case=null`. The summary separates attempted cases, available diagnostics, measured graphs and restored projections. The outer diagnostic file maps each shard to its assigned baseline indices, with safe traceback and stderr size/hash only. It does not turn a shard setup failure into a claimed per-PDF extraction attempt.

The closed export validator `validate_export` checks identity/order, labels/splits, null semantics, numeric counts, safe traceback fields, enums, counts and grouping. Exported diagnostics contain stderr byte count/hash and capture flags, never stderr text, exception messages, locals or source. Parent tracebacks use the same restrictions. Source artifacts are kept at LAB; only the exact validated analysis files may be retrieved to Windows.

Repeated analysis of unchanged results is idempotent; differing existing analysis artifacts are refused. This preserves previous output instead of silently replacing a report.

## Verification and completion boundary

`tests/test_diagnostic_replay.py` covers the 74-case scope, tampering, immutable identity, limits/offline requirement, classification limits, original/cleanup evidence, null graph measurements, restored graph with unknown size, private stderr/export rejection, closed record/summary validation, pre-normalization observation, durable attempt artifacts and same-job resume. Path extraction tests use the existing reviewed benign fixture and run only in Linux LAB.

B1 cannot be called complete before the operator run and validation of its 74 real replay records. BUG-007B also remains open until the separate B2 truncation audit and B3 extraction quality gate are finished.
