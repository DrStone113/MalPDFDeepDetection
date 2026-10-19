# Static extraction on the dedicated VM

The 2026-10-19 safety review makes bounded execution the default for
`extract_pdf()` and `malpdf extract`, with one worker by default for batch API
calls. Windows path-based extraction is refused before input access. This
document describes the explicit legacy VM policy introduced on 2026-10-18;
it requires separately approved LAB work and does not enforce resource quotas.
The implementation reuses the existing raw profiler, three
native inventories, independent raw grammar, filter matrix, recursive carver,
Arlington rules, script AST/semantics, evidence graph and three-store exports.
PDFs remain immutable binary inputs. No page rendering, JavaScript execution,
URI access or Reader execution is performed.

## Running extraction

Real-corpus execution requires the user's confirmation that the LAB is isolated
and an explicit request to run. The `vm` action does not automatically verify
isolation. During development, inspect saved JSON and use generated benign
fixtures; do not reopen corpus PDFs or retained payloads to validate a change.

From the repository root, use the active environment:

```bash
source .venv/bin/activate
python scripts/22_extract_pdf.py vm
```

The scheduler keeps all available CPU slots active and submits the next PDF
before yielding a completed bundle to the output writer. Override the worker
count for a measured comparison with `--workers 1` or `--workers 4`.
The console reports `sample_started`, `sample_finished` and a `workers_active`
heartbeat while files remain in progress; a long file does not prevent new work
from starting in another free slot.

`configs/extraction_vm.yaml` selects all CIC rows in the saved Protocol G Train
and Validation partitions with seed 42. It does not rebalance, truncate to 32
rows, regenerate partitions or inspect Test by default. The current saved
manifests select 1,161 rows: 870 Train and 291 Validation. This count was checked
from metadata; it does not describe a completed corpus extraction run.

Set `workers: auto` to use all CPUs available to the process. An explicit positive
worker count is supported, bounded only by the available CPUs and input count.
`partitions` selects existing partitions; Test may be included explicitly for
static extraction, and no classifier is fitted or evaluated by this command.
Manifests are verified by their declared checksums, labels and provenance.
Duplicate hashes, duplicate groups and related lineages must stay within one
partition, including groups in excluded partitions. Different labels in a related
lineage remain possible; identical PDF hashes cannot have conflicting labels.

For one file:

```bash
python -m malpdf extract data/raw/cic_pdf/example.pdf --execution-mode vm \
  --arlington-lock configs/arlington.lock.json
```

For library callers, `malpdf.extraction.extract_pdfs(paths, boundary=...,
workers=None)` now selects one bounded worker and yields `(input_index, bundle)`
in completion order. VM jobs pass explicit `VMInspectionLimits` and their
configured worker count; the old policy is not selected implicitly. Repeated
inputs keep distinct occurrences. Thread coordinators supervise separate spawned
parser processes; parsing runs in those disposable processes. Only the active
worker count is submitted at once. Closing the iterator cancels and reaps active
workers. One sample's exception produces an explicit failed bundle and does not
discard sibling results. Pass `expected_hashes` to verify every input identity.

## Resource policy and parser safeguards

`VMInspectionLimits` leaves CPU, address-space and wall time quotas unset. The
worker records inherited OS limits and does not change BLAS/OpenMP environment
variables. Input, decoded-byte, graph, IPC and retention allowances use
`sys.maxsize - 1`, the representable buffer boundary with room for a sentinel
byte, instead of the former 10 MB/1 MB/4 MB quotas. This is recorded explicitly
in requested capacities. The raw profiler scans all windows, names and markers.
Native projections, differential comparisons, raw IR and Arlington/semantic
ledgers similarly use that representational capacity in VM mode.

Graph cycle detection, verified stream boundaries, maximum parser/AST depth,
recursive artifact depth and decompression expansion-ratio checks remain active
as required by the extraction plan. Byte-image tile sampling, abstract-value
widening and trigger-plan quotas remain representation/analysis choices; their
scope and incomplete states are retained. These checks can still produce
`partial`, `unsupported`, `decode_error`, `encrypted` or `resource_limit`.
VM mode does not imply whole-document conformance or complete threat coverage.
Workers retain the no-core-dump and no-child-file-write policies; the parent
persists verified blobs. Process separation is failure isolation, not containment.

`CodeInspectionLimits(...)` and `--execution-mode bounded` are now the default
policy. Pass `VMInspectionLimits(...)` or `--execution-mode vm` explicitly only
for separately reviewed legacy LAB runs with agreed resource controls. The old
`prepare/check/run` actions, pinned launcher and consumed claims remain historical
compatibility paths. Their clean-commit, credential and console-isolation gates
do not apply to the new `vm` action. No existing benchmark lock, claim or output
is reset. A new VM invocation creates its own run and can use a dirty worktree.

## Outputs and provenance

VM snapshots are coalesced between stage boundaries. Native inventories flush
after each backend and at completion; raw forensic output flushes after the
sequential scan, selected-view comparison and final graph; streams, carving and
Arlington flush their final states. The scheduler waits at least 0.5 seconds
between ordinary snapshots, increasing that interval when copying/transport is
expensive. This controls logging work, not extraction time or feature scope.
Finite metadata budgets still run their existing checks. Completed stage output
is unchanged; a crash inside a stage preserves the last flushed prefix and
keeps its interrupted/partial status. The bounded policy keeps its old cadence.
VM input/worker failures remain explicit even when an Arlington reference
directory is outside a Git checkout; provenance falls back to the loaded code's
repository instead of discarding the primary extraction result.

Arlington shares completed schema evaluations within one immutable document,
PDF version and xref context. Acyclic subtrees can be reused only when their
dependencies do not intersect active ancestors and their height fits the
remaining rule depth. Results involving cycles require the identical active
ancestor set and entry depth. Interrupted evaluations are never reused;
unsupported rules and cycles retain their unknown outcomes. Stream/dictionary
context is part of the identity. The bounded policy retains per-path evaluation.

`arlington_binding_reuse` evidence preserves each incoming link, original raw
sources and the canonical binding it reused. Reuse records expose their cache
scope and a hashed link path. `arlington_candidate_checks_*` counts stored rule
checks, with shared evaluations counted once; `arlington_reused_schema_bindings`
counts reuse links separately. Compare this representation with historical
counts using those scopes, not by assuming identical per-path multiplicity.
The primary legacy measurements and original raw IR are unchanged.

Out-of-file xref offsets now produce `forensic_xref_offset_invalid`, separate
from `forensic_xref_count_limit` for an exhausted traversal allowance. Malformed
offsets alone do not imply resource exhaustion. This does not repair or trust
the malformed xref. Other parser/decode/cycle/expansion causes remain explicit.

Formal run metadata goes to
`reports/experiments/pdf_extraction_vm/run_<UTC>_<commit>/`, including
`locked_methodology.json`, `model_comparison.csv`, `runtime_environment.json`
and `coverage_summary.json`. Per-sample bundles, selection metadata and binary
streams go under ignored `data/processed/pdf_extraction/<run>/`. The binary
inputs in `data/raw/` are never overwritten. Arlington is loaded and verified
once per batch, then supplied to each disposable worker.

Each run records the Git HEAD and dirty worktree, generating-source hashes,
manifest identities, seed, effective workers, Python/package/native-library
versions, CPU/RAM and CUDA/GPU availability. Every completed failure remains in
the planned-row denominator. Interruption preserves completed bundles, an
interrupted summary and the count of rows not completed. Timing median/P99 and
peak worker RSS describe measured rows only; they are not detector metrics.
`ResearchRun` appends the existing research register, with F1/MCC/ECE/Brier marked
N/A when no model was evaluated.

Coverage and run output metadata are finalized even if iterator cleanup itself
raises an interruption. This retains the completed-row denominator and resume
path after an interrupt during worker cleanup. Abrupt process termination or
another interruption during report writing can still prevent finalization;
the per-sample completion journal remains separate evidence.

## Resume a finished or interrupted invocation

```bash
python scripts/22_extract_pdf.py vm --resume-from run_REPLACE_WITH_SOURCE_RUN_ID
```

Use a `pdf_extraction_vm` run ID printed by the VM command. A fresh output run
is always created. `completed_samples.jsonl` records the SHA-256 of each fully
written compact JSON record. A partial JSON write or a torn journal tail cannot
be mistaken for a completed sample. Reused occurrences retain their global
input indices, saved labels, partitions and original evidence, plus
`reused_from`/`resumed_by` provenance.

Resume verifies the source run's code/environment fingerprint, reference model,
selection, record hash, bundle contract, input PDF hash, worker completion and
retained blob hashes. A finished partial/unsupported parser scope can be reused;
an aborted worker or changed/missing/corrupt input, bundle or blob is recomputed.
A changed code/environment/selection fingerprint starts a fresh extraction and
reports `resume.status=incompatible`; historical locks do not block the new run.
Runs created before the completion journal and worker-completion marker cannot
be reused through this path. Resume is between PDFs, not within a PDF.

Retained blobs of reused records stay in the verified source run and their
provenance paths remain explicit. Keep those source directories while using the
resumed dataset. A later resume re-verifies those original blobs as well.
Coverage summaries separate `reused` and `newly_extracted`; worker timing
statistics include new extraction only. All planned samples, including failures
and rows not completed at interruption, remain in the coverage denominator.

## Verification and remaining plan work

`tests/test_extraction_performance.py` verifies scheduler cadence with a fake
clock, final evidence parity against every-snapshot execution, final flushes,
worker refill while the consumer is paused, global indices, resume chains,
interrupted prefixes, checksum/worker/input/blob rejection and source drift.
The [performance report](../reports/progress/extract_pdf_performance_2026-10-18.md)
records isolated-stage measurements, a serial/parallel batch comparison and
three paired historical Train/Validation samples. These are diagnostic
measurements, not a full-cohort throughput or detector-quality claim.

`tests/test_extraction_result_fixes.py` adds generated DAG/cyclic-schema parity,
version/xref/stream separation, ancestor/depth guards, unfinished-evaluation
rejection, exported reuse references, malformed xref classification and cleanup
interruption/resume checks. The
[saved-result review](../reports/progress/extract_pdf_saved_review_2026-10-18.md)
records the 44 completed JSON records that motivated these changes and the
separate synthetic verification. No corpus PDF is reopened for that review.

`tests/test_extraction_vm.py` uses generated benign PDFs and synthetic manifests
to check larger inputs/streams/IR, complete raw scans, wide dictionaries,
concurrent failure isolation, cancellation, duplicate occurrences, split
integrity, dirty-worktree runs, repeated fresh outputs and environment recording.
The existing bounded/checkpoint/parser/schema tests continue to exercise the
historical path. No dataset is required by these tests.

Native media decoding, complete Arlington conformance, interprocedural JS/heap
analysis, page OCR/QR, JS emulation, Reader/CAPE execution, dynamic artifact
reingestion and labeled threat-family benchmarks remain open in the six-stage
plan. The current static-only repository rule excludes executing or rendering
PDF samples. Test fixtures and valid JSON schemas do not establish those
capabilities or an increase in malicious-PDF detection accuracy.
