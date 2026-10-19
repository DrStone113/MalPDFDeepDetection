# Windows DEV extraction validation, 2026-10-19

This follow-up improves admission and the reliability of incomplete evidence.
It does not establish malware containment or superior detection on real PDFs.
All execution in this turn was local Windows DEV with
`.venv-windows-dev/Scripts/python.exe`, Python 3.11.16. No real PDF corpus, LAB
connection, rendering, JavaScript runtime, model training or Test partition was
used. The source remains uncommitted on top of
`5222a287af896ae5320037850790036e5abf998b`; earlier runs and their artifacts remain
unchanged.

## Corrections

- Path-based extraction, batch extraction and the `22_extract_pdf.py vm/run`
  entry points refuse Windows before reading PDF inputs or starting workers.
  Setting `MALPDF_LAB_ISOLATED=1` does not bypass this guard. Corpus path checks
  also recognize case variants of `data/raw` and `data/external`.
- API/CLI defaults are finite. The API uses 8s wall/4s CPU/1GiB address-space
  limits, the CLI uses 20s/12s/1GiB, and batch defaults to one worker. These OS
  limits apply to the existing Linux worker, not to direct Windows native calls.
  Explicit legacy VM execution remains unbounded and requires a separately
  agreed LAB operation; an environment variable is not isolation evidence.
- A nested array/dictionary cut at its node budget previously could leave its
  root field marked complete. Truncation accounting now marks that field
  incomplete while retaining independent complete fields. Existing projection
  hash structure is preserved; the merger cannot assert a conflict from a
  truncated field.
- QPDF now retains both projection and raw-byte exhaustion reasons when they
  occur together. The inventory propagates unknown field flags and unavailable
  stream hashes, avoiding a confirmed empty/null/absent measurement.

The platform guard is an application safeguard, not an OS security boundary.
Internal byte APIs remain available for reviewed synthetic fixtures. There is
no Windows worker memory containment, real-sample authorization or verified LAB
isolation implied by these changes.

## Reviewed synthetic execution

All commands below ran after reviewing their fixtures and collection paths.
They use generated inert syntax and bounded byte buffers, without discovering
PDF files in the workspace. Commands are shown after the dedicated Python
executable.

| Command | Result |
| --- | --- |
| `-m pytest tests/test_extraction_admission.py tests/test_parser_projection_limits.py tests/test_mupdf_adapter.py tests/test_parser_inventory.py -q` | 61 passed; 2 Linux worker tests skipped |
| `-m pytest tests/test_raw_forensic.py -q -k 'not worker_deadline_keeps_raw_syntax_and_primary_checkpoint and not isolated_raw_pass_keeps_primary_native_views_and_parent_verified_bytes and not parent_verifies_and_persists_raw_structural_decode_blobs'` | 63 passed; 3 Linux process/worker cases deselected |
| `-m pytest tests/test_pdf_evidence_v8.py::test_readonly_mupdf_adapter_preserves_scripts_and_original_bytes tests/test_pdf_evidence_v8.py::test_matching_readonly_backend_views_do_not_conflict_on_stream_representation tests/test_pdf_evidence_v8.py::test_missing_startxref_recovery_stays_partial_with_primary_failure -q` | 3 passed |
| `scripts/25_validate_extractor_synthetic.py --save` | 52/52 scalar probes passed for each adapter |

Total focused pytest result: **127 passed, 2 skipped, 3 deselected**. This is not
the repository-wide suite. Linux worker cleanup, OS limits and complete pipeline
parity on the new source remain unverified in this turn. The standalone
`22_extract_pdf.py vm` Windows invocation was also refused; subprocess regression
tests verify exit code 2 for both `vm` and `run`, without a Linux import traceback.

The synthetic validator accepts no PDF paths and generates 52 fixtures of at
most 4096 bytes with seed 42. Its independent expected scalar values cover
signed int64 boundaries, representable reals, booleans, null, escaped UTF-8 names,
unresolved references/generations, all 256 string byte values, UTF-16 BOMs and
deterministic random strings encoded as hex or octal literals. A serial child
process compares the native inventory adapter and historical v8 recovery
adapter; the parent applies a 60s timeout. No renderer, native decoded-stream API
or sample code is invoked. Diagnostic JSON contains fixed case descriptors,
hashes, source/package identity and timings, with no PDF bytes or extracted text.

Both adapters passed the scalar oracle. This shows preservation of these
values; it does not demonstrate improved corpus coverage or detector accuracy.
Timings are single-run per-case creation/read/close diagnostics, with imports
before timing and the first native open retained. Host load and startup vary;
they do not establish a speed advantage. Saved observations are under
`artifacts/tmp/maintenance/extract_pdf/synthetic_scalar/`, including
`run_20261019T155309148095Z/validation.json`. Final source/test validation is
recorded in a separate fresh Windows-safety maintenance directory.

`scripts/lab/check_local.py --save` passed: 291 Python sources parsed by AST,
18 declared dependency versions satisfied, reviewed imports and `pip check`
passed, repository-content guard/diff checks passed, and 24 source/workflow
security regressions passed. The Python/package environment is recorded in
`artifacts/tmp/maintenance/lab_workflow/windows_20261019T155029277092Z.json`.
This source-only workflow check is separate from the 127 focused extractor tests.

## Comparative acceptance still required

Before claiming superiority, lock a baseline and candidate source revision and
use the same approved Protocol G Train/Validation manifest, seed 42, extraction
profile and resource budgets on LAB. Keep failures in denominators and retain
missing evidence. Measure primary-feature preservation, labeled evidence gains,
parser completeness, confirmed false absences/conflicts, timeout/failure rate,
median/P99 duration and peak RSS. Model recall/FPR requires its own validation
design; extraction counts alone cannot prove detection gain. No Test access or
split regeneration is part of this follow-up.

Real-sample commands, input/output manifests, containment, finite resource/time
bounds and recovery need current-task approval under AGENTS.md. No commit,
push, deployment or real-PDF run was performed here.
