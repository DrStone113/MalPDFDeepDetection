# Native MuPDF inventory: Windows DEV, 2026-10-19

The additive MuPDF inventory now traverses native objects instead of reparsing
whole object dictionaries with pypdf. This closes the inventory-specific shared
syntax dependency recorded in the extraction plan. The historical v8 recovery
adapter remains unchanged; inventory objects still do not feed the legacy
action/filter/carver graph. This does not complete stage 2 or prove better
malicious-PDF detection.

The preceding, separately approved workflow was committed as
`5222a287af896ae5320037850790036e5abf998b`. Its clean 321-file source package and
six-file public-key bootstrap were prepared locally. Neither was deployed in
this turn. The extractor changes described here remain a separate working diff
and are not part of that package or commit.

## Implementation and evidence

`src/malpdf/extraction/mupdf_adapter.py` uses native MuPDF object loading, type
inspection, dictionary/array traversal and raw-stream access. Object references
stay inert and preserve their declared generation; inventory owner generation
and file offset stay unknown. Common pypdf containers/text codecs and the raw
lexer's individual string decoder remain shared infrastructure. The adapter
version is explicitly recorded alongside the effective native library versions.

MuPDF int64 values avoid int32/float loss. Decimal projections preserve the
native selected real's canonical lexeme, including its already-rounded
precision; the merger keeps resulting native/QPDF/raw disagreements. Native
string bytes survive NUL and Unicode through a bounded escaped representation.
Unknown encoding or resource exhaustion sets explicit partial flags, including
field completeness. No unavailable stream becomes a verified empty stream.

The orchestrator imports the Linux worker lazily so direct parser tests and API
imports work on Windows. No Windows implementation of Linux process/resource
enforcement is claimed. Linux worker behavior, full primary-vector parity in a
real worker and actual LAB isolation still require separately approved checks.

The following commands ran with `.venv-windows-dev/Scripts/python.exe`, Python
3.11.16, on Windows. All PDF bytes were manually reviewed fixture generators;
no corpus, raw LAB artifacts, Test partition, model training, renderer or JS
runtime was used.

| Command after the Python executable | Result |
| --- | --- |
| `-m pytest tests/test_mupdf_adapter.py tests/test_parser_inventory.py -q` | 41 passed, 2 skipped: Linux worker timeout and full worker parity |
| `-m pytest tests/test_raw_forensic.py -q -k 'not worker_deadline_keeps_raw_syntax_and_primary_checkpoint and not isolated_raw_pass_keeps_primary_native_views_and_parent_verified_bytes and not parent_verifies_and_persists_raw_structural_decode_blobs'` | 63 passed, 3 deselected: Linux process/worker tests |
| `-m pytest tests/test_pdf_evidence_v8.py::test_readonly_mupdf_adapter_preserves_scripts_and_original_bytes tests/test_pdf_evidence_v8.py::test_matching_readonly_backend_views_do_not_conflict_on_stream_representation tests/test_pdf_evidence_v8.py::test_missing_startxref_recovery_stays_partial_with_primary_failure -q` | 3 passed: historical direct v8 behavior |

Total: **107 passed, 2 skipped, 3 deselected**. This is a focused, reviewed set,
not the repository-wide suite or functional verification on REMnux.

The new 22 cases cover the independent native call path, byte-preserving strings,
large integers, rounded-real disagreements, reference generation, invalid name
encoding, typed null/bool values, depth/node/string caps, shared raw-stream
allowance, genuine empty streams, unavailable hashes and portable API import.
An earlier collection attempt exposed the eager Linux `resource` import; lazy
worker loading removed that import obstacle without removing any OS limits.

The Git commit/dirty state, native/package versions and local validation
observations are saved under ignored
`artifacts/tmp/maintenance/extract_pdf/mupdf_native/`. No accuracy, performance or
new real-corpus coverage measurement was made. Related metrics are N/A.

## Remaining checks

- Linux disposable-worker timeout/cleanup and full primary/v8/v9 parity on the
  new code: NOT VERIFIED in this turn.
- New code deployed to the restricted REMnux workflow: NOT VERIFIED.
- Real-PDF extraction, threat coverage and downstream model impact: NOT RUN.
- Canonical-text v8 recovery removal, inventory-only object routing, complete
  Arlington/reachability, media/runtime/hybrid acceptance: remain open.
