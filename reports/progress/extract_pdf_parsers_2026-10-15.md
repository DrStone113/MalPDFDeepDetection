# Extract-pdf native parser inventories — 2026-10-15

Status: additive QPDF/MuPDF/pypdf inventories and differential comparisons
implemented and verified with generated benign fixtures. The full
[extract-pdf roadmap](../../plans/extract-pdf/plan.md) remains open; see
[remaining acceptance](../../plans/extract-pdf/acceptance.md). No real PDF was
opened, hashed, parsed or decoded in this maintenance task.

## Behavior and limits

`qpdf_adapter.py`, `parser_views.py` and `parser_exports.py` add native xref/
object inventories after the existing primary/v8/v9, filter and recursive
artifact checkpoints. Every engine receives the original immutable snapshot;
no engine consumes a repaired PDF produced by another. All three inventories
are attempted even when primary succeeds, and their failures do not replace
original model measurements or completed checkpoints.

The declared `pikepdf==10.17.0` supplies the native QPDF reader. Recovery and
page-attribute inheritance are disabled. Objects are converted directly into
inert projection containers, without reparsing QPDF text or casting native
decimals to float. Only raw stream APIs are called; native decoded-stream,
whole-PDF syntax-check, save, render and action APIs are excluded. The
[upstream API reference](https://pikepdf.readthedocs.io/en/latest/api/main.html)
documents these controls. Native internal xref/object-stream decompression
remains covered by OS caps rather than an exact explicit decode ledger.

QPDF preserves selected object/generation pairs, compressed-container/index
metadata and offsets only after checking the original object header at that
offset. Compressed-object offsets remain null. pypdf exposes its xref candidates,
including retained generations, without assigning historical revisions. MuPDF
inventories current number-addressed xref slots; generation/file offsets remain
null. Its native selection and raw streams are independent, while the existing
adapter parses canonical MuPDF object text with pypdf syntax. This shared syntax
dependency remains a limitation on full parser independence. MuPDF observations
retain synthetic provenance. Warning counts/categories are retained without
sample text, including warnings arising during object reads.

Common bounded projections retain dictionary/array/scalar/reference hashes and
up to 64 root key/value hashes per object. Unknown names and string content are
hashed. Stream `/Length` is excluded from comparison because parsed dictionaries
do not prove authored lengths. Exact QPDF decimals survive adaptation; numeric
engine interpretation differences remain unresolved signals. Partial projections
and unavailable raw data do not become verified empty/absent values.

The merger matches known generations first. Number-only candidate comparisons
are explicitly uncertain and admitted only when both sides are unambiguous.
It preserves key/value/raw-stream and selected-generation disagreements,
without choosing a winner or claiming historical object/file identity. Missing
objects from failed/partial enumerations stay `not_observed_in_partial_view`.
Each comparison links its source observations, including one-sided scope.
Prior graph backend flags remain alongside native inventory coverage flags.

Caps are `max_objects` candidates per view, a shared `max_file_bytes` raw-byte
allowance across inventories, 1024 projection nodes/depth8 per object, 64 root key
details, 2048 comparisons and 1MiB combined metadata with terminal reserve.
Completed inventories and localized comparisons survive later metadata/worker
failure. Parent-verified blob retention shares the existing 10MiB allowance.
CPU/wall/RAM limits and earlier decode/AST budgets are unchanged. Carved JS AST
time is now measured separately and retained when the root has no scripts.

These are xref interpretations, not complete raw forensic coverage. The plan's
QPDF/MuPDF/raw-forensic trio still requires a full original-byte syntax/xref/
trailer/orphan parser and revision identity. Newly discovered inventory-only
objects are not yet routed through graph/filter/carver analysis. Nested PDFs
retain their prior v9 inventory path. Native media, Arlington, abstract JS
semantics, visual/dynamic tiers, reingestion, release packaging, labeled threat
studies and real-PDF acceptance remain open.

## Fresh environment and verification

A fresh root `.venv/` was created with Python 3.11.17 and installed from
`pyproject.toml` using `-e '.[dev]'` and the PyTorch CPU extra index. The previous
venv was temporarily retained for rollback, then removed after the full suite
passed. Its temporary ignore entry was removed; the original `.gitignore`
content was restored exactly. No source-tree copy or artifact virtualenv remains.

Effective versions: pikepdf 10.17.0, QPDF 12.4.2, PyMuPDF 1.26.7 with MuPDF 1.26.12,
PyTorch 2.11.0+cpu and torchvision 0.26.0+cpu; the PyTorch CUDA build is null.
Compared with the prior environment, pikepdf/lxml were added and narwhals,
filelock and fonttools changed. The saved environment lists every effective
package version; this run is not asserted identical to previous runs. The
existing XGBoost declaration still brings its NCCL dependency; PyTorch CPU
selection does not claim a dependency tree containing no NVIDIA packages.

Final complete suite: **1184 passed**, 2 existing single-label sklearn warnings,
167.79 seconds, outside the tool sandbox with bounded BLAS threads and
disk-backed synthetic scratch. This adds 22 cases to the previous 1162-test
source: 21 native inventory cases and one carved-AST timing case. Suite duration
does not measure extraction speed or quality on real PDFs.

Fixtures cover actual installed QPDF/MuPDF/pypdf, immutable input and exact
primary/code/v8 parity, compressed objects, nonzero generations, verified
offsets, key/value/stream/generation conflicts, exact decimal adaptation,
encrypted and damaged-xref refusal, partial/failed enumerations, native API
exclusions, raw/metadata/object limits, retention and worker timeout cleanup.
Earlier logs preserve an absent test-path invocation, a monkeypatch targeting
the pikepdf factory rather than its Object API, and a Real-constructor fixture
that rounded before parsing. Corrected targeted checks passed; failed evidence
was retained. The final full suite covers the final sources.

Maintenance ID: `run_20261015T083427333186Z_7d02abdb85da`.
Generating commit: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, dirty worktree
recorded. No staging or commit. Root README, unrelated edits, old reports and
the research-log prefix were preserved. Full dependency/diff/ignore/link/source
preservation checks passed. Completed synthetic scratch directories were removed.

Private evidence under `artifacts/tmp/maintenance/extract_pdf/`:
`multiparser_install.log`, `multiparser_environment.json`,
`multiparser_release_pytest.log`, `multiparser_pip_check.log`,
`multiparser_checks.json`, `multiparser_preservation_checks.json`,
`multiparser_prepare_audit.json`, and retained targeted logs.

## Prepared job and remaining runtime boundary

New metadata-only preparation: `run_20261015T120337358471Z_7d02abdb85da`.

- [Run summary](../experiments/pdf_extraction_prepare/run_20261015T120337358471Z_7d02abdb85da/run_summary.json)
- [Manifest paths/hashes and selection checks](../experiments/pdf_extraction_prepare/run_20261015T120337358471Z_7d02abdb85da/preparation_checks.json)
- [Locked methodology](../experiments/pdf_extraction_prepare/run_20261015T120337358471Z_7d02abdb85da/locked_methodology.json)
- [Recorded environment](../experiments/pdf_extraction_prepare/run_20261015T120337358471Z_7d02abdb85da/environment_metadata.json)

The private lock pins 200 source/config files plus packages, native QPDF/MuPDF
versions, platform and budgets. It retains exactly the preceding 64 records:
32 Train and 32 previously exposed Validation, 16/class/partition, saved Protocol G
seed42. All three manifest paths/checksums and the selection digest match the
prior lock; no split regeneration, PDF byte access, Test selection, model load,
fitting or extraction execution claim occurred. Old fingerprints are refused.

```bash
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T120337358471Z_7d02abdb85da
```

The metadata check passed. Execution still requires reviewed/committed matching
source and confirmation at the non-root VMware console of disconnected NICs,
disabled shared folders/clipboard/drag-and-drop and a credential/agent-forwarding
audit. The SSH connection does not provide offline isolation. No network or
sharing setting was changed. Follow [the guarded offline procedure](../../docs/pdf_extraction.md#reproducible-offline-cic-job)
only once those conditions hold. Rendering, JS execution/emulation, Reader and
CAPE remain outside authorization. The historic 21 partial Validation PDFs have
not been rerun, and these fixture tests establish no detector or corpus-coverage
gain. F1/MCC/ECE/Brier are N/A: no model/partition evaluation. Label=1 is malicious;
ECE uses 10 equal-width malicious-probability bins with p=1 in the final bin.
