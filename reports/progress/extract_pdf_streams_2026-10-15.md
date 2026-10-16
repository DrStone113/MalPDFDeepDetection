# Extract-pdf stream filter implementation — 2026-10-15

Status: additive static filter-matrix implementation and a new metadata-only
offline job prepared. The six-stage [original plan](../../plans/extract-pdf/plan.md)
remains open; see the [full acceptance inventory](../../plans/extract-pdf/acceptance.md).
No real PDF was opened, hashed, decoded or executed in this maintenance task.

## Implemented behavior and evidence

`malpdf.extraction.filters` decodes ordered Flate, LZW (EarlyChange0/1), ASCIIHex,
ASCII85 and RunLength filters with PDF aliases. It supports TIFF horizontal
differencing for 1/2/4/8/16-bit samples and PNG None/Sub/Up/Average/Paeth
prediction. It records parameters, raw/input/output identities, byte debit and
the result of each layer. Unknown/media codecs are unsupported; Crypt requires
a context except for explicit Identity passthrough. No renderer or JS engine is
invoked.

`malpdf.extraction.streams` observes streams in the existing v9 catalog graph,
then spends only v9's remaining decoded-byte budget. Every completed layer has
an independent checkpoint. If a later layer stops, prior layers and their source
relationships remain available. A partial prefix is never input to a later
filter and is never labeled a complete decoded stream. Unknown offsets/revisions
and unverified original `/Length` remain unavailable.

The shared limits are the existing worker's wall/CPU/RAM/file caps, remaining
decoded-byte allowance and parent transport budget. Supplemental limits cover
128 discovered streams, eight filters, 1MiB output per layer, expansion ratio100,
one shared parameter-reference read allowance derived from max_objects, and
512KiB metadata with space for an active stream and terminal reasons.

Parent-held transport verifies size/hash before recording a blob. The offline
runner requests non-executable digest-named raw/intermediate/prefix blobs in
ignored `data/processed/pdf_extraction/<run>/sample_<index>_streams/`, sharing the
existing 10MiB per-sample retention cap with v9. `verified_not_persisted` remains
distinct from persisted `verified` evidence for callers that do not request
storage. Blob identity verification does not certify a damaged stream's decoded
semantics.

Synthetic integration tests compare exact original primary features, code view
and v8 view before/after the supplement. They also verify escaped filter names,
object/generation/byte identities, true empty output versus unsupported/encrypted/
malformed data, retention and source/metadata/byte limits. Worker-deadline tests
keep completed filter metadata inside an unfinished stream and reap the child.
Unresolvable filter references remain partial; known backend limits and unsupported
generations retain their own statuses. These fixture results do not prove
preservation on the historic 21 real partial Validation files.

## Validation

Final complete suite: **1114 passed**, 2 existing single-label sklearn warnings,
253.50 seconds. This adds 76 stream decoder/integration cases to the previous
1038-test foundation. Python3.11.17 in the preserved root `.venv/`; dependencies
unchanged. `pip check`, diff, ignore, source-preservation and local-link checks
passed. Fresh-environment installation/validation was not performed.

The suite ran outside the tool sandbox using the documented disk-backed
temporary fixture directory and bounded BLAS threads. Earlier full checks
(1106/1110 cases) and the initial regression demonstrating incorrect decode-error
classification of unavailable references are retained separately. Final-source
verification is the 1114-case log, not those earlier checks. Fixture-suite duration
is not a real-PDF extraction throughput measurement.

Maintenance ID: `run_20261015T070014164994Z_7d02abdb85da`.
Generating HEAD: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, dirty worktree
recorded with source hashes. Existing unrelated edits, prior reports and the
research-log prefix were preserved; nothing was staged or committed.

Private evidence is grouped in `artifacts/tmp/maintenance/extract_pdf/`:
`stream_release_pytest.log`, `stream_release_prepare.log`,
`stream_decoding_checks.json`, `stream_preservation_checks.json`, and the retained
targeted/regression logs. Completed synthetic fixture directories were removed.
No new top-level artifact directory, source-tree copy or artifact virtualenv was
created.

## Current prepared job

ID: `run_20261015T074139030904Z_7d02abdb85da`.

- [Preparation summary](../experiments/pdf_extraction_prepare/run_20261015T074139030904Z_7d02abdb85da/run_summary.json)
- [Manifest paths, hashes and selection checks](../experiments/pdf_extraction_prepare/run_20261015T074139030904Z_7d02abdb85da/preparation_checks.json)
- [Locked methodology](../experiments/pdf_extraction_prepare/run_20261015T074139030904Z_7d02abdb85da/locked_methodology.json)
- [Recorded environment](../experiments/pdf_extraction_prepare/run_20261015T074139030904Z_7d02abdb85da/environment_metadata.json)

The new private lock pins the final sources/packages and the same64 selection
as the first foundation preparation: 32 Train and 32 previously exposed
Validation, 16 per class/partition, Protocol G seed42. All three saved manifest
checksums match. No Test identity was selected, no split was regenerated and no
PDF bytes were read. Earlier job/report directories remain intact; old source
fingerprints are refused after implementation changes.

Metadata-only check:

```bash
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T074139030904Z_7d02abdb85da
```

Actual execution still requires review/commit of matching source, the non-root
VMware console, disconnected NICs, disabled sharing/clipboard/drag-and-drop and
the approved credential audit. The active SSH environment does not supply that
console attestation. No network setting or consumed v9 Final campaign claim was
changed; no new extraction claim was created. Follow
[the guarded offline procedure](../../docs/pdf_extraction.md#reproducible-offline-cic-job)
only after those conditions hold.

QPDF, independent full differential parsing, native media filters, original xref/
Length/history coverage, recursive carving, Arlington, abstract interpretation,
visual/dynamic tiers and release packaging remain open. There are no new detector
metrics or real-corpus coverage gains. F1/MCC/ECE/Brier are N/A: no research
model/partition evaluation. Label=1 is malicious; the retained ECE convention is
ten equal-width malicious-probability bins with p=1 in the last bin.
