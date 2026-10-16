# Extract-pdf recursive artifact implementation — 2026-10-15

Status: bounded static recursive artifact increment implemented and verified with
generated benign fixtures. The six-stage [original plan](../../plans/extract-pdf/plan.md)
remains open; see [the acceptance inventory](../../plans/extract-pdf/acceptance.md).
No real PDF was opened, hashed, parsed or decoded in this maintenance task.

## Implemented behavior

`extraction/carving.py` receives complete hash-verified output from the root
stream matrix. It routes magic/context candidates into nested PDF inspection,
stored/DEFLATE ZIP members, ObjStm syntax/projections, XFA/XML and inert JS ASTs.
Unknown streams are bounded unclassified inputs. Font/image/native media magic
is only candidate recognition; format analysis remains unsupported. Arbitrary
offset carving and archive formats beyond ZIP remain open.

Each occurrence keeps its source/container/slot, exact byte identity, ancestors,
depth and retention. Hash/kind reuse avoids repeated analysis while retaining
every incoming lineage; ancestor digests stop recursion. Synthetic-repair
provenance is inherited. Child PDFs use the canonical analyzer's new bounded
in-memory snapshot entry point inside the original disposable worker, without
writing temporary PDFs. Child evidence retains its own document digest and
`child:<sha256>:` feature namespace. Root measurements remain unchanged. Only
root document ownership can seed root trigger plans; child actions do not prove
activation. No dataset label is assigned to artifacts.

ZIP directories are checked before constructing bounded metadata objects. Local
and central headers, data descriptors, output size and CRC are checked; no
archive read/extract API or external unpacker runs. Names are hashed metadata,
never paths. Symlinks, unsafe paths, encryption, ZIP64, multidisk and unsupported
methods/layouts remain explicit. Failed/capped prefixes are retained without
routing them as complete children. XML forbids DTD/entity/external-resource
processing; JavaScript is parsed as syntax without execution. ObjStm references
remain opaque, with generation0 and decoded-relative offsets; no original-file
byte offset or execution graph is inferred.

Depth4, 64 occurrences, 1MiB per artifact, 4MiB cumulative admitted bytes, 64 ZIP
members, ratio100, eight PDF children, 128 child streams and 1MiB recursive
metadata bound the supplement. Explicit decode/AST/script/XML allowances include
root work; children receive no additional wall/CPU/RAM/retention allowance.
Per-parser-pass object reservations share one allowance and are not a count of
all native objects. Internal native parser decoding is OS-capped rather than
an exact decoded-byte ledger. Uncertain child accounting burns remaining
decode/AST/script allowance. Metadata overflow preserves the last bounded
snapshot with unavailable scope; those counters cannot resume parsing.

Completed artifact/member/XML/object checkpoints survive later limits or worker
timeouts. Blob transport remains parent-verified and shares the existing 10MiB
per-sample retention cap. The offline runner stores digest-named non-executable
blobs under ignored processed storage. Detailed scopes and limits are in
[the technical documentation](../../docs/pdf_extraction.md#bounded-recursive-artifacts).

## Verification

Final full suite: **1162 passed**, 2 existing single-label sklearn warnings,
279.02 seconds. This adds 48 cases to the prior 1114-test source. Python3.11.17
in the preserved root `.venv/`; no dependencies changed. The suite ran outside
the tool sandbox with bounded BLAS threads and disk-backed synthetic scratch.
It is not a measurement of extraction speed on real PDFs. A fresh-environment
installation was not performed.

New tests cover snapshot/legacy feature parity, nested PDF/ZIP identities,
retention, content reuse with separate lineage, root-only trigger plans, CRC and
data-descriptor handling, unsupported/encrypted/malformed archives, depth/count/
byte/ratio/metadata limits, ObjStm trailing syntax, Unicode XML/JS identity, AST
reuse, exhausted prior budgets, uncertain accounting and timeout cleanup.
Initial targeted tests retained two test-harness assertion failures; corrected
35-case and expanded 96-case targeted runs passed before the full suite. No
failed test evidence was removed.

Private evidence is grouped under `artifacts/tmp/maintenance/extract_pdf/`:
`carving_release_pytest.log`, `carving_checks.json`,
`carving_preservation_checks.json`, `carving_prepare_audit.json`,
`carving_prepare_check.log`, and the retained initial/targeted logs. Completed
synthetic fixture directories were removed. `pip check`, `git diff --check`,
ignore coverage, local documentation links and source preservation passed.
Forty-six pre-existing files outside this increment remain byte-identical;
the initial research-log prefix is unchanged. Nothing was staged or committed.

Maintenance ID: `run_20261015T075634542971Z_7d02abdb85da`.
Generating HEAD: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`; dirty worktree
recorded truthfully with source fingerprints. Existing unrelated edits, the
root README and prior reports were preserved.

## Prepared offline job and authorization boundary

New metadata-only preparation: `run_20261015T082603044770Z_7d02abdb85da`.

- [Preparation summary](../experiments/pdf_extraction_prepare/run_20261015T082603044770Z_7d02abdb85da/run_summary.json)
- [Manifest paths/hashes and selection checks](../experiments/pdf_extraction_prepare/run_20261015T082603044770Z_7d02abdb85da/preparation_checks.json)
- [Locked methodology](../experiments/pdf_extraction_prepare/run_20261015T082603044770Z_7d02abdb85da/locked_methodology.json)
- [Recorded environment](../experiments/pdf_extraction_prepare/run_20261015T082603044770Z_7d02abdb85da/environment_metadata.json)

The private lock pins 197 source/config files, packages and the same 64 metadata
records as the preceding preparation: 32 Train and 32 previously exposed
Validation, 16 per class/partition, saved Protocol G seed42. All three saved
manifest paths/checksums and the exact selection digest match. No split was
regenerated, no Test identity selected and no model loaded. The previous source
fingerprint is refused after these code changes. Prior job directories remain
intact, and no extraction execution claim was created.

Metadata-only check:

```bash
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T082603044770Z_7d02abdb85da
```

Actual PDF processing still requires matching reviewed/committed source and the
non-root VMware console with disconnected NICs, disabled shared folders,
clipboard and drag-and-drop, plus the credential/agent-forwarding audit. The
SSH development connection is not an offline-isolation attestation. No NIC or
sharing control was changed. Follow [the guarded procedure](../../docs/pdf_extraction.md#reproducible-offline-cic-job)
only after these conditions hold. Rendering, JS evaluation/emulation, Reader
and CAPE remain outside the authorized scope.

The historic 21 partial Validation PDFs have not been rerun. QPDF, independent
full differential parsing, native media codecs, full xref/orphan/Length/history
coverage, Arlington, abstract interpretation, visual/dynamic tiers and release
packaging remain open. QPDF/pikepdf were unavailable in this environment; no
package or dataset was downloaded. There are no new detector metrics or corpus
coverage claims. F1/MCC/ECE/Brier are N/A because no research model/partition was
evaluated. Label=1 is malicious; the retained ECE convention is 10 equal-width
malicious-probability bins, with p=1 in the last bin.
