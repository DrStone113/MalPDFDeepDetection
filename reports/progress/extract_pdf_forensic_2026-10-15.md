# Extract-pdf raw grammar, xref history and static IR — 2026-10-15

Status: independent original-byte forensic increment implemented and verified
with generated benign fixtures. The [full roadmap](../../plans/extract-pdf/plan.md)
remains open; see [remaining acceptance](../../plans/extract-pdf/acceptance.md).
No real PDF was opened, hashed, parsed, decoded, rendered or executed in this
maintenance task. Preparation used saved manifest metadata only.

## Implemented behavior

`raw_syntax.py` provides bounded PDF lexical/object grammar without a native PDF
reader or object parser: comments/whitespace, escaped names, literal/hex strings,
exact numbers, arrays, dictionaries, booleans, nulls and references. Duplicate
keys remain separate ordered observations. Original token ranges/digests are
retained; arbitrary content/names are hashed. The existing PDFDocEncoding/BOM
codec is reused only for string projection identity, not structural parsing.

`raw_forensic.py` records each admitted physical declaration separately, even
when object number/generation repeat. It verifies stream endpoints against
authored direct lengths or references that agree under a complete examined xref
chain. An uncertain boundary stops sequential scanning. Xref-targeted bodies
may still be retained as candidates, with their context unverified; headers
inside known stream payload are not promoted to top-level declarations.
Headers and completed-value prefixes survive later parse/resource failure.

Traditional xref tables/trailers, binary xref streams, `/Prev`, hybrid supplement
priority, free/ordinary/compressed entries, `/W` defaults and noncontiguous
`/Index` ranges are checked and preserved. Cycles, ambiguous entries, bad widths,
unavailable targets and unknown scope remain explicit. No parser or revision
is chosen as a winner to suppress disagreement.

Structural XRef/ObjStm streams reuse the filter matrix and only the remaining
decoded-byte allowance after prior root/carver work. Uncertain interrupted
allowances become zero; failed prefixes are retained without parsing them as
complete objects. Compressed members use the same independent grammar,
generation0, container/index provenance and decoded-relative locations. Their
original-file offsets remain null. Encrypted object payload interpretations
remain unavailable; no password/decryption path is added. Filter time has its
own stage within the original worker's wall/CPU/RAM envelope.

`forensic_exports.py` links syntax nodes, every admitted key/value/array item,
declaration, xref entry, context and static reference to evidence IDs. Missing
targets receive separate `is_synthetic=true` nodes; original reference/null
syntax stays intact. Resolutions are scoped to individual examined xref
contexts. Unlisted declarations/compressed members are identified only against
examined xrefs, without maliciousness or catalog-unreachability claims.
The selected raw view participates in conservative native-parser comparison.

Xref-chain distance is distinct from revision ordinal. Public revision locators
remain null unless distinct top-level startxref/EOF pairs, chronological order
and selected body/xref dependencies within each prefix establish the examined
linked ordinals. Linearized multi-section files, missing old EOFs and old xrefs
pointing into future bytes do not prove historical identity. This is not
signature validation or proof of every possible revision outside the chain.

The pass runs after original primary/v8/v9, filters, carver and native inventory
checkpoints. Their measurements and flags remain separate. Raw/decoded blob
retention shares the existing parent-controlled cap. No viewer, URI follower,
Reader, JavaScript runtime or native PDF parse API is called by the raw grammar.
See [the technical scope](../../docs/pdf_extraction.md#original-byte-grammar-xrefs-and-static-reference-ir).

## Resource and verification evidence

Defaults: 2000 completed/partial declarations sharing one quota, 128000 lexical
tokens/nodes, 8192 exported IR nodes, 16000 xref/reference entries, 32 xref contexts,
64 structural streams, 2048 comparisons and 1.5MiB metadata with terminal reserve.
Depth/string and OS limits remain inherited. On interruption/overflow the last
bounded snapshot survives, and counters are explicitly lower bounds that
cannot resume decoding.

Final complete suite: **1250 passed**, 2 existing single-label sklearn warnings,
157.32 seconds. This adds 66 forensic cases to the prior 1184-test source. Python
3.11.17 uses the `.venv/` freshly installed in the preceding native-parser task;
dependencies did not change in this increment. QPDF 12.4.2/MuPDF 1.26.12 versions
remain recorded in the job fingerprint. No fresh installation is claimed for
this increment. The suite ran outside the tool sandbox with bounded BLAS
threads and disk-backed synthetic scratch. Duration is not corpus throughput.

Fixtures cover independent-parser API guards, escaped/invalid names, literal/
hex strings, exact numbers, duplicate keys, false payload markers, candidate
headers inside streams, incremental replacements, inherited Root, free entries,
unlisted physical/compressed objects, indirect length ambiguity, binary/hybrid
xrefs, compressed locations, cycles, encryption, cutoff bundles, all resource
caps, worker timeouts, parent retention and exact original primary/code/v8
parity. Linearization and footer/prefix tests prevent invented revision ordinals.

The first extended regression preserved two failures: an all-zero width vector
was mislabeled as a Size error, and a test incorrectly assumed removing final
whitespace invalidates a complete EOF. Both were corrected and retained. An
earlier full 1248-case check passed before the last quota audit. That audit added
partial-header accounting to compressed-member admission and a new regression;
a 1249-case check then passed. A final integration audit added direct parent-
verified on-disk raw/Flate-output blob assertions; the full 1250-case log is the
final evidence. Prior logs are retained separately. No detector/model selection
was performed.

Maintenance ID: `run_20261015T121100885216Z_7d02abdb85da`.
Generating commit: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, dirty worktree
recorded. No staging or commit. Seventy-one pre-existing files outside this
increment, root README, prior reports and the initial research-log prefix were
preserved. Dependency, diff, ignore, documentation-link and preservation checks
passed. Completed synthetic scratch was removed; evidence logs remain under
the stable maintenance domain, without new artifact roots/source copies/venvs.

Private evidence in `artifacts/tmp/maintenance/extract_pdf/` includes
`forensic_parent_release_pytest.log`, `forensic_checks.json`,
`forensic_preservation_checks.json`, `forensic_pip_check.log`,
`forensic_final_prepare_audit.json`, and retained unit/regression/earlier logs.

## Prepared job and remaining acceptance

Final metadata-only preparation: `run_20261015T124951020284Z_7d02abdb85da`.

- [Run summary](../experiments/pdf_extraction_prepare/run_20261015T124951020284Z_7d02abdb85da/run_summary.json)
- [Manifest paths/hashes and selection checks](../experiments/pdf_extraction_prepare/run_20261015T124951020284Z_7d02abdb85da/preparation_checks.json)
- [Locked methodology](../experiments/pdf_extraction_prepare/run_20261015T124951020284Z_7d02abdb85da/locked_methodology.json)
- [Recorded environment](../experiments/pdf_extraction_prepare/run_20261015T124951020284Z_7d02abdb85da/environment_metadata.json)

The lock pins 203 source/config files and the same 64 records as preceding jobs:
32 Train and 32 previously exposed Validation, 16/class/partition, Protocol G
seed42. All three manifest paths/checksums and the exact selection digest match.
No split regeneration, Test selection, PDF-byte access, model load/fitting or
extraction execution claim occurred. Both the preceding native-source lock and
the earlier preparation in this increment are refused after final source changes.
Their directories remain immutable.

```bash
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T124951020284Z_7d02abdb85da
```

The metadata check passed. Real-PDF execution still requires reviewed/committed
matching source and a non-root VMware console with disconnected NICs, disabled
shared folders/clipboard/drag-and-drop and a credential/agent-forwarding audit.
The SSH session is not that attestation; no network/sharing control was changed.
Follow [the guarded offline procedure](../../docs/pdf_extraction.md#reproducible-offline-cic-job)
only after those conditions hold. Rendering, JS execution/emulation, Reader and
CAPE remain outside authorization. The historic 21 partial Validation PDFs have
not been rerun.

Arlington/full conformance and catalog reachability, malformed regions with
unverifiable boundaries, MuPDF canonical-text syntax independence, routing
inventory-only objects into action analysis, native media, abstract JS semantics,
visual/dynamic/reingestion tiers, tabular/plugin/container release and labeled
threat/quality studies remain open. No real-corpus or detector gain is claimed.
F1/MCC/ECE/Brier are N/A: maintenance and preparation only. Label=1 is malicious;
ECE uses 10 equal-width malicious-probability bins, with p=1 in the final bin.
