# V8 development candidate — final LAB acceptance pending

The candidate is developed on `development/v8.0`. V7 is the sealed baseline:
`run_20261010T154029301301Z_20cf4e14ac84`, completed on October 10 at
22:44:41 Asia/Ho_Chi_Minh. It has 23 complete, 23 partial and 18 parser errors
among 64 balanced Train/development PDFs. Strict C1 classified 11/32 development
rows, with TP2/6 malicious and FP2/5 benign. V7 is not rerun.

The saved-evidence [failure audit](../experiments/cic_v8_audit/run_20261010T163245301129Z_20cf4e14ac84/failure_analysis.md)
retains all64 identities, labels and stage failures in ignored LAB artifacts.
Fourteen structural opens report missing `startxref`; four failures are not
classified precisely by their saved diagnostics. Partial cases include missing
references, invalid or unsupported stream decoding, encryption and object,
AST and XFA XML caps. These categories overlap. The audit cannot establish
irrecoverability, a code bug or the actual content-level cause without the
authorized final offline analysis; no sample bytes were copied into fixtures.

## Evidence pipeline

The existing primary analyzer, raw-byte counters, JS/XFA extraction and strict
C0/C1/P0/P1/P2 definitions are retained. The LAB profiler adds a separately
versioned `analysis_v8` / `pdf-evidence-v8` record. It traverses the latest
catalog's references and passive action edges, identifies embedded streams,
decodes them within the existing explicit byte allowance, and records their
magic, whitelisted MIME, size and digest privately. URLs, names, script text
and payload bytes are never exported by this overlay or executed.

When primary analysis is incomplete, one read-only MuPDF object view is opened
from the same original byte snapshot. Existing inert JS AST/XFA inspection is
reused against that adapter. Nonzero-generation references are refused because
the MuPDF public xref API does not establish generation identity. Backend
graphs and features stay separate; overlapping objects are compared by bounded
dictionary/array/scalar/reference projections and raw-stream digests. Stream
`/Length`, stream class representation and equivalent integer/decimal notation
are normalized because parser representations differ. Other disagreements are
preserved and C1 abstains.
There is no repaired PDF output, `scrub`, `sanitize`, save, rendering or execution.

Every feature records value, source, recovery flag, evidence IDs, completeness
and `observed`, `absent_after_complete_check`, `unknown` or `not_applicable`.
Missing values and legacy `-1` sentinels become unknown in the new evidence
view; the original canonical measurements remain intact. Absence applies only
to the named checked scope. Recovery remains partial even if reopening works.
Historical revisions, orphan objects, general font/image decoding and
steganography are not certified by this graph. URI actions are contextual
structure, not a verified phishing detector. Token presence is not exploit
coverage. QPDF/pikepdf are unavailable and were not added as new dependencies;
the two available engine families are pypdf and MuPDF.

## C1 and evaluation

The new LAB-only C1 uses the original fixed RF budget, seed42 and threshold0.5.
Train-only median imputation includes missingness indicators. Canonical,
observed partial AST, backend-specific recovered AST, action and embedded
features remain distinct. The saved Protocol G identities, groups and split
are checked, and newly equivalent feature vectors cannot cross partitions.
No threshold/model selection or deployment replacement occurs.

`Benign` requires complete analysis and a negative model score. An incomplete
positive additionally requires available JS AST with JavaScript action context,
or executable-magic attachment with Launch/GoToE context. These are eligibility
checks; co-occurrence is not proof of an execution link or maliciousness. Backend
conflicts, unavailable scores and incomplete negatives are `Inconclusive` and
operationally quarantined. Explicit parser/AST/XML/stream resource caps also
refuse a contextual positive and retain their reason codes. Explanations name supporting evidence IDs and do
not claim causal feature attribution.

Probability calibration is deferred: fitting it on the same32 exposed
development rows and then reporting those rows as independent evaluation would
be misleading. This fixed pilot reports ECE/Brier without claiming calibrated
probabilities. A calibration study needs a separately locked validation design.

The final comparison joins all64 SHA-256/label/partition identities to saved v7
evidence. It preserves per-file outcomes, all v7 FP/FN cases, backend failures,
prediction transitions and P0/P1/P2 changes under ignored artifacts. Aggregate
reports distinguish conditional recall/FPR, class-specific coverage, whole-cohort
detected/false-positive fractions and operational quarantine. Abstentions never
count as true detections. Unexplained P0/P1/P2 changes block acceptance.

## Limits and final execution

The [final code validation](../experiments/cic_v8_final_validation/run_20261010T171551960762Z_21161c1eb7f5/validation_report.md)
passed 801 tests (all760 existing plus41 new), with the two known sklearn
single-label warnings and no additional warnings. Python3.11.17 uses a fresh
CPU pyproject installation; dependencies, diff/ignore checks and source/test
fingerprint stability passed. This verifies the implementation, not CIC accuracy.

All analysis stays in a disposable subprocess with existing CPU, RAM, wall,
file, traversal, stream-filter, XML and AST limits. Explicit decoded-byte and
AST allowances are shared with recovery. Object caps apply per traversal and
there is one additional engine attempt; native implicit object-stream decoding
is bounded by OS memory/CPU/deadline limits, not by the explicit decoded-byte
counter. Counters describe successfully observed decoded bytes/nodes; failed
transient decoding is per-stream and OS-capped. A primary or graph byte/node
limit exhausts the respective fallback allowance rather than restarting it.
The same locked one-worker budget is kept for comparability. Primary
raw/structure/code checkpoints survive later crashes or resource exhaustion.
IPC and cache payloads are size-capped; incomplete v8 profiles are not reused.

`scripts/19_validate_pdf_evidence_v8.py` creates an immutable maintenance report
and fresh Python3.11 CPU environment from `pyproject.toml`, runs the entire
dataset-free suite, and records dependency, diff, status and ignore checks.
The final CIC job must start from clean committed code through the selected
console LAB workflow. Online preparation copies metadata and the exact verified
native frozen model; it does not read PDFs or unpickle/refit the original model.
Preparation seals baseline evidence checksums, source/backend versions and the
fixed C1 policy. An atomic attempt marker prevents automatic final reruns and
preserves failed/interrupted attempts for review.

The targets of complete≥32/64, unavailable/unrecovered≤9/64 and C1 classified≥18/32
are research targets, not measured results. `run_summary.json` will contain the
final measurement and evidence paths; completed measurement does not imply an
accepted release. Final benchmark, resource/safety checks and reconciliation of
every prediction change are still required. V8 is not marked completed and no
accuracy improvement is claimed before that evidence exists.

Reference checks: [PDFMalExtract pinned upstream](https://github.com/Mo-Alani/PDFMalExtract/blob/ec63665c671fb26e987b1b0640af500c192eddc4/PDFMalExtract.py)
uses `doc.scrub(garbage=4)` in failure paths. Installed PyMuPDF1.26.7 does not
accept `garbage` in `scrub`; its removal defaults include JavaScript, embedded
files and links. That path is unsuitable for evidence recovery. See
[PyMuPDF Document API](https://pymupdf.readthedocs.io/en/latest/document.html).
Canonical RIT features remain pinned to the earlier PDFMalExtract release.
