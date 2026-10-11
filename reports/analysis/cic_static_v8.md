# V8 development candidate — measurement completed, release blocked

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

## Final same64 measurement

The [final console run](../experiments/cic_static_profile/run_20261010T181946430830Z_3c5f90ef33fb/run_summary.json)
completed on October 11 at 01:22:10 Asia/Ho_Chi_Minh from clean revision
`3c5f90ef33fb`. It retained all64 cold and all64 warm records, with 23 warm
cache hits. The [saved-evidence review](../experiments/cic_v8_outcome_review/run_20261011T013204209994Z_3c5f90ef33fb/outcome_review.json)
verified the same identities, labels, partitions, configuration and baseline
checksums, and matched source fingerprints to the generating commit. The run
records non-root offline console checks, unchanged original bytes and no active
content execution. Test was not accessed and v7 was not rerun.

| Measure | Sealed v7 | Final v8 measurement |
| --- | --- | --- |
| Complete analysis | 23/64 (35.9%) | 23/64 (35.9%) |
| Partial analysis | 23/64 (35.9%) | 38/64 (59.4%) |
| Parser error / unavailable | 18/64 (28.1%) | 3/64 (4.7%) |
| C1 development coverage | 11/32 (34.4%) | 9/32 (28.1%) |
| C1 recall among classified malicious | 2/6 (33.3%) | 3/6 (50.0%) |
| C1 FPR among classified benign | 2/5 (40.0%) | 2/3 (66.7%) |
| Whole-development detected malicious | 2/16 (12.5%) | 3/16 (18.8%) |
| Whole-development false positives | 2/16 (12.5%) | 2/16 (12.5%) |

Fifteen former parser failures became partial; none became complete. Recovery
was attempted on38 files and returned a partial object view on37; 12 files had
backend disagreements. The three unavailable results are saved `AttributeError`
worker failures, so they do not establish that those PDFs are irrecoverable.
The complete≥32 and C1 classified≥18 targets were missed. Unavailable≤9 was met
as an observed count, with these limitations.

C1 retained both false positives and all six previously classified malicious
files; one FN became TP. Two previous benign true negatives became Inconclusive
because primary structure and graph traversal caps were reached. This changes
the conditional FPR denominator from five to three benign files, while the
whole-cohort FP count remains two. Overlapping abstention reasons include
unavailable contextual evidence, resource caps, backend conflicts and the two
development worker errors. The [C1 comparison](../experiments/cic_static_profile/run_20261010T181946430830Z_3c5f90ef33fb/c1_v8_comparison.json)
reports classified-cohort F1=0.5455, MCC=-0.1581, ECE=0.4050 and Brier=0.2745
with ten equal-width ECE bins. These different classified cohorts do not support
an overall accuracy or calibration improvement claim.

All saved primary P0/P1/P2 feature vectors match v7. However, three overlay
worker errors discarded one Train and two development inputs at the experimental
eligibility gate despite retained primary checkpoints. The fitted cohort became
31 instead of32 Train rows, and scored development became30 instead of32. The
reported nine regression events comprise three eligibility-change events
(one per variant) and six hard-label changes on common eligible rows (five P1,
one P2); they are not nine distinct files or nine label flips. These changed
cohorts prevent treating the new P0/P1/P2 metrics as evidence of improvement.
Acceptance remains **blocked**.

The subsequent maintenance catches backend `AttributeError` with redacted stage
codes and preserves other backend evidence. Completed, verified primary
checkpoints remain eligible for the fixed experimental fallback after an overlay
failure; the unavailable v8 view still makes C1 abstain, and deployment gates
stay strict. This restores numeric eligibility to32 Train and32 development rows
when inspecting the saved records. Synthetic tests verify legacy fit/probability
parity when an overlay fails and test backend containment. The exact untrusted
parser trigger was not reproduced. No real PDFs were read, models refitted,
thresholds changed or benchmark repeated during this repair. Its CIC behavior
and release acceptance remain unverified; the measured results above are unchanged.

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

The [first console invocation](../experiments/cic_static_profile/run_20261010T172942216671Z_2d744ec19f24/run_summary.json)
failed RAM admission before any PDF access: cold0/64, warm0/64, no predictions
or CIC metrics. Its atomic claim and failed report are preserved. Pressing the
same launcher again therefore refused another attempt. The
[RAM diagnosis](../experiments/cic_v8_ram_maintenance/run_20261010T175704924562Z_66ef2cf467d8/findings.json)
records the saved failure and reversible relocation of old synthetic/benign pytest
cache from RAM-backed `/tmp` to ignored disk artifacts. Available RAM increased
from 2,597,974,016 to 3,422,146,560 bytes during that maintenance; the original
failed run did not save its exact available-memory value.

The current code checks admission before claiming and again after loading the
frozen model. The locked parser cap remains 1GiB plus a 256MiB parent reserve:
at least 1,342,177,280 available bytes at admission, also subject to cgroup
headroom. Per-file checks and hard caps remain active; later pressure can still
stop a job and must remain recorded. Fresh validation uses ignored on-disk
temporary files rather than consuming `/tmp` RAM. Existing claims are displayed
with their saved status and `report_path`, without launching a new process.

A [replacement metadata-only job](../experiments/cic_static_prepare/run_20261010T181103978407Z_d5cb3d5309e1/run_summary.json)
was prepared from clean committed repaired code `d5cb3d5309e1`
using the exact sealed v7 subset/configuration and byte-identical native frozen
model. This replaces a zero-input failed launch, not an evaluated benchmark;
no validation result or model setting was used to choose a favorable repeat.
The existing Desktop **Chạy CIC offline** launcher targets that lock.
The [startup review](../experiments/cic_v8_ram_handoff/run_20261010T181226185135Z_d5cb3d5309e1/startup_review.json)
verifies the same64/configuration/design, identical frozen-model bytes and the
core source hashes tested by the full810 suite; six launcher checks passed after
pinning the metadata-only job. Its final evaluation has now completed and its
claim/report are retained. Reopening the shortcut or using
`scripts/18_launch_cic_offline.py --check` reads the saved completed outcome,
even after maintenance changes the extractor fingerprint. It does not read PDFs,
request another benchmark or bypass the attempt lock.

The [pre-benchmark code validation](../experiments/cic_v8_validation/run_20261010T180544719622Z_66ef2cf467d8/validation_report.md)
passed 810 tests (all760 existing plus50 new), with the two known sklearn
single-label warnings and no additional warnings. Python3.11.17 uses a fresh
CPU pyproject installation; dependencies, diff/ignore checks and
[source/test fingerprint stability](../experiments/cic_v8_validation/run_20261010T180544719622Z_66ef2cf467d8/source_integrity.json)
passed. This verifies the implementation, not CIC accuracy.

The [post-measurement maintenance validation](../experiments/cic_v8_validation/run_20261011T013058581840Z_3c5f90ef33fb/validation_report.md)
passed **817 tests**, including all760 original cases and57 v8 cases, in104.65s
with the same two sklearn single-label warnings. A fresh Python3.11.17 CPU
environment was installed from `pyproject.toml`; dependency, diff, status and
ignore checks passed. It verifies the repair with synthetic/benign fixtures,
and cannot replace the saved CIC measurement or unblock release acceptance.

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
The final CIC job started from clean committed code through the selected
console LAB workflow. Online preparation copied metadata and the exact verified
native frozen model; it does not read PDFs or unpickle/refit the original model.
Preparation seals baseline evidence checksums, source/backend versions and the
fixed C1 policy. An atomic attempt marker prevents automatic final reruns and
preserves failed/interrupted attempts for review.

The saved run distinguishes `status=completed` for measurement from
`v8_acceptance=blocked` for release. Complete analysis and C1 coverage missed
their research targets, and the measured legacy-model cohorts changed after
overlay failures. The subsequent repair has only maintenance validation. V7
remains the baseline; v8 is not an accepted release and no overall malware
detection improvement is claimed. The one completed final benchmark is preserved.

Reference checks: [PDFMalExtract pinned upstream](https://github.com/Mo-Alani/PDFMalExtract/blob/ec63665c671fb26e987b1b0640af500c192eddc4/PDFMalExtract.py)
uses `doc.scrub(garbage=4)` in failure paths. Installed PyMuPDF1.26.7 does not
accept `garbage` in `scrub`; its removal defaults include JavaScript, embedded
files and links. That path is unsuitable for evidence recovery. See
[PyMuPDF Document API](https://pymupdf.readthedocs.io/en/latest/document.html).
Canonical RIT features remain pinned to the earlier PDFMalExtract release.
