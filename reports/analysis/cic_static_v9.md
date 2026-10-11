# V9 evidence contracts and offline acceptance

V9 starts from commit `8ef6ec1` on `development/v9.0`. Its objective is preserving
verified evidence and checking the exact evidence required by the original C1
model. No accuracy improvement, release acceptance or completed real-PDF run is
established by synthetic tests. V7/v8 reports, labels and Protocol G assignments
remain historical evidence.

## Evidence store and graph

`analysis_v9` uses `pdf-evidence-v9`, alongside unchanged legacy static/code
measurements and the v8 numeric adapter. Observations record the original PDF
digest, backend, object/generation or direct locator, verified offsets when
available, raw/decoded digests, status and fixed reason codes. Revision identity
remains unknown when the backend cannot establish it. Backend-local identities
are never merged by object number alone. Direct array elements retain indices.

Typed semantic paths prove catalog/page/annotation/field action placement,
JavaScript `/JS`, action `/Next`, Launch filespec `/EF`, and AcroForm/XFA declared
events. Arbitrary dictionary reachability, filenames and tokens do not establish
these paths. Shared scripts retain incoming edges; exact validated decoded hashes
allow reuse of completed per-script AST summaries. Recovery views remain separate;
ambiguous revision/projection differences cannot be treated as unrelated conflicts.
MuPDF generation limitations remain explicit, with no generation-zero aliasing.

Object, script extraction and AST checkpoints are append-only. A later backend,
AST, IPC, timeout or signal failure retains completed primary measurements and
graph entries. Worker cleanup is recorded after reaping. Checkpoint identity
collisions refuse replacement. Metadata is capped at2MiB. Parent-only raw storage
checks sequential64KiB chunks, sizes and SHA-256, with a shared10MiB/file allowance.
Incomplete raw transfers remain private `.partial` evidence. The worker retains
`RLIMIT_FSIZE=0`. Original PDFs are never changed, sanitized or executed.

Strict Flate decoding requires valid filters, EOF/checksum and no trailing data.
Invalid/truncated streams retain raw evidence and do not supply decoded eligibility.
The shared4MiB decoded-byte and AST allowances include primary/v8 work; recovery
does not renew exhausted allowances. `pypdf==6.18.1` is pinned to the upstream
[malformed-Flate runtime fix](https://github.com/py-pdf/pypdf/security/advisories/GHSA-jw7q-gvrg-4vj3).
PyMuPDF1.26.7 stays unchanged; no additional parser engine is introduced.

## Frozen C1 and dependency ledger

Policy `c1-v9-frozen-ml-linked-evidence-v1` uses the original C1v8 RF173 artifact,
31 Train rows, saved median/missing indicators and threshold0.5. P0/P1/P2 use
the v7 Train32 artifacts. Preparation only copies and verifies model bytes;
unpickling occurs after offline LAB admission. The V9 workflow has no fit,
calibration or selection path.

All173 ordered columns have a ledger entry describing the original measurement,
total/lower-bound semantics, completion requirement and frozen missingness
support. Provenance links immutable measured inputs and the contributing verified
objects/scripts. A missing value is supported only when its original fitted
imputer indicator exists. Unsupported unknown inputs, missing provenance,
unlocalized conflicts and affected model or witness dependencies abstain.
Original totals and sentinels are not reinterpreted to bypass these checks.

| Decision | Required evidence |
| --- | --- |
| Partial positive | Score≥0.5; verified model contract; legal action→exact completed JS/AST, declared XFA event→completed JS/AST, or Launch→filespec→EF→verified bounded PE/ELF payload |
| Benign | Score<0.5; complete primary gates and mandatory catalog/action/script/XFA/embedded checks; no affected failure/conflict/cap |
| Inconclusive | Insufficient model/graph evidence, affected failure, or incomplete negative |

GoToE, URI, RichMedia and other observations remain diagnostics. Eligible script
or payload context is not proof of malware behavior. An unrelated, localized cap
does not erase verified primary evidence or independently block a positive.
Every decision records frozen identity/probability, selected witness, required
checks, supporting IDs and blocking codes. Abstention remains quarantine and
contributes neither detection nor benign labels.

## Validation and measured limits

`scripts/21_validate_pdf_evidence_v9.py` creates a fresh Python3.11 CPU environment
from `pyproject.toml`, runs the full dataset-free suite and saves dependency,
source-integrity, ignore, diff and status checks with warnings. Environment-only
preparation may be followed by `--environment-run <run_id>` using that saved fresh
runtime. A successful clean-generating-code validation fingerprint is required
for sealing final. Report-only commits do not change the source fingerprint.

Synthetic regressions cover direct/shared scripts, legal ownership, Next cycles,
unresolved references/generation differences, XFA events, unrelated payloads,
external Launch, GoToE, strict Flate failures/bombs, monotonic IPC and retained
checkpoints after AST/worker failures. Frozen inference checks require unchanged
feature order/preprocessing, absolute probability parity≤1e-12 and identical
hard labels for unchanged inputs. Synthetic coverage cannot prove the three
historic PDF triggers are fixed or that any old abstention should be classified.

## Console handoff and one final attempt

The versioned shortcut is `configs/cic_v9_launcher.desktop`; its entry point is
`scripts/20_launch_cic_v9.py`. Metadata-only `--action prepare` locks exactly the
three saved AttributeError identities without reopening PDFs or loading pickle.
`--check` reads preparation/status only. On the selected isolated non-root VMware
console, **Integration → Enter** runs bounded extraction without detector metrics.
The launcher checks disconnected interfaces and refuses SSH/root sessions.

Integration acceptance verifies immutable input hash, retained primary checkpoints,
completed graph evidence, localized stage failures and worker cleanup. Replacing
AttributeError with a generic failure is insufficient. Preserved unresolved
references or unsupported data may remain partial with specific evidence. After
reviewing and committing aggregate integration reports, metadata-only
`--action seal` locks matching integration and clean CPU validation evidence,
source/backend/policy fingerprint, original manifests/artifacts and budgets.
Commit its aggregate preparation reports before using **Final → Enter**.

Final permits one campaign-wide atomic claim, shared across preparations. LAB,
clean code, provenance/checksums and RAM admission precede it, including RAM
recheck after model loading. Zero-input refusals get immutable reports without
consuming the claim. Claimed failures/interruptions remain consumed; there is no
automatic deletion, favorable rerun or resume.

The final job retains one worker,20s wall,12s CPU,1GiB address-space budget,
10MiB/file and shared4MiB explicit decode allowance. It measures the same64
Train/development files cold/warm; no Test data is accessed. Private per-file
SHA-based comparisons include parser/recovery evidence, graph/capability coverage,
C1 dependency reasons, legacy input/probability parity and runtime/RSS. Each of
the21 old development partials receives its own private comparison/reason record.
Public reports aggregate these records without sample identities or content.

Recall/FPR/F1/MCC use actual classified labels, with classified and planned
denominators. ECE/Brier use the separately reported cohort with valid frozen ML
probabilities, including abstentions; ECE uses10 equal-width bins, p=1 in the last.
Measurement completion leaves technical review required unless acceptance evidence
has established no loss/refusal of qualified evidence and explained all regressions.
No target forces the21 old partials to become classified.

## Supplemental-xref compatibility review

The saved initial fresh CPU validation passed975 tests with2 retained sklearn
warnings. Subsequent console integration
`run_20261011T040344406533Z_fd3166d34abb` completed three files, verified source
hashes and worker cleanup, and retained the original primary feature vectors.
Its recorded `passed` outcome remains immutable.

The later review found that the supplemental `/XRefStm` compatibility wrapper
discarded exceptions without recording an incomplete check. That made this
integration insufficient for final sealing after the correction. The wrapper
now records fixed failure codes and offsets when known, restores the stream
cursor on every exit, and propagates resource/system failures. Primary structural
totals remain unknown after supplemental-xref loss; code, v8 and v9 preserve the
same explicit partial condition while retaining usable objects. The pinned
initializer repair is retained. Seven synthetic hybrid-xref regressions cover
valid supplemental references, malformed/out-of-bounds pointers, idempotence,
retained graph evidence and propagated memory/recursion/system failures.

This is a documented legacy-completeness correction, not a model adjustment.
The previous validation and integration fingerprints cannot seal the changed
source. The corrected source passed 982 dataset-free tests in 117.32s, with 2 retained
sklearn single-label warnings, in the saved fresh Python3.11 CPU environment.
Dependency, source-integrity, diff and ignore checks passed from clean generating
code. See [the saved validation](../experiments/cic_v9_validation/run_20261011T041749327636Z_c626318a1300/run_summary.json).

An earlier tool-sandbox validation was interrupted while a synthetic DataLoader
waited, after 357 passing tests. Its failed report remains immutable and grants no
validation seal. The isolated DataLoader control passed outside that sandbox;
the subsequent full validation above passed on unchanged source. See
[the execution diagnostic](../experiments/cic_v9_validation_diagnostic/run_20261011T041717302629Z_2dde794fc3ae/diagnostic_evidence.json).
These CPU checks have no real PDF or frozen-model loading. A new matching
three-file console integration is still required before the unchanged single
final attempt; no final claim has been consumed by these maintenance checks.

The metadata-only [preceding integration job](../experiments/cic_v9_prepare/run_20261011T042108432378Z_ecd14db5e113/run_summary.json)
was prepared for exactly the three historic AttributeError inputs and matched
the 982-test validation above. Its console outcome is recorded below. It cannot
run the later checkpoint correction; preparation only verifies saved metadata
and frozen model bytes, without PDF/pickle access or another final attempt.

## Recovery metadata checkpoint correction

The [three-file integration on October 11 at 04:28 UTC](../experiments/cic_v9_integration/run_20261011T042829844425Z_1d8248aeb2c0/integration_evidence.json)
completed all three inputs as partial. Source hashes, primary checkpoints and
worker cleanup were verified; primary feature changes were zero. All three
integration checks were blocked by `backend_failure_stage_unlocalized`. The
supplemental-xref failure had its own verified locator; MuPDF hit the metadata
allowance without retaining a localized stage-failure checkpoint. These `passed`
booleans measure integration acceptance, not a C1 prediction or detector metric.
The blocked report and private evidence remain immutable.

The store previously rejected stage-failure records at the same ordinary-entry
boundary that stopped object enumeration. Some backend/capability/conflict
fallbacks also bypassed accounting and checkpoint delivery. The correction allows
at most 64KiB of terminal records within the existing metadata reserve; ordinary
objects cannot spend this allowance. Total graph metadata remains capped at2MiB,
with room for the frozen feature ledger. Localized failures, partial checks and
backend summaries use the same immutable delta path with byte accounting. If that
terminal allowance is exhausted, extraction fails with preserved checkpoints.
Oversized complete checks become localized partial checks, and backend summaries
include that failure. No gate, model, threshold or worker budget is relaxed.

Synthetic regressions reproduce a secondary metadata cap after retained primary
evidence, interruption after terminal checkpoints, exhausted status reserves and
oversized completeness checks. Integration still rejects an otherwise identical
result after its localized failure evidence is removed. The focused V9 suite
passed 163 tests. The corrected source then passed
[987 tests in the fresh Python3.11 CPU environment](../experiments/cic_v9_validation/run_20261011T043858567176Z_f9181d42a6a5/run_summary.json)
in 119.97s, with 2 retained sklearn warnings. Dependency, source-integrity, diff
and ignore checks passed from clean generating code. A matching console
integration remains required. The preceding 982-test fingerprint and prepared
job cannot seal the changed source; the final campaign attempt remains unused.

The [current integration preparation](../experiments/cic_v9_prepare/run_20261011T044229698570Z_1c8bc06aa8e2/run_summary.json)
locks the same three historic inputs and matches the 987-test source/backend/budget
fingerprint. The Desktop shortcut selects it for **Integration → Enter** through
the isolated non-root VMware console. Per-file progress now includes fixed reason
codes, and the launcher labels integration acceptance separately from Final's
detector metrics. No PDFs or frozen pickle were opened during preparation.

## Matching integration accepted

The [corrected console integration](../experiments/cic_v9_integration/run_20261011T044535236209Z_e8f532bac70e/integration_evidence.json)
completed and passed all 3/3 extraction checks. Original PDF hashes and worker
cleanup were verified, with zero primary feature changes. Each result retained
1451 observations and 1459629 bytes of graph metadata, below 2MiB. All three files
remain partial: supplemental-xref loss and recovery metadata caps retain their
actual localized evidence; completion is not inferred from integration acceptance.
No probabilities or quality metrics were evaluated.

Its source/backend/budget fingerprint matches the successful 987-test clean
Python3.11 CPU validation. The [metadata review](../experiments/cic_v9_integration_review/run_20261011T044743081180Z_e8f532bac70e/review_evidence.json)
verifies both prerequisites before sealing the same 64 diagnostic Final campaign.
Model bytes, preprocessing, 173-column ledger, threshold 0.5, original labels and
Protocol G partitions stay frozen. The earlier blocked reports remain unchanged.

## Final sealed for console execution

The [Final preparation](../experiments/cic_v9_prepare/run_20261011T044846162865Z_a46caece1d06/run_summary.json)
was sealed from clean commit `a46caec`, pinning the successful three-file integration
and 987-test validation to the same source/backend/budget fingerprint. Metadata
checks confirm all 64 locked rows, the original frozen model bytes and
preprocessing, 173 C1 inputs, threshold 0.5 and one campaign-wide final attempt.
Preparation read no PDFs, loaded no pickle and consumed no campaign claim.

After committing these aggregate reports, use the disconnected non-root VMware
console shortcut **Chạy CIC v9 offline**, select **2 → Enter** (Final), then
confirm the selected LAB isolation procedure with Enter. The default Enter runs
Integration. Final recall, FPR, coverage and per-file acceptance explanations
remain unavailable until the console attempt finishes; integration acceptance
does not establish detector accuracy.

## Completed Final measurement

The [single Final attempt](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/run_summary.json)
completed on October 11 at 11:57:47 Asia/Ho_Chi_Minh, from clean commit `ff3f5b6`.
All 64 cold and 64 warm profiles were recorded. The locked identities, labels,
Protocol G assignments, original frozen models, 173 C1 columns, preprocessing and
threshold 0.5 were preserved; no fitting, calibration, tuning or Test access took
place. The campaign-wide claim is consumed and remains immutable.

| Measure | v7 | v8 | v9 |
| --- | --- | --- | --- |
| Complete analysis | 23/64 | 23/64 | 22/64 |
| Partial analysis | 23/64 | 38/64 | 42/64 |
| Parser-error / unavailable analysis | 18/64 parser errors | 3/64 unavailable | 0/64 unavailable |
| C1 development coverage | 11/32 (34.4%) | 9/32 (28.1%) | 9/32 (28.1%) |
| Recall among classified malicious files | 2/6 (33.3%) | 3/6 (50.0%) | 3/6 (50.0%) |
| FPR among classified benign files | 2/5 (40.0%) | 2/3 (66.7%) | 2/3 (66.7%) |

The analysis row counts refer to each version's full evidence view. V9's
[legacy primary pipeline](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/pipeline_summary.json)
separately reports 23 complete, 26 partial and 15 parser-error files in each pass.
Those primary errors coexist with retained partial overlay evidence and are not
worker-unavailable results. Relative to v8, three unavailable overlays became
partial; one complete Train overlay became partial at the graph metadata allowance.
Its primary features remained complete and numerically unchanged.
V7 and v8 use different saved C1 estimators; v8 and v9 share the frozen RF173.
The comparison is descriptive and does not isolate an accuracy gain from the graph.

The [C1 evidence](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/c1_comparison.json)
has TP3, FN3, FP2 and TN1 across 9 classified files, with 23 Inconclusive results.
Conditional malicious F1 is 0.5454545 and MCC is -0.1581139. All 32 decisions match
v8. Across the planned 16 malicious and 16 benign files, detected and false-positive
fractions are 3/16 (18.75%) and 2/16 (12.5%); abstentions are neither detections nor
benign predictions. These fractions do not turn abstention into a hard-label error
or establish improved generalization on this already exposed diagnostic cohort.

ECE is 0.1472687 and Brier is 0.2697494 on the separate cohort of all 32 valid
frozen ML probabilities, including abstentions. ECE uses 10 equal-width bins,
with p=1 in the last bin. This cohort differs from v8's 30 scored rows because
two development inputs previously lost to worker errors now retain measurements;
the calibration values cannot be presented as a paired gain over v8.

The [graph summary](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/graph_coverage.json)
records 678 verified MuPDF-local object observations, usable script/AST evidence
in 20/64 files, usable payload evidence in 19/64, and verified witness paths in
14/64. These are syntax/eligibility counts; they do not prove exploit detection,
historical revision completeness, or 678 newly recovered objects absent from the
primary backend. The verified witness families in this run are PDF JavaScript.

## Acceptance review and partial-file explanations

The [metadata acceptance review](../experiments/cic_v9_final_review/run_20261011T050628599657Z_ff3f5b65d376/review_evidence.json)
verified original source identities, static-only flags and worker cleanup on all
128 saved profiles. The largest serialized graph is 1477331 bytes, below the
2MiB hard limit; admission can stop earlier to reserve bounded terminal/check
metadata. Maximum worker wall time is 6.0822s. The sealed source fingerprint still
matches the clean fresh Python3.11 CPU validation: 987 tests passed, with two
retained sklearn warnings. Dependency consistency was checked again and passed;
its cache-permission warning was saved. This review reopened no PDFs or raw
streams, loaded no models and generated no new model probabilities.

All 173-column model contracts were rechecked from saved provenance and frozen
missingness metadata. All 32 decisions replayed identically from their original
saved scores. Absolute probability parity is exactly zero and hard labels match
for the comparable unchanged inputs: C1 30, P0 32, P1 30 and P2 30 development
rows. No unchanged-input numerical regression was found. The remaining legacy
differences are six changed-input records across the same three historic
AttributeError files, affecting P1 and P2. Guarded supplemental-xref recovery now
retains observed AA/EmbeddedFiles and script counters, plus the corresponding P2
parser/recovery flags, instead of losing the whole primary result. Unverified
supplemental-xref totals remain unknown and those files remain partial. Two
development probabilities per P1/P2 change, while their hard labels stay the same;
the third changed input belongs to Train. The corresponding synthetic regression
is `tests/test_pypdf_compatibility.py`. The original acceptance report's six
unexplained records are preserved; their explanations are added in the new review.

Each of the 21 old development partials has an individual private record in
`artifacts/cic_v9_final_review/run_20261011T050628599657Z_ff3f5b65d376/old_partial_reviews.jsonl`,
including original identity, retained checkpoints, model dependencies, incomplete
checks, conflict scopes, usable paths and a per-reason explanation. All remain
Inconclusive. Eighteen have a positive numeric ML score, but only one has a
completed legal graph path; that file's aggregate model AST provenance is still
unverified. A positive score alone does not establish eligibility.

| Blocking reason among the 21 old partials | Files |
| --- | --- |
| Resource limit intersects a model/required-path dependency | 13 |
| Backend conflict lacks verified affected scope | 4 |
| Resource limit lacks verified affected scope | 3 |
| Original total input enumeration incomplete | 1 |
| Aggregate script AST input provenance unverified | 1 |
| Partial negative | 1 |
| Mandatory checks incomplete | 1 |

These counts overlap. The 13 dependency-limited cases include MuPDF embedded
decoded-byte limits under the shared budget. The unlocalized limits/conflicts
cannot be declared independent of the frozen model inputs. Retaining completed
objects does not establish that capped source enumeration missed no qualifying
evidence. The one complete-to-partial Train overlay is separately explained in
the private `overlay_regression_reviews.jsonl`; primary evidence was retained,
but graph completeness remains unverified.

Acceptance remains **blocked**. Evidence retention improved for the three historic
worker failures, but detector accuracy/coverage did not improve and the saved
capped views cannot certify that every qualifying source item was extracted.
Further work should first inspect graph metadata duplication and dependency-scope
precision using synthetic fixtures and saved metadata, preserving current byte
budgets and frozen feature meanings. This completed campaign is retained as
diagnostic evidence; a new real-PDF campaign requires a separately locked design.

The initial metadata-review attempt stopped on a Python integer versus serialized
JSON string key comparison. Its failed run was preserved. Normalizing that
representation allowed the completed review above; neither review reanalyzed PDFs
or consumed another Final attempt.

The [runtime evidence](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/resource_usage.json)
records a cold median of 2.6112s/file, compared with 1.4899s in v7 and 0.8211s in v8;
the warm median is 2.1824s/file with 22 complete-profile cache hits. Cold totals
are 175.6974s and warm totals are 140.8869s. Cold peak worker RSS is 382582784 bytes
and peak sampled family RSS is 827375616 bytes. Host load/OS cache were not
controlled, so these are measured costs rather than an isolated speed attribution.
