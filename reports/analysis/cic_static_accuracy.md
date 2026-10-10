# CIC static accuracy development

The supplied Windows XGBoost is available and verified. The remaining problem
is classifier transfer/feature information and incomplete structural analysis.
The saved first64-PDF run has23 complete,23 partial and18 parser-error results;
its RF pilot classified11/32 development rows. Both variants detected2/6
classified malicious rows; false positives were4/5 and3/5 classified benign
rows. These are small, exposed development subsets, not independent accuracy.
Source: `reports/experiments/cic_static_profile/run_20261009T143328562606Z_57544eaea873/`.

The saved controlled numeric CIC cohort contains870 Train and291 Validation
rows. An audit on Train/development metadata only found501 unique vectors on
Train and118 on Validation using its existing measured feature columns.
Seventeen Validation vectors contain conflicting published labels. Even an
oracle selecting the majority label separately for each of those Validation
vectors would classify at most211/291 rows correctly. This72.5086% is a
descriptive information ceiling on these particular labeled vectors, not a
model result or a limit on richer features/future cohorts.

Projection to the RIT38 schema creates13 feature-equivalent vectors across
the saved CIC Train/Validation boundary. Retaining both measured raw-byte
features, `script_ratio` and `ObfuscationCount`, gives zero overlapping40-column
vectors. No partition is regenerated and no colliding row is silently removed.
The three existing exclusions (`Acroform`, `Colors`, `BaseEncoding`) are checked
as zero constants on Train only. Remaining security measurements are kept.
Identifiers, source, paths, hashes, Label and pipeline parser flags are not
predictors.

For the64 saved pilot identities, every known canonical feature value was
compared against the controlled cached table. There were no differences in
any of the41 columns; four metadata fields were known on62/64 rows rather than
all64. This is record-level evidence for the pilot, not proof for the entire
dataset. No PDF was reread during this audit.

The first adaptation study is deliberately fixed:200 trees, depth6, seed42
and the existing XGBoost factory configuration; threshold0.5; one candidate
fit on CIC Train only. No search, early stopping, calibration or threshold
selection uses Validation. The baseline uses the supplied frozen RIT38 model
and the candidate uses the40 measured columns. Both score the same finite
Validation rows, with refusals and full class denominators retained. The study
changes training cohort and input projection, so any gain cannot be attributed
solely to feature extraction.

```bash
.venv/bin/python scripts/17_train_cic_static.py
```

The official invocation requires clean committed code and automatically writes
a unique `reports/experiments/cic_static_accuracy/run_<UTC>_<commit>/` directory.
Methodology/config/input checksums are locked before fitting. The new native
JSON candidate stays under ignored `artifacts/cic_static_accuracy/`; original
models and reports remain intact. Candidate loading rechecks its manifest,
native checksum and40-feature binary contract. Only previously controlled CSV
features are read; Test identities are removed before numeric conversion.
No PDF bytes, viewers, JavaScript execution, downloads or cloud training occur.

Validation has previously been inspected in other studies. Numeric coverage is
not end-to-end parser coverage, and RIT PDF overlap cannot be excluded from
CSV-only identities. The candidate is a development artifact; deploying it or
claiming improved full-PDF accuracy requires the corresponding offline LAB
measurement on saved partitions and a separately locked evaluation design.

## Measured outcome and extractor maintenance

The fixed study completed in
`reports/experiments/cic_static_accuracy/run_20261010T055507589311Z_a476b20fd847/`.
Both models scored all 291 cached Validation rows at the locked threshold 0.5.
The frozen RIT model detected 134/160 malicious rows and falsely flagged
112/131 benign rows. The CIC candidate detected 57/160 and falsely flagged
53/131. Its malicious F1 fell from 0.6601 to 0.4222 and MCC from -0.0240 to
-0.0496. The candidate is preserved as negative development evidence and
has not replaced the frozen model. This comparison changes training cohort
and input projection; it does not establish a feature-only improvement.

Three extractor limitations were reproduced using generated benign bytes:

| Fixture | Previous behavior | Maintenance behavior |
| --- | --- | --- |
| UTF-16BE BOM JavaScript stream | `script_decode_error`, zero parsed scripts | One correctly decoded and parsed script |
| 100-page PDF, `/OpenAction`, 16-object traversal budget | Budget exhausted before reading JS | Known script AST retained; total counts still unknown and result partial |
| Incorrect `startxref` offset | Strict parser failure, no JS evidence | One xref-only retry in the same capped worker; recovered AST retained as partial evidence |

Code-inspection schema v5 decodes PDFDocEncoding and explicit Unicode BOMs
for strings/streams, prioritizes action routes during bounded traversal, and
retains strict failure plus recovery diagnostics. UTF-16LE BOM compatibility
is explicit; BOM-less UTF-8/UTF-16 is not guessed. Encoding corruption, decoded
byte caps, unsupported filters, memory failures and incomplete traversal retain
their failure states. Recovered xref evidence is never marked complete or
cached as a complete result. Full-history/incremental-revision coverage is
still unverified. The RIT numeric schema and existing model remain unchanged;
the code/schema fingerprint invalidates previous prepared jobs and caches.

The text-stream encoding definition is in Adobe's
[PDF Reference 1.7, Table 8.90](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf);
[PDF 2.0 adds UTF-8 text with a BOM](https://pdfa.org/understanding-utf-8-in-pdf-2-0/).
The same64 offline v5 run subsequently completed in
`reports/experiments/cic_static_profile/run_20261010T064045861512Z_53173f5a5625/`.
Observed AST coverage rose from11 to20 files; complete/partial/parser-error
counts stayed23/23/18, and the strict RF pilot's recall/FPR stayed unchanged.
Its `advanced_features()` uses only complete totals, leaving recovered partial
AST evidence out of the classifier input. Eighteen files have fatal structural
parse failures, including14 missing-startxref failures. These failures are
retained in all reported denominators; they are not benign predictions.

## Locked observed-evidence ablation

The existing entry point also supports a distinct saved-profile study:

```bash
.venv/bin/python scripts/17_train_cic_static.py --config configs/cic_profile_accuracy.yaml
```

The config pins the completed profile, its methodology, comparison and private
per-file JSONL checksums. The loader verifies every development identity,
label, split, original manifest/group boundary, snapshot checksum, v5 schema
and static-only execution state before fitting. It reads saved bounded metadata;
it does not reopen/hash PDF bytes or convert any Test measurements. Only cold
records are used, avoiding repeated cold/warm observations as training samples.

All three variants use RF200 trees/depth12/min-leaf2/class-balanced, seed42 and
threshold0.5, matching the original RF budget. No threshold/hyperparameter
search, calibration, selection or production promotion occurs. The canonical
41 measurements preserve original `-1` and null evidence. Unknown advanced
totals stay null, while observed values have separate lower-bound names.
The29 AST node-type names are fixed syntax categories, not selected from
Validation. Imputation/missing indicators fit on eligible Train only.

| Variant | Fixed input group |
| --- | --- |
| P0 | Canonical RIT41 measurements; explicit experimental raw-feature fallback |
| P1 | P0 plus existing complete totals, observed structure/AST/node types and analysis-coverage flags |
| P2 | P1 plus parser success/completeness/resource/encryption/repair flags |

Eligible input requires the saved capped, checksum-verified byte snapshot and
measured raw features. On the locked source64 rows, all32 Train and32 Validation
rows meet this condition, including parser errors. Input/worker failures still
refuse classification. Counts, coverage, malicious recall, FPR and analysis-status
strata keep every planned row in their denominators. Unknown fields are not
replaced with invented source measurements or default benign predictions.
Cross-partition feature equivalence causes failure before fitting, rather than
changing the saved split or silently dropping rows.

Only P0/P1/P2 share the same fitting rows and fallback policy. The older C0/C1
models trained on18 and classified11/32 development rows under a strict gate;
their conditional recall/FPR cannot be treated as directly comparable feature
ablation results. Full-class detection/false-positive fractions and refusals
are reported separately. Binary development models remain in ignored LAB
artifacts; the frozen RIT model and production refusal gate stay unchanged.

This is a small, balanced, previously exposed development cohort. A positive
result would require a larger locked Train/dev measurement and separate fresh
offline raw-to-result confirmation; it would not establish independent Test
accuracy or justify silently deploying a fallback on unknown PDFs.

The invocation completed from clean code9e3c8c3 in
`reports/experiments/cic_profile_accuracy/run_20261010T083405354981Z_9e3c8c3e3d9f/`.
All variants fit32 Train rows and classified32 Validation rows (16 of each
class), keeping threshold0.5. These are cached-profile measurements, not new
raw-to-result timings or Test scores.

| Variant | TP / malicious | FP / benign | Malicious F1 | MCC |
| --- | --- | --- | --- | --- |
| P0 | 12/16 | 13/16 | 0.5854 | -0.0756 |
| P1 | 12/16 | 13/16 | 0.5854 | -0.0756 |
| P2 | 12/16 | 12/16 | 0.6000 | 0.0000 |

Observed AST did not improve hard-label recall/FPR. Parser-status flags changed
one partial benign prediction, leaving poor discrimination. All15 Validation
parser-error files (8 malicious,7 benign) were predicted malicious by all three
variants. Only3 Train files had parser errors, illustrating the small cohort's
uneven failure coverage. No fallback candidate is promoted. Coverage1.0 here
means model input availability, not successful full structural/AST analysis.

## Missing-startxref maintenance

The14 missing-startxref files have recorded raw object/trailer counts, while
the code inspector previously stopped before object traversal. A benign
fixture with the marker removed reproduced this failure. V6 now permits one
in-memory zero-offset marker suffix only after the strict parser reports
`startxref_missing` and the original bounded bytes contain no `startxref` token.
Pypdf's existing lenient xref reconstruction remains inside the same OS-capped
worker and deadline. This changes a parser-only buffer, never the source file,
source checksum or canonical raw count. Its fixed diagnostic records that
reconstruction occurred. Original strict failure is retained; recovered AST
is an observed lower bound, all global counts/completeness remain unknown,
and reconstructed profiles are not cached as complete. A fake PDF still
refuses analysis, an existing marker is not replaced, and MemoryError is not
retried. Reconstruction does not establish valid revision history or safe PDF
behavior. Old v5 job/cache fingerprints are invalidated; saved v5 records remain
readable by their explicit historical schema contract.

The completed paired v6 console run recovered partial structure on all14 files,
with AcroForm/XFA/embedded-file lower bounds. It did not increase observed JS/AST
file counts or improve the strict pilot's classification/whole-file coverage.
See [the v6 measurement](cic_static_offline.md#completed-v6-paired-measurement).

The v6 saved-profile study pins its own explicit schema and four input checksums
in `configs/cic_profile_accuracy_v6.yaml`. It keeps the same three RF variants,
32/32 Train/development identities, seed42 and threshold0.5 as the v5 study.
This measures the effect of newly observed structure without reopening PDFs,
tuning on the exposed Validation rows or silently promoting a fallback.

The additional fixed RF200/depth12/min-leaf2/class-balanced study uses all870
cached CIC Train rows and the same291 Validation rows as the earlier XGBoost
study. Run `scripts/17_train_cic_static.py --config configs/cic_static_rf_accuracy.yaml`.
It reuses the existing40 measured predictors, identity/group checks and baseline
artifact. Median imputation with missing indicators fits only Train; source
nulls/sentinels and the saved split stay intact. Common finite Validation
eligibility retains comparable refusal denominators. Test is removed before
numeric conversion. Its LAB-only RF artifact has a distinct model identity;
numeric results do not establish end-to-end PDF coverage or independent Test
accuracy.

The RF study completed from clean commit 9398934 in
`reports/experiments/cic_static_rf_accuracy/run_20261010T100303272932Z_939893441e7f/`.
Both models classified the same 291 numeric Validation rows, with no refusals.
The frozen RIT baseline remained 134/160 TP and 112/131 FP. The RF candidate
detected 38/160 malicious rows (recall 23.75%) and flagged 34/131 benign rows
(FPR 25.95%). Its malicious F1 was 0.3276 and MCC -0.0254, compared with baseline
F1 0.6601 and MCC -0.0240. Lower false positives came with substantial recall
loss. This candidate is retained as negative development evidence and is not
promoted; the numeric40 features alone did not solve the accuracy problem.

## Completed v6 observed-evidence ablation

`run_20261010T100355572064Z_18f2aa3b29d5` completed from clean commit 18f2aa3 using
the sealed v6 offline records. The three variants fit exactly the same 32 Train
rows and score the same 32 exposed development rows (16 per class), retaining
all 15 parser-error inputs under the previously locked experimental fallback.
The production gate and original model are unchanged. No PDF or Test is read.

| Variant | TP / malicious | FP / benign | Malicious F1 | MCC |
| --- | --- | --- | --- | --- |
| P0 canonical RIT41 fallback | 12/16 | 13/16 | 0.5854 | -0.0756 |
| P1 additional observed structure/AST | 12/16 | 14/16 | 0.5714 | -0.1601 |
| P2 additional parser-status flags | 12/16 | 13/16 | 0.5854 | -0.0756 |

The new partial structure did not improve malicious recall; P1 falsely flagged
one more partial benign file than P0. P2 returned to the baseline hard-label
counts. All 15 parser-error inputs still receive malicious predictions, despite
including 7 benign files. Numeric fallback coverage is 32/32; complete analysis
coverage remains a separate quantity. No candidate is promoted, and no exposed
development threshold is adjusted to rescue these negative results.

The confirmed remaining extraction gaps include 24 unresolved-reference files,
18 failed structural parsers and 3 AST-error files on the 64-file cohort.
All 14 newly recovered missing-marker files share AcroForm/XFA/EmbeddedFile
counts, across both published labels. At the v6 review, the inspector traversed PDF
dictionaries but did not parse JavaScript inside XFA XML or inspect embedded
payload content; `inspect_js_syntax()` also discards its AST on syntax/resource
failure without separate lexical evidence. These are code-level coverage gaps,
not proof that any particular CIC file contains missed malicious behavior.
Future corrections need benign fixtures, bounded decoding/provenance, and a
new locked offline measurement before claiming recall/FPR improvement.

The review/maintenance suite passed 729 synthetic tests with 2 existing
single-label metric warnings. `pip check`, `git diff --check` and `git fsck`
passed. Full outputs and the exact Git-recovery backup remain in ignored LAB
artifacts; aggregate provenance is recorded in
`reports/experiments/cic_v6_review_checks/run_20261010T095754964749Z_537d06776817/`.
Empty Git objects were reconstructed with their original hashes; HEAD, index
and source files were preserved. This repair is separate from model outcomes.

## Completed v7 same 64 outcome

The user ran the prepared XFA job through the disconnected console LAB.
`run_20261010T154029301301Z_20cf4e14ac84` completed from clean commit 20cf4e1
at 15:44:41 UTC on 2026-10-10. Saved evidence verifies identical 64 identities,
labels, partitions, raw canonical features, configuration, limits and frozen
model bytes relative to v6; no Test rows are involved.

The strict C0/C1 pilots still classify 11/32 development rows (6 malicious,
5 benign). C0 retains 2/6 TP and 4/5 FP. C1 retains 2/6 TP and decreases from 3/5
to 2/5 FP: recall 33.33%, FPR 40%, malicious F1 0.4000 and MCC -0.0690.
Twenty-one refusals remain explicit; planned-class detection is 2/16 and
false-positive fraction 2/16. This is one fewer false positive on five benign
inputs, not independent evidence of a general accuracy gain. These are RF
pilot metrics, not the supplied frozen XGBoost's CIC accuracy.

The same-run observed P0/P1/P2 variants classify 32/32 known-input development
rows and exactly retain the v6 ablation's hard-label counts:

| Variant | Recall | FPR | Malicious F1 | MCC |
| --- | ---: | ---: | ---: | ---: |
| P0 canonical RIT41 fallback | 12/16 (75%) | 13/16 (81.25%) | 0.5854 | -0.0756 |
| P1 observed structure/AST | 12/16 (75%) | 14/16 (87.5%) | 0.5714 | -0.1601 |
| P2 observed plus parser flags | 12/16 (75%) | 13/16 (81.25%) | 0.5854 | -0.0756 |

Complete-parser coverage remains 23/64, with 23 partial and 18 parser-error
files. V7 records a declared XFA JS source, but its AST reaches the existing
node budget; another input reaches the XFA XML node budget. Observed JS/AST
file counts remain 25/20, with 22 parsed scripts and 4 AST-error files. The XFA
XML omission described in the historical v6 review is addressed in code,
without measured additional successful JS/AST coverage on this cohort.
Embedded-payload content and other recorded gaps remain outside the scope.
No limit, feature contract, threshold or candidate is selected from these
previously exposed development outcomes.

The requested upstream PDFMalExtract main now declares v0.1.1 and changes two
raw counters to `/AcroForm` and `/BaseEncoding`. The existing implementation
preserves the pinned v0.1 dataset contract and its Train-constant exclusions.
The upstream script still skips failed PDFs and does not inspect XFA XML/AST;
its source does not establish a remedy for the saved parser failures.
See [the paired measurement and source comparison](cic_static_offline.md#completed-v7-xfa-paired-measurement)
and the immutable
[model metrics](../experiments/cic_static_profile/run_20261010T154029301301Z_20cf4e14ac84/model_comparison.csv).
