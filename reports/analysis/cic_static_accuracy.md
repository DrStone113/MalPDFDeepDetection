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

This correction is verified on synthetic benign inputs only. A paired same64
offline console measurement must verify real recovery and model effects;
there is no measured new real-PDF accuracy or parser coverage gain for v6 yet.
