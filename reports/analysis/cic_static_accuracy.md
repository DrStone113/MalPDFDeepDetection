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
These fixture corrections have no new real-CIC recall/FPR result yet. The
same 64-file offline diagnostic subset must be measured again through the
existing CLI after clean source and preparation commits.
