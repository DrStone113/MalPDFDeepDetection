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
