# CIC raw-PDF normalization and frozen cross-dataset evaluation

The six-branch v3 stack was evaluated once, without fitting or threshold changes,
on 1,452 independent valid PDFs (800 published malicious labels, 652 benign).
This is a separately locked valid-PDF study, not an evaluation of all CIC rows.

| Selection stage | Rows |
| --- | ---: |
| Local CIC Parquet | 10,023 |
| Known source SHA identities excluded | 8,386 |
| Source-equivalent model-input vectors excluded | 146 |
| Unsupported identifiers excluded | 11 |
| Input refusals, separately referred without scores | 28 |
| Independently evaluated valid PDFs | 1,452 |

The 3,727 disagreements among overlapping identities remain unresolved. Both
publisher labels are retained; neither archive names nor static token/YARA
observations establish ground truth. The saved preparation counted 145 feature
exclusions in memory; a recheck of numeric CSV inputs excluded one additional
vector before predictions. Source feature grouping is independent of labels.

Raw parsing preserved all 43 measured columns and nulls; the original frozen
model order has 40 columns. 9,984 rows were parsed, with 434 parser flags;
1,598 Markov caches were created and 8,386 verified caches reused. Every retained
evaluation row has complete measurements. Matrices preserve their original
float32 conditional transition probabilities. The AES-wrapped Malicious2.zip
was not decrypted. Failed acquisition evidence and the blocked full-cohort
preparation remain preserved.

| Metric | Frozen CIC valid-PDF cohort |
| --- | ---: |
| Accuracy | 0.51446281 |
| Malicious F1 | 0.62440064 |
| MCC | -0.02337365 |
| Brier | 0.46416972 |
| Log loss | 1.78803463 |
| ECE (10 equal-width bins) | 0.46148688 |

The confusion matrix is TN=161, FP=491, FN=214, TP=586. Accuracy is below the
55.10% majority-label reference, and MCC is slightly negative. These results do
not demonstrate reliable transfer or evasion resilience on the published labels.
Distribution shift and label/source quality cannot be separated by this study.

Entropy routing referred 145/1,452 rows (9.986%), retaining 1,307 (90.014%). It
caught 0/214 false negatives; retained accuracy was 50.803%. The additional 28
input refusals receive mandatory unscored referrals. Among 1,480 post-overlap
candidates, combined static coverage is 88.311% and referral is 11.689%. Missing
probabilities and FN catch for input refusals remain unavailable; referrals are
not credited as corrected predictions and no dynamic sample was executed.

Generating evaluation revision: 392482a1571cf031018e51a1205bcfdd0a25c1ee. The code checkout was
clean at invocation. All 25 saved tabular folds, Vision weights, Train-only
preprocessing, Validation-only meta/Platt coefficients and Youden threshold
were restored. The original Protocol G Test was not rerun. The comparison CSV
copies its saved result and cannot be used to select another model or threshold.

Full synthetic suite: 516 tests passed before this execution. Source code hashes
are rechecked against the saved precheck snapshot; final dependency and Git
checks are recorded alongside this summary. Raw files, identities, caches,
checkpoints and detailed predictions stay ignored; the main workspace retains
its pre-existing changes.
