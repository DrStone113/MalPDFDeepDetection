# Tri-Modal Stacking v3 cross-dataset readiness

Status: **blocked before CIC inference**. Run: `run_20261003T091848313122Z_3b68d36a5705`.

The local Kaggle Parquet mirror contains **10,023 rows**, with 4,468 Benign and 5,555 Malicious labels. The [CIC publisher](https://www.unb.ca/cic/datasets/pdfmal-2022.html) reports 10,025 rows (4,468 benign, 5,557 malicious). The two missing malicious rows are not fabricated or restored. The archive contains only `PDFMalware2022.parquet`; no CIC PDFs or verified Markov matrices are present.

The frozen v3 input has 40 raw features. The existing conservative semantic review identifies 6 exact, 18 ambiguous and 16 unmatched feature relations. See `feature_compatibility.csv`. `ObfuscationCount` must remain measured from actual PDF bytes. Neither missing features nor Vision probabilities can be replaced with zeros, guessed values or source-domain samples.

The [publisher](https://www.unb.ca/cic/datasets/pdfmal-2022.html) lists Contagio and VirusTotal as collection sources. The v3 cohort includes mirrored Contagio PDFs. Filename-like identifiers do not verify file identity; target file hashes and related-group evidence are needed to exclude known source overlap before an independent evaluation. No zero-overlap or evasion-resilience result is claimed.

| Cohort | Accuracy | F1 malicious | MCC | Routing coverage | Status |
|---|---:|---:|---:|---:|---|
| Saved Protocol G Test, 4,050 rows | 0.999259259 | 0.999334664 | 0.998500367 | 90% | Existing saved reference |
| CIC mirror, 10,023 rows | N/A | N/A | N/A | N/A | Missing required inputs |

The reference metrics are copied from `run_20261003T085417853973Z_4b4478ca98a8` without reevaluation. `cross_dataset_comparison.csv` also records Brier and ECE. No model fitting, calibration, threshold selection, sample execution or original Test reevaluation occurred. The saved threshold remains `0.037803058353758114` and the prospective entropy referral budget remains 10%; no CIC referral rate was measured.

To continue, provide a labeled CIC PDF manifest, or verified numeric Markov matrices plus features from the same v3 parser, including actual security counts and parser flags. The locked external design will exclude known duplicate and related files and retain the original models, preprocessing, calibration and threshold.
