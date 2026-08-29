# Limitations and Threats to Validity

- The local RIT CSV lacks original PDF hashes and raw RIT PDFs. Feature-vector-disjointness is not PDF-file, family, temporal, or provenance disjointness; record-level extractor equality cannot be verified.
- Protocol P is only paper-aligned: the paper does not fully specify its seed, hyperparameters, preprocessing, zero-variance treatment, or every cross-validation detail.
- Protocol G has smaller training partitions and a different split construction than P. Its lower scores for most models should not be interpreted as proof of real-world generalization differences.
- The multi-seed study has five fixed split seeds and fixed model randomness. It reports descriptive mean ± sample standard deviation and paired directions, not statistical significance or calibrated uncertainty.
- CV10 is row-level, non-stratified shuffled KFold and allows equal feature vectors in separate folds. Hardware/software runtime and variation are not directly comparable with the paper.
- Threshold 0.5 is frozen for the deployment detector; calibration, cost-sensitive operation, robustness, and alert-management performance are not evaluated.
- SHAP values describe a fitted model and local feature distribution; they do not establish malware causality, safe feature manipulation, or evasion resistance.
- The neural comparison fixes one architecture and one Protocol G split. CUDA operations can have residual non-determinism; it is not a broad deep-learning benchmark.
- CIC-Evasive-PDFMal2022 evidence is exploratory only. The reviewed third-party mirrors disagree and strict-six readiness was intentionally blocked, so there is no cross-dataset result.
- No live PDF execution, CAPE run, dynamic classifier, hybrid detector, sandbox measurement, external validation, temporal holdout, or operational deployment trial has been performed.
