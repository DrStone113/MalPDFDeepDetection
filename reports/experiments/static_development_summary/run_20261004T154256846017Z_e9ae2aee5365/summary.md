# Static model development on private Kaggle GPU

Completed 50 fits (five static families × five saved Train folds × two weighting schemes) in 135.61 seconds. FT-Transformer used CUDA FP16 on Tesla T4; tree models used two CPU threads. The existing Vision model was unchanged. Checkpoints remain in private Kaggle Output.

The original Train/Validation partitions and four disjoint Validation roles were preserved. All 40 measured security features and ten metadata-missingness flags remained available. Source/parser nulls were preserved; RF/FT preprocessing fit only within each Train fold. Calibration, meta fitting and selection used their saved separate Validation roles. Neither source nor CIC Test was predicted or scored. Both existing Test cohorts had been exposed in earlier studies, so this is retrospective development, not a fresh independent evaluation.

| Scheme | Validation selection cohort | Rows / groups | Accuracy | F1 malicious | MCC | Brier | ECE |
| --- | --- | --- | --- | --- | --- | --- | --- |
| uniform | source_raw | 817 / 462 | 0.997552 | 0.997290 | 0.995070 | 0.002649 | 0.034119 |
| uniform | cic | 64 / 48 | 0.531250 | 0.680851 | 0.016169 | 0.384947 | 0.359361 |
| cohort_group_class | source_raw | 817 / 462 | 0.998776 | 0.998643 | 0.997531 | 0.008529 | 0.083164 |
| cohort_group_class | cic | 64 / 48 | 0.531250 | 0.666667 | 0.023669 | 0.354826 | 0.329155 |

Equal cohort/class/group Train weighting selected C=0.1 and Youden threshold=0.14863979640166966 by Validation macro-cohort MCC and the locked tie-breakers. On the 64 CIC selection rows (48 groups), Accuracy stayed 53.125%; MCC stayed near zero and malicious F1 decreased. CIC Brier/ECE improved, while source calibration worsened. These results do not establish an effective evasion improvement, and the candidate has not replaced the deployed model. The CIC early-stopping role consists of 88 rows in a single mixed-label model-input-equivalence group; diagnostics have substantial sampling and grouping limitations.

Entropy routing referred 6/64 CIC rows (9.375%, nearest integer to 10%) under both schemes. It caught 0/2 and 0/4 CIC false negatives respectively. Source routing referred 82/817 rows (10.037%), including five parser failures. Referrals are recommendations only, with zero sandbox executions and no errors counted as corrected.

PyTorch runtime during training was 2.11.0+cu128, torchvision 0.26.0+cu128, Python 3.13.15 and XGBoost 3.4.1. This differed from the pre-upgrade bounds at generating revision 579e337990c75a2fe6baca198d4f1f38a282ed37; it is recorded as the observed cloud environment, not claimed as a reproduction of those older dependency declarations. The user subsequently authorized upgrading the project to PyTorch 2.11.0 / torchvision 0.26.0 and supporting Python 3.11 and 3.13. The local CPU upgrade passed 578 tests and pip check; separate Python 3.13 package-compatibility QC is recorded under its own study.

Verified 94 source-file SHA-256 values against the generating Git revision and recomputed all 96 saved Validation metric rows. Round-trip CSV parsing is required for exact probability comparisons at the locked threshold. No historical report was overwritten.

Training: https://www.kaggle.com/code/nguyenkhang294/malpdf-static-development-20261004-140347
Evidence: reports/experiments/static_development_validation/run_20261004T150445937096Z_579e337990c7
