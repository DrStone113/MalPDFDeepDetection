# PyTorch upgrade and Python runtime checks

The project now declares PyTorch 2.11.0 and torchvision 0.26.0, supporting Python 3.11 and 3.13. Python 3.11 remains the Codespace/devcontainer baseline. Codespace selects CPU wheels to reduce unused PyTorch CUDA storage; authorized Kaggle training uses the matching CUDA build. XGBoost bounds also accept the observed Kaggle 3.4.1 version.

| Runtime | PyTorch / torchvision | Full pytest | pip check |
| --- | --- | --- | --- |
| Codespace Python 3.11.13 | 2.11.0+cpu / 0.26.0+cpu | 578 passed, 2 warnings; 67.75 s | clean |
| Fresh Kaggle venv Python 3.13.15 | 2.11.0+cpu / 0.26.0+cpu | 578 passed, 20 warnings; 90.88 s | clean |

The Python 3.13 job installs the editable project with development dependencies from pyproject.toml in a new venv without system site packages. Sealed inputs contain code, tests/configs and aggregate-only thesis fixtures, with all individual/group identifiers omitted. 215 unmodified code/aggregate files were verified against generating commit e9ae2aee5365a2f27d807ac289e2453a44d51cf6 after LF normalization; 10 returned evidence files passed SHA-256 verification. Two earlier failures (missing ensurepip and an omitted aggregate-fixture validation field) remain in the append-only log and immutable reports.

Warnings: Python 3.13 reports 18 standard multiprocessing fork deprecation warnings from synthetic tests and two existing single-label confusion-matrix warnings. The host Kaggle sitecustomize also prints an optional wrapt import message; project dependency checks and all tests exit successfully. These are recorded rather than suppressed.

A checksum-verified FT-Transformer checkpoint generated with PyTorch 2.7.1 loaded under 2.11.0 using weights_only=True, matched the state dict strictly, and produced finite outputs for two synthetic feature rows. No dataset inference or Test evaluation was performed during compatibility checks. Historical reports, datasets, caches and checkpoints were preserved. Local git diff --check passed. Codespace retained approximately 5.8 GiB free at completion.

The actual 50-fit private Kaggle development study used Python 3.13.15 / PyTorch 2.11.0+cu128 / torchvision 0.26.0+cu128, with CUDA FP16 FT training on Tesla T4 and trees on CPU. Its 64-row CIC Validation selection Accuracy remained 53.125% and MCC near zero. It is development evidence, not a new independent Test result, and has not replaced the deployed model.

Compatibility kernel: https://www.kaggle.com/code/nguyenkhang294/malpdf-pytorch313-qc-20261004-154850
Training kernel: https://www.kaggle.com/code/nguyenkhang294/malpdf-static-development-20261004-140347
Training evidence: ../static_development_summary/run_20261004T154256846017Z_e9ae2aee5365/summary.md
