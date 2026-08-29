# Protocol G seed-42 deep-learning comparison

This is a focused, fixed-configuration comparison of MLP and FT-Transformer against the already committed historical XGBoost `G-drop3constant` test result. It is not a deployment evaluation and does not retrain XGBoost.

- Dataset SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`; split manifest SHA-256: `802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21`.
- Partitions: train 14602; validation 4868; test 4867.
- StandardScaler is fit only on train. Checkpoint selection is by validation BCEWithLogitsLoss; test is evaluated once at threshold 0.5 after checkpoint reload.
- Device: `cuda`; code commit: `e84a97d58ac68c241693f239a24e4fc4c8bc4718`.

## Test comparison

| Model | Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) | F1 macro | ROC-AUC | PR-AUC | MCC | Parameters | Training s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| XGBoost historical Protocol G | 0.976988 | 0.995301 | 0.954054 | 0.974241 | 0.976723 | 0.997079 | 0.997354 | 0.954161 | n/a | 0.586 |
| mlp | 0.971029 | 0.995236 | 0.940991 | 0.967354 | 0.970657 | 0.995053 | 0.994965 | 0.942546 | 15617 | 34.986 |
| ft_transformer | 0.979453 | 0.990741 | 0.963964 | 0.977169 | 0.979246 | 0.996447 | 0.996691 | 0.958795 | 27969 | 118.711 |

## Confusion matrices

- mlp: TN/FP/FN/TP = 2637/10/131/2089.
- ft_transformer: TN/FP/FN/TP = 2627/20/80/2140.

No test metric was used for epoch selection, architecture choice, class weighting, threshold setting, or reruns.

## Runtime reproducibility warning

PyTorch requested deterministic algorithms in warning mode, disabled cuDNN benchmarking, and seeded CPU/CUDA RNGs. The official CUDA run emitted PyTorch warnings that CuBLAS operations require `CUBLAS_WORKSPACE_CONFIG` for strict determinism and that memory-efficient attention may be non-deterministic. These warnings are recorded as a limitation; the successful fixed-configuration run was not repeated.
