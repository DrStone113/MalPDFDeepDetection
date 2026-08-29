# Protocol G deep-learning comparison

## 1. Objective

Assess whether two fixed tabular neural baselines improve on the committed XGBoost detector under the same feature-vector-disjoint Protocol G split. This is a comparative seed-42 result, not a claim that deep learning must win.

## 2. Dataset and Protocol G

RIT-PDFMal-2026 SHA-256 is `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`. The saved split manifest SHA-256 is `802c3962bc537ed78f63c5b1a5308e09df357a096f703846d0e5fe57598b4e21`: train 14,602, validation 4,868, and test 4,867 rows. Identical 41-dimensional static feature vectors are partition-disjoint; this is not evidence of PDF-file identity.

## 3. Preprocessing

The exact 38-feature `G-drop3constant` order is used, excluding only Acroform, Colors, and BaseEncoding. StandardScaler was fit on train rows only, then applied unchanged to validation and once to test after selection. Raw semantic values were not imputed, clipped, encoded, or altered.

## 4. Fixed architectures and training

- MLP: Linear 38→128→64→32→1, ReLU, LayerNorm after the first hidden layer, dropout 0.2/0.1/0.0.
- FT-Transformer: feature-specific numeric affine tokens, learned CLS token, d_token=32, two self-attention blocks, four heads, feed-forward width 128, GELU, dropout 0.1, and a one-logit head.
- Both use unweighted BCEWithLogitsLoss, AdamW (learning rate 0.001, weight decay 0.0001), batch size 256, maximum 150 epochs, patience 20, model seed 42, and validation-loss-only early stopping. Threshold is fixed at 0.5.

## 5. Test results and XGBoost comparison

| Model | Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) | F1 macro | ROC-AUC | PR-AUC | MCC | Parameters | Training s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| XGBoost historical Protocol G | 0.976988 | 0.995301 | 0.954054 | 0.974241 | 0.976723 | 0.997079 | 0.997354 | 0.954161 | n/a | 0.586 |
| mlp | 0.971029 | 0.995236 | 0.940991 | 0.967354 | 0.970657 | 0.995053 | 0.994965 | 0.942546 | 15617 | 34.986 |
| ft_transformer | 0.979453 | 0.990741 | 0.963964 | 0.977169 | 0.979246 | 0.996447 | 0.996691 | 0.958795 | 27969 | 118.711 |

## 6. Model complexity

- mlp: 15617 trainable scalar parameters; best validation epoch 45; training time 34.986 s.
- ft_transformer: 27969 trainable scalar parameters; best validation epoch 96; training time 118.711 s.
Parameter count is reported for neural models but is not strictly comparable to XGBoost's 200-tree complexity.

## 7. Interpretation

The highest observed malicious F1 is `ft_transformer`; the highest observed MCC is `ft_transformer`. MLP F1 delta versus historical XGBoost is -0.006887; FT-Transformer delta is +0.002928. These are observed fixed-protocol differences, not an invitation to search architectures until a neural model wins.

## 8. Threats to validity and conclusion

This comparison has one Protocol G split seed and fixed compact architectures rather than exhaustive tuning. CUDA determinism was requested, but GPU kernels/drivers can still prevent bit-identical reproduction. The official run emitted PyTorch warning-mode notices that CuBLAS requires `CUBLAS_WORKSPACE_CONFIG` for strict determinism and that memory-efficient attention may be non-deterministic; the successful fixed run was not repeated. The data are static tabular features, not raw PDFs or dynamic behavior, and no cross-dataset/generalization claim follows. XGBoost is a previously committed historical reference rather than a retrained concurrent model. Results therefore answer this focused seed-42 question only.
