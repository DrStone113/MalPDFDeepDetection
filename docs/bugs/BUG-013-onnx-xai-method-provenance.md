# BUG-013 — ONNX occlusion was mislabeled as gradient saliency

Status: RESOLVED. Severity: MEDIUM. Category: EVIDENCE_INTEGRITY.
Recorded: 2026-11-10.

## Symptoms and root cause — five whys

ONNX explanations reported `measured_gradient_saliency` although they masked
selected inputs and measured logit changes. Unevaluated positions appeared as zero.

1. Shared forensic formatting always called saliency gradient-derived.
2. ONNX reused it without supplying a method identifier.
3. Selected-position occlusion populated a full vector with zero defaults.
4. Consumers could not distinguish unknown positions from measured zero effect.
5. The parity test asserted the incorrect label without a provenance contract.

## Resolution and anti-regression invariants

The backend supplies `occlusion`; PyTorch retains `gradient_input`. The dossier
reports `xai_method` and evaluated/total coverage. Unevaluated ONNX nodes are
`null`; only evaluated tabular features enter ranked attributions. A measured
zero remains zero instead of being replaced by arbitrary uniform importance.
ONNX sparsity is calculated only over evaluated attribution values and is labeled
`sparsity_scope=evaluated_inputs`; excluded dimensions are not counted as zero.

- Method labels describe the computation, independent of prediction parity.
- Unknown attribution is distinct from measured zero.
- Cross-matrix rows reference only evaluated nodes.
- Regression: `test_xai_provenance.py`, corrected `test_onnx_production.py`.

No training, new detector accuracy or explanation-parity claim is made.
