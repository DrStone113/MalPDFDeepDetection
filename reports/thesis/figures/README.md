# Thesis Figure Inventory and Quality Check

The following existing, tracked figures are suitable for thesis use because their labels make the relevant metric or contribution clear and visual inspection found readable text, non-clipped axes, and sufficient contrast at the stored resolution.

| Figure | Suggested thesis use | Quality check |
| --- | --- | --- |
| [`../../figures/multiseed/mean_f1_by_model_protocol.png`](../../figures/multiseed/mean_f1_by_model_protocol.png) | Protocol P/G five-seed malicious-positive mean F1 comparison | Readable model labels and legend; caption must state mean ± sample SD is in the source table. |
| [`../../figures/multiseed/mean_mcc_by_model_protocol.png`](../../figures/multiseed/mean_mcc_by_model_protocol.png) | Complementary MCC comparison | Use with the same seed and fixed-randomness limitation. |
| [`../../figures/explainability/xgb_protocol_g_shap_bar.png`](../../figures/explainability/xgb_protocol_g_shap_bar.png) | Global TreeSHAP ranking for Protocol G XGBoost | Feature labels and contribution scale are readable; explain as descriptive only. |
| [`../../figures/explainability/xgb_protocol_g_shap_distribution.png`](../../figures/explainability/xgb_protocol_g_shap_distribution.png) | Contribution-distribution supplement | Retain the legend and explanation boundary in caption. |
| [`../../figures/deep_learning/ft_transformer_training_curve.png`](../../figures/deep_learning/ft_transformer_training_curve.png) | Fixed FT-Transformer training history | Clearly label it as a single split/run, not a tuning curve. |
| [`../../figures/deep_learning/mlp_training_curve.png`](../../figures/deep_learning/mlp_training_curve.png) | Fixed MLP training history | Clearly label it as a single split/run, not a tuning curve. |

The Mermaid architecture diagram in [`../methodology_summary.md`](../methodology_summary.md) is the system figure; green nodes are implemented and gray dashed nodes are planned/design-only.

Historical figures whose axes say only “F1” are not selected as primary thesis figures because their labels do not identify malicious-positive versus macro averaging. The numerical evidence remains preserved in the explicit-metric tables; no historical figure was altered to change a result.
