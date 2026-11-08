# Canonical PDF-TransGraph v2 (23D) Training & Evaluation Report — `run_20261106T151845675931Z_c6b920385d96`

## 1. Provenance & Quality Gate v2 Pre-Flight Verification

- **Git Commit:** `c6b920385d966eaba9f0e1eec0ac2dcb789a4664`
- **Execution Device:** `NVIDIA GeForce RTX 5060 Ti`
- **Canonical Extraction Job ID:** `89bf66f04d932dece2518500fbdfb3121fff8799df74b2f02accac03197e1900`
- **Quality Gate Contract:** `pdf-extraction-quality-gate-v2` (`ready_for_locked_export`, `8/8` checks passed)
- **Graph Projection Contract:** `pdf-graph-projection-v2` (`node_feature_dim = 23`, `node_cap = 200`)
- **Cohort Accounting:** `1,452` planned (`870` train, `291` validation, `291` test); `1,446` GNN-eligible 23D graphs (`866` train, `289` validation, `291` test); `6` ledgered unavailable empty-graph documents (`train=[11, 292, 407, 749]`, `validation=[3, 141]`, `test=[]`).
- **Strict Policy Enforcement:** `placeholder_nodes_inserted = false`, `eval_denominator_shrinkage_allowed = false`, `StandardScaler` fit strictly on `train` (`870` rows).

## 2. Component Ablation Study (Seed 42 — Full Split Denominators: Val=291, Test=291)

| Configuration | Mode | Train N | Val Acc (291) | Val F1 (291) | Test Acc (291) | Test Precision | Test Recall | Test F1 | Test MCC | Test ROC-AUC | Test PR-AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tabular ResNet Only | `tab_only` | 870 | 96.56% | 0.9684 | 95.88% | 95.12% | 97.50% | 0.9630 | 0.9168 | 0.9858 | 0.9859 |
| AST Transformer Only | `ast_only` | 870 | 54.98% | 0.7095 | 54.98% | 54.98% | 100.00% | 0.7095 | 0.0000 | 0.4810 | 0.5377 |
| Tabular + AST (No Graph) | `tab_ast` | 870 | 97.25% | 0.9750 | 95.88% | 95.68% | 96.88% | 0.9627 | 0.9167 | 0.9848 | 0.9847 |
| Hetero HGT Graph Only | `graph_only` | 866 | 55.33% | 0.7111 | 54.98% | 54.98% | 100.00% | 0.7095 | 0.0000 | 0.4704 | 0.5440 |
| Tabular + HGT (No AST) | `tab_graph` | 866 | 96.91% | 0.9716 | 95.19% | 95.06% | 96.25% | 0.9565 | 0.9028 | 0.9866 | 0.9886 |
| PDF-TransGraph Full (All 3 Fused) | `full` | 866 | 96.91% | 0.9714 | 95.88% | 95.12% | 97.50% | 0.9630 | 0.9168 | 0.9860 | 0.9871 |

## 3. Representation Comparison: Legacy 19D (`v1`) vs Provenance-Backed 23D (`v2`)

| Configuration | `v1` (19D) Test Acc | `v2` (23D) Test Acc | `v1` (19D) Test F1 | `v2` (23D) Test F1 | `v1` (19D) ROC-AUC | `v2` (23D) ROC-AUC | F1 Delta (`v2 - v1`) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tabular ResNet Only | 93.47% | 95.88% | 0.9389 | 0.9630 | 0.9847 | 0.9858 | +0.0241 |
| AST Transformer Only | 54.98% | 54.98% | 0.7095 | 0.7095 | 0.4993 | 0.4810 | +0.0000 |
| Tabular + AST (No Graph) | 94.85% | 95.88% | 0.9530 | 0.9627 | 0.9883 | 0.9848 | +0.0098 |
| Hetero HGT Graph Only | 54.98% | 54.98% | 0.7095 | 0.7095 | 0.5200 | 0.4704 | +0.0000 |
| Tabular + HGT (No AST) | 94.50% | 95.19% | 0.9497 | 0.9565 | 0.9862 | 0.9866 | +0.0068 |
| PDF-TransGraph Full (All 3 Fused) | 93.81% | 95.88% | 0.9430 | 0.9630 | 0.9850 | 0.9860 | +0.0199 |

## 4. Multi-Seed Statistical Significance (`PDF-TransGraph v2 Full`, 23D)

### 4.1 Academic 3-Seed Suite (`[42, 100, 2026]`)
- **Test Accuracy:** `95.99% +/- 0.16%`
- **Test Precision:** `94.95% +/- 0.24%`
- **Test Recall:** `97.92% +/- 0.59%`
- **Test F1-Score:** `0.9641 +/- 0.0016`
- **Test MCC:** `0.9193 +/- 0.0036`
- **Test ROC-AUC:** `0.9823 +/- 0.0051`
- **Test PR-AUC:** `0.9782 +/- 0.0105`
- **Test Brier Score:** `0.0381 +/- 0.0038`

### 4.2 Protocol G 5-Seed Suite (`[42, 43, 44, 45, 46]`)
- **Test Accuracy:** `93.95% +/- 3.01%`
- **Test Precision:** `92.23% +/- 4.97%`
- **Test Recall:** `97.62% +/- 1.27%`
- **Test F1-Score:** `0.9475 +/- 0.0235`
- **Test MCC:** `0.8813 +/- 0.0546`
- **Test ROC-AUC:** `0.9817 +/- 0.0054`
- **Test PR-AUC:** `0.9803 +/- 0.0102`
- **Test Brier Score:** `0.0509 +/- 0.0211`

### 4.3 Individual Seed Runs (`Test N = 291`)

| Seed | Val F1 (291) | Val F1 (GNN 289) | Test Acc (291) | Test Precision | Test Recall | Test F1 | Test MCC | Test ROC-AUC | Confusion Matrix (TN, FP, FN, TP) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 42 | 0.9714 | 0.9712 | 95.88% | 95.12% | 97.50% | 0.9630 | 0.9168 | 0.9860 | `(123, 8, 4, 156)` |
| 100 | 0.9752 | 0.9750 | 95.88% | 95.12% | 97.50% | 0.9630 | 0.9168 | 0.9750 | `(123, 8, 4, 156)` |
| 2026 | 0.9812 | 0.9811 | 96.22% | 94.61% | 98.75% | 0.9664 | 0.9244 | 0.9858 | `(122, 9, 2, 158)` |
| 43 | 0.9781 | 0.9779 | 94.85% | 94.48% | 96.25% | 0.9536 | 0.8959 | 0.9741 | `(122, 9, 6, 154)` |
| 44 | 0.9625 | 0.9623 | 95.53% | 93.49% | 98.75% | 0.9605 | 0.9110 | 0.9844 | `(120, 11, 2, 158)` |
| 45 | 0.9750 | 0.9748 | 87.97% | 82.38% | 99.38% | 0.9008 | 0.7729 | 0.9766 | `(97, 34, 1, 159)` |
| 46 | 0.9659 | 0.9657 | 95.53% | 95.65% | 96.25% | 0.9595 | 0.9097 | 0.9876 | `(124, 7, 6, 154)` |

## 5. Error Taxonomy & Unavailable-Document Audit (Seed 42)

- **Held-Out Test Set (`291` samples, `0` unavailable):** `4/160` False Negatives, `8/131` False Positives.
- **False Negatives by Extraction Status:** `{"decode_error": 1, "unsupported": 3}`
- **False Positives by Extraction Status:** `{"bounded_complete": 1, "timeout": 1, "unsupported": 6}`
- **False Negatives by Sample Disposition:** `{"usable_degraded_partial_or_timeout": 4}`
- **False Positives by Sample Disposition:** `{"usable_complete_projection": 1, "usable_degraded_partial_or_timeout": 7}`

## 6. Computational Complexity & Latency Benchmark

- **Node Input Dimension:** `23D`
- **Total Trainable Parameters:** `808,323`
  - Graph Encoder (`HeteroGraphTransformer` 23D): `172,288`
  - AST Encoder (`ASTSequenceTransformer` RoPE): `273,537`
  - Tabular Encoder (`TabularResNet`): `72,576`
  - Cross-Modal Attention & Classifier Head: `281,473`
- **GPU Inference Latency:** `20.345 ms/sample` (Peak VRAM: `35.77 MB`)
- **CPU Inference Latency:** `13.38 ms/sample`
