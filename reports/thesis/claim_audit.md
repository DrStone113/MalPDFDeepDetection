# Claim and Terminology Audit

## Method

On 2026-08-29, the repository was searched with:

```powershell
rg -ni -C 1 -g '*.md' -e 'duplicate PDF' -e 'deep learning is better' -e 'RIT-compatible extractor' -e 'proves generalization' -e 'real-world accuracy' -e 'dynamic detector' -e 'hybrid detector' -e 'sandbox evaluated' -e 'statistically significant' reports README.md
```

The thesis documents were then reviewed against the resulting contexts and this audit's prescribed wording.

## Findings and wording controls

| Risky claim area | Search finding | Thesis-package wording / action |
| --- | --- | --- |
| Duplicate PDF files | Matches in historical reports and the new package explicitly negate the claim because no original file hashes exist. | Use “identical 41-dimensional feature vectors” or “feature-equivalent groups”; never infer file identity. |
| Generalization | No unqualified “proves generalization” match was found. Historical P/G analysis already limits the inference. | State only “feature-vector-disjoint evaluation” and name what it does not test: temporal, file-identity, external, or real-world deployment validity. |
| Deep learning superiority | No “deep learning is better” match was found. | FT-Transformer is “best observed by f1_malicious and MCC in one fixed split”, not superior in general. Its ROC-AUC/PR-AUC are lower than the historical XGBoost reference. |
| RIT compatibility | Static reports document a schema-level 38/38 gate and separately warn that raw RIT record-level equality is unavailable. | Use “RIT-schema-oriented” / “schema-level compatibility”; do not call the extractor record-level RIT-verified. |
| Real-world accuracy | No “real-world accuracy” claim was found. | Deployment uses a full-data static artifact but contributes no new benchmark, calibration, or operational result. |
| Dynamic/hybrid/sandbox evaluation | No match claims a completed evaluation. Dynamic and CAPE reports repeatedly say offline/design-only. | Use “dynamic-schema/routing implemented” and “CAPE laboratory designed”; explicitly state no live dynamic, hybrid, or sandbox performance result. |
| Statistical significance | No claim of statistical significance was found. | Five-seed values are “descriptive mean ± sample standard deviation” and paired directions only; no p-values or inferential claim. |
| F1 metric semantics | Historical files include generic `F1` labels in some figure/report contexts. | All primary thesis tables use `f1_malicious` and `f1_macro`. Paper P/R/F1 comparison is called macro. Generic historical figures are not selected as primary evidence. |

Historical reports are preserved rather than rewritten. Where an older table/figure label is less explicit, this package links to the metric-semantics correction and uses qualified language around it.
