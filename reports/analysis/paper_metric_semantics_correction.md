# Paper metric-semantics correction

## 1. Background

The completed RIT-PDFMal-2026 baselines preserve their original operational reporting convention: Label=1 (malicious) is the positive class. This audit adds a non-destructive macro-metric view for paper comparison; it does not change stored predictions, split assignments, or historical baseline result files.

## 2. Metric definitions used locally

- `precision_malicious`, `recall_malicious`, and `f1_malicious` refer to Label=1. Historical `precision`, `recall`, and `f1` remain backward-compatible aliases for those malicious-positive values.
- `precision_macro`, `recall_macro`, and `f1_macro` average the benign and malicious class metrics with equal class weight.
- Accuracy is unchanged. ROC-AUC and PR-AUC retain Label=1 score semantics; MCC remains a binary metric and is unchanged.

## 3. Metric definitions stated in the paper

The paper's metric-definition section presents binary formulas, while its Table 5 GNB numerical values do not equal the malicious-class values reconstructed from the reported class rates and confusion information. The available evidence is therefore insufficient to treat Table 5 Precision, Recall, and F1 as malicious-positive metrics.

## 4. Numerical inconsistency observed

The reconstructed GNB malicious true-positive rate is approximately 98.41% and benign true-negative rate approximately 31.79%. These class-specific rates are compatible with the paper's reported behavior but not with Table 5 Precision, Recall, and F1 when those columns are read as malicious-positive metrics.

## 5. GNB confusion-matrix reconstruction

The paper test class counts are 3,309 benign and 2,776 malicious. The reported confusion-matrix information reconstructs as TN=1,052, FP=2,257, FN=44, TP=2,732. The following computation uses only these counts:

| Metric | Paper Table 5 | Malicious-positive | Macro | Macro matches Table 5 |
| --- | --- | --- | --- | --- |
| accuracy | 0.621857 | n/a | 0.621857 | True |
| precision | 0.753729 | 0.547605 | 0.753729 | True |
| recall | 0.651035 | 0.984150 | 0.651035 | True |
| f1 | 0.590655 | 0.703670 | 0.590655 | True |

## 6. Evidence for macro averaging

For GNB, macro Precision, Recall, and F1 reconstructed from the paper counts match the Table 5 values within a 1e-6 rounding tolerance, while the malicious-positive values do not. This is numerical evidence for macro averaging in Table 5; it does not establish why the paper's narrative formulas and reported table differ.

## 7. Corrected paper-comparison methodology

Paper Accuracy is compared with local Accuracy. Paper Precision, Recall, and F1 are compared with local macro Precision, Recall, and F1, respectively. Local malicious-positive metrics remain separately reported because they are operational malware-detection metrics. The full mapping is in `reports/tables/metric_semantics/metric_definition_map.csv`.

## 8. Impact on previous conclusions

The Protocol P-versus-G comparison remains unchanged: both completed local baselines used Label=1 malicious-positive Precision, Recall, and F1, so their direct local-to-local deltas retain one consistent definition. The correction applies to comparisons with paper Table 5.

The prior P-vs-G analysis now explicitly records this distinction. Its local P-versus-G conclusions do not change, because both sides use the same malicious-positive convention.

## 9. Residual GNB discrepancy

| Metric | Paper | Local P macro | Local minus paper |
| --- | --- | --- | --- |
| Accuracy | 0.621857 | 0.589975 | -0.031882 |
| Precision (macro) | 0.753729 | 0.747913 | -0.005816 |
| Recall (macro) | 0.651035 | 0.622215 | -0.028820 |
| F1 (macro) | 0.590655 | 0.545267 | -0.045388 |

Before semantic alignment, the Local P GNB malicious-positive Precision/Recall/F1 differences from the paper values were -0.226798, 0.339239, and 0.097197. After macro-to-macro comparison, the residual differences are -0.005816, -0.028820, and -0.045388. Thus much of the previous P/R/F discrepancy is metric-definition mismatch, while residual differences remain and cannot be assigned to one cause from these results alone.

## 10. All-model corrected comparison

| Model | Variant | Accuracy delta | Macro precision delta | Macro recall delta | Macro F1 delta |
| --- | --- | --- | --- | --- | --- |
| LR | P-all41 | 0.024651 | 0.025662 | 0.021272 | 0.024304 |
| LR | P-drop3constant | 0.024651 | 0.025662 | 0.021272 | 0.024304 |
| RF | P-all41 | -0.002794 | -0.002587 | -0.003004 | -0.002822 |
| RF | P-drop3constant | -0.003123 | -0.002919 | -0.003335 | -0.003153 |
| DT | P-all41 | -0.003451 | -0.003560 | -0.003377 | -0.003474 |
| DT | P-drop3constant | -0.003616 | -0.003760 | -0.003499 | -0.003638 |
| GNB | P-all41 | -0.031882 | -0.005816 | -0.028820 | -0.045388 |
| GNB | P-drop3constant | -0.031882 | -0.005816 | -0.028820 | -0.045388 |
| XGB | P-all41 | -0.002301 | -0.002154 | -0.002463 | -0.002322 |
| XGB | P-drop3constant | -0.002301 | -0.002154 | -0.002463 | -0.002322 |

## 11. Implications for future experiments

Future result schemas expose both malicious-positive and macro metrics. Future paper-comparison tables must map Table 5 P/R/F to macro fields, preserve malicious-positive fields for security operations, and retain the metric-definition note. Remaining differences may reflect the unreported paper split seed, hyperparameters, preprocessing, software behavior, or other undocumented methodology; no tuning was performed in this audit.
