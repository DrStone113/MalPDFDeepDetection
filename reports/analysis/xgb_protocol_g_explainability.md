# Protocol G XGBoost TreeSHAP explainability

## 1. Objective

This analysis describes feature contributions to the established seed-42 Protocol G XGBoost malicious-class margin. It does not tune, select features, or change the benchmark.

## 2. Model and evaluation protocol

- Protocol G reuses the saved feature-vector-disjoint split; equal 41-dimensional static vectors cannot cross partitions. This is not a proof of PDF-file identity or real-world generalization.
- XGBoost uses `G-drop3constant`: 38 features, with only Acroform, Colors, and BaseEncoding absent.
- Train rows: 14602; explained test rows: 4867. Test rows are never used for fitting.

## 3. TreeSHAP methodology and verification

Native `Booster.predict(DMatrix, pred_contribs=True)` was used. The final contribution column is bias/base value, not a feature.
- Contribution shape: [4867, 38] plus one bias per row.
- Max |sum(SHAP)+bias−margin|: 1.02e-05.
- Max |sigmoid(margin)−probability|: 8.28e-08.
- Historical Protocol G reproduction verification: `True`.

## 4. Global feature importance

Mean absolute TreeSHAP is the primary global model-importance measure. Positive contributions increase the raw malicious-class margin; negative contributions decrease it. Contributions are associative, not causal.

| Rank | Feature | Mean |SHAP| | Mean SHAP | Paper meaning |
| --- | --- | --- | --- | --- |
| 1 | JavaScript | 3.53258 | 1.17031 | Number of occurrences of the string "/JavaScript" in the PDF file. |
| 2 | pdfsize | 0.953764 | -0.313766 | Size of the PDF file in kilobytes. |
| 3 | URI | 0.826528 | -0.298257 | Number of occurrences of the string "/URI" in the PDF file. |
| 4 | contains_text | 0.74033 | 0.129898 | Whether the file contains at least the default threshold of 50 text characters. |
| 5 | metadata size | 0.521561 | -0.105159 | Size of metadata extracted from the PDF file, in bytes. |
| 6 | images | 0.468498 | -0.100141 | Number of images in the PDF file. |
| 7 | obj | 0.387312 | -0.147125 | Number of occurrences of the string "obj" in the PDF file. |
| 8 | pages | 0.387037 | -0.152118 | Number of pages in the PDF file. |
| 9 | xref length | 0.384634 | -0.130088 | xref length as extracted from the file header. |
| 10 | pdf_ver | 0.311643 | -0.0508957 | PDF version extracted from the file header. |

## 5. Direction, class-conditional behavior, and errors

Feature-value/SHAP plots are descriptive because tree relationships can be non-monotonic. Higher values are not asserted to be universal malware rules.

| Feature | Benign mean |SHAP| | Malicious mean |SHAP| |
| --- | --- | --- |
| JavaScript | 1.9517 | 5.41752 |
| pdfsize | 1.13693 | 0.735363 |
| URI | 0.85086 | 0.797515 |
| contains_text | 0.595445 | 0.913082 |
| metadata size | 0.512655 | 0.532181 |
| images | 0.576072 | 0.340232 |
| obj | 0.430809 | 0.335448 |
| pages | 0.54564 | 0.19793 |
| xref length | 0.413635 | 0.350055 |
| pdf_ver | 0.326136 | 0.294362 |

### False Negative

Count: 102; average predicted malicious probability: 0.161679. Top aggregate model contributions:

| Feature | Mean |SHAP| | Mean SHAP | Feature mean |
| --- | --- | --- | --- |
| JavaScript | 2.11357 | -1.78707 | 0.0392157 |
| URI | 0.906261 | -0.0743757 | 3.64706 |
| contains_text | 0.589178 | -0.229041 | 0.862745 |
| pdfsize | 0.534872 | -0.303863 | 306.255 |
| Registry | 0.4245 | 0.235512 | 2.30392 |

### False Positive

Count: 10; average predicted malicious probability: 0.813367. Top aggregate model contributions:

| Feature | Mean |SHAP| | Mean SHAP | Feature mean |
| --- | --- | --- | --- |
| JavaScript | 4.07791 | 3.22088 | 1.9 |
| XFA | 0.986429 | 0.805256 | 0.5 |
| URI | 0.915571 | 0.0177352 | 3.2 |
| obj | 0.761939 | -0.670257 | 61.2 |
| contains_text | 0.627934 | 0.0383248 | 0.8 |

## 6. Paper comparison

Local top-ten overlap with the paper's published SHAP reference: JavaScript, pdfsize, URI, contains_text, metadata size, images, obj, pages, xref length, pdf_ver. This is descriptive only; differences can arise from Protocol G, seed/split, project configurations, and library versions.

## 7. Static-scanner implication

The top model-contribution features should receive early extraction-validation attention in the future static scanner. This does not reduce the deployment schema: the scanner must reproduce the complete 38-feature model input, preserving documented semantic values such as `contains_text=-1`, `pages=0`, and out-of-spec `pdf_ver` values.

## 8. Threats to validity and conclusion

TreeSHAP explains this retrained benchmark model on one saved test partition; it does not establish causality, temporal robustness, PDF-file disjointness, or deployment performance. No feature/model changes were made from these results.
