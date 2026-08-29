# RIT-PDFMal-2026 paper-alignment audit

Paper: [RIT-PDFMal-2026: A Comprehensive Benchmark Dataset for PDF Malware Detection](https://www.researchgate.net/publication/408100426_RIT-PDFMal-2026_A_Comprehensive_Benchmark_Dataset_for_PDF_Malware_Detection)
DOI: `10.1109/ACCESS.2026.3707213`

## 1. Dataset identity

- Local filename: `rit-pdfmal-2026.csv`
- Local CSV SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`
- Local shape: 24337 rows × 42 columns
- Local predictive features: 41; target: `Label`
- Local class distribution: [{'raw_label': 0, 'count': 13235, 'percentage': 54.382216}, {'raw_label': 1, 'count': 11102, 'percentage': 45.617784}]
- Paper row comparison: exact match; class-count comparison: exact match.
- Schema comparison: aligned after excluding paper hash. The paper's `hash` field is absent locally; all 41 named non-hash predictive features align.

### PDF hashes versus feature vectors

The paper's hash field is the SHA-256 of a PDF file, retained to identify repetitions of the same file under different names and removed before ML.

No paper-style per-PDF hash column is present, so raw PDF identity or duplicate-PDF status cannot be verified locally.

```text
{
  "unique_static_feature_vectors": 15371,
  "groups_with_identical_static_feature_vectors": 551,
  "rows_in_multirow_feature_groups": 9517,
  "additional_rows_beyond_first_per_feature_vector": 8966,
  "groups_with_multiple_target_labels": 0,
  "terminology": "These are identical 41-dimensional static feature vectors in this CSV. They are not asserted to be duplicate PDF files because this local CSV has no per-PDF SHA-256 hash column."
}
```

## 2. Feature dictionary

| Column | Paper meaning | Expected type | Special values | Stated higher/lower meaning |
| --- | --- | --- | --- | --- |
| pdfsize | Size of the PDF file in kilobytes. | Non-negative numeric size (kilobytes). | Not specified in the paper. | Paper SHAP discussion: lower size pushed toward malicious; larger size toward benign. |
| metadata size | Size of metadata extracted from the PDF file, in bytes. | Non-negative integer-like size (bytes). | Not specified in the paper. | Not stated in the paper. |
| pages | Number of pages in the PDF file. | Non-negative integer count. | 0 is documented as occurring in deliberately corrupted malicious PDFs. | Paper SHAP discussion says a similar lower-versus-higher pattern to pdfsize applies. |
| xref length | xref length as extracted from the file header. | Non-negative integer-like length. | Not specified in the paper. | Not stated in the paper. |
| title length | Number of characters in the file title. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| isEncrypted | 1 if the file is encrypted; 0 otherwise. | Binary integer (0 or 1). | Not specified in the paper. | Not stated in the paper. |
| embedded files | Number of embedded files inside the PDF, as extracted from the header. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| images | Number of images in the PDF file. | Integer count; normally non-negative. | -1 means the file is corrupted and the number of images cannot be shown. | Not stated in the paper. |
| contains_text | Whether the file contains at least the default threshold of 50 text characters. | Ternary integer signal (-1, 0, 1). | 1: threshold met; 0: threshold not met; -1: corrupted file and text could not be read. | Paper SHAP discussion: 0 pushed toward malicious; >=50 characters (1) pushed toward benign. |
| pdf_ver | PDF version extracted from the file header. | Numeric version value. | The paper documents max 5 although the highest valid PDF version is 2.0; it attributes such invalid values to many malicious samples. Meaning of 0 is not explained. | Not stated in the paper. |
| obj | Number of occurrences of the string "obj" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| endobj | Number of occurrences of the string "endobj" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| stream | Number of occurrences of the string "stream" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| endstream | Number of occurrences of the string "endstream" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| trailer | Number of occurrences of the string "trailer" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| xref | Number of occurrences of the string "xref" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| startxref | Number of occurrences of the string "startxref" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| page_command | Number of occurrences of the string "/Page" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Encrypt | Number of occurrences of the string "/Encrypt" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| ObjStm | Number of occurrences of the string "/ObJStm" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| JS | Number of occurrences of the string "/JS" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Paper SHAP discussion: higher occurrences pushed toward malicious; lower occurrences toward benign. |
| JavaScript | Number of occurrences of the string "/JavaScript" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Paper SHAP discussion: higher occurrences pushed toward malicious; lower occurrences toward benign. |
| AA | Number of occurrences of the string "/AA" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| OpenAction | Number of occurrences of the string "/OpenAction" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Acroform | Number of occurrences of the string "/Acroform" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| JBIG2Decode | Number of occurrences of the string "/JBIG2Decode" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| RichMedia | Number of occurrences of the string "/RichMedia" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Launch | Number of occurrences of the string "/Launch" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| EmbeddedFile | Number of occurrences of the string "/EmbeddedFile" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| XFA | Number of occurrences of the string "/XFA" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Paper SHAP discussion relates this feature to JavaScript/JS; /XFA can embed scripts in XML Forms Architecture. |
| Colors | Number of occurrences of the string "/Colors > 2^24" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| URI | Number of occurrences of the string "/URI" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Paper SHAP discussion says the number of URI occurrences is considered an indication of maliciousness by the classifier. |
| BaseEncoding | Number of occurrences of the string "/BaseEncoding" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Encoding | Number of occurrences of the string "/Encoding" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| ProcSet | Number of occurrences of the string "/ProcSet" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Registry | Number of occurrences of the string "/Registry" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Resources | Number of occurrences of the string "/Resources" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| www | Number of occurrences of the string "/www" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| server | Number of occurrences of the string "/server" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| Root | Number of occurrences of the string "/Root" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |
| BitsPerComponent | Number of occurrences of the string "/BitsPerComponent" in the PDF file. | Non-negative integer count. | Not specified in the paper. | Not stated in the paper. |

Target `Label`: Binary class label for the entry. (0 denotes benign and 1 denotes malicious.)

## 3. Special-value semantics

### `contains_text`

- Local: `{'local_counts': {'-1': 39, '0': 10820, '1': 13478}, 'label_distribution_for_negative_one': {'0': 39}, 'paper_interpretation': '-1 is an intentional PDFMalExtract signal: corrupted file and text could not be read; 0/1 represent failure/success of the default 50-character threshold.', 'alignment': 'Local -1 values are retained as documented signals; they are not treated as missing data.'}`

### `images`

- Local: `{'local_negative_one_count': 0, 'paper_interpretation': '-1 is an intentional PDFMalExtract signal: corrupted file and the image count could not be shown.', 'alignment': 'No local images=-1 observations were found; no values are changed.'}`

### `pages`

- Local: `{'local_zero_count': 986, 'label_distribution_for_zero': {'0': 13, '1': 973}, 'paper_interpretation': '0 pages is documented in deliberately corrupted malicious PDFs.', 'alignment': 'Local zero-page observations are retained as documented signals; they are not treated as missing data.'}`

### `pdf_ver`

- Local: `{'local_minimum': 0.0, 'local_maximum': 5.0, 'local_greater_than_2_count': 75, 'label_distribution_for_greater_than_2': {'0': 39, '1': 36}, 'local_zero_count': 516, 'paper_interpretation': 'The paper states that values up to 5 occur, 2.0 is the highest valid PDF version, and many malicious samples use invalid version values. It does not explain the meaning of value 0.', 'alignment': 'Values above 2 are retained as documented potentially malicious invalid-version signals. Value 0 remains unverified rather than cleaned or imputed.'}`

## 4. Descriptive-statistics comparison

Table 3 publishes mean, variance, minimum, and maximum. Standard deviation is derived here as sqrt(published variance); its status is judged against the published variance rounded to two decimals.

| Feature | Δ min | Δ max | Δ mean | Δ std | Classification |
| --- | --- | --- | --- | --- | --- |
| pdfsize | 0 | 0 | 0.00421539 | -2.23875e-07 | rounding-level difference |
| metadata size | 0 | 0 | 0.00103135 | 1.26375e-06 | rounding-level difference |
| pages | 0 | 0 | 0.0048642 | 5.30743e-05 | rounding-level difference |
| xref length | 0 | 0 | -0.00222501 | 1.61453e-08 | rounding-level difference |
| title length | 0 | 0 | -0.00293832 | -1.6521e-06 | rounding-level difference |
| isEncrypted | 0 | 0 | 0.00310761 | 0.013738 | rounding-level difference |
| embedded files | 0 | 0 | 0.00173645 | -0.002218 | rounding-level difference |
| images | 0 | 0 | -4.51987e-06 | -1.61021e-06 | rounding-level difference |
| contains_text | 0 | 0 | 0.00220446 | 0.000489743 | rounding-level difference |
| pdf_ver | 0 | 0 | -0.00384353 | 0.00148025 | rounding-level difference |
| obj | 0 | 0 | 0.00204503 | 6.28433e-07 | rounding-level difference |
| endobj | 0 | 0 | 0.00483708 | 2.40241e-06 | rounding-level difference |
| stream | 0 | 0 | 0.00201381 | 4.78414e-06 | rounding-level difference |
| endstream | 0 | 0 | -0.00413403 | -6.23359e-06 | rounding-level difference |
| trailer | 0 | 0 | 0.00444097 | 0.00128225 | rounding-level difference |
| xref | 0 | 0 | -0.0047586 | -0.00102569 | rounding-level difference |
| startxref | 0 | 0 | -0.00465628 | 0.00141847 | rounding-level difference |
| page_command | 0 | 0 | 0.00348605 | -2.68711e-05 | rounding-level difference |
| Encrypt | 0 | 0 | 0.000216132 | -0.00262513 | rounding-level difference |
| ObjStm | 0 | 0 | 0.000685376 | 4.11762e-05 | rounding-level difference |
| JS | 0 | 0 | -0.0022057 | -0.000148887 | rounding-level difference |
| JavaScript | 0 | 0 | 0.00363521 | 7.53645e-05 | rounding-level difference |
| AA | 0 | 0 | 0.00030242 | -6.48497e-06 | rounding-level difference |
| OpenAction | 0 | 0 | -0.00285286 | -0.00477711 | rounding-level difference |
| Acroform | 0 | 0 | 0 | 0 | exact match |
| JBIG2Decode | 0 | 0 | 0.00259975 | 0.00011108 | rounding-level difference |
| RichMedia | 0 | 0 | -0.00227514 | 0.0035648 | rounding-level difference |
| Launch | 0 | 0 | -0.000266261 | 1.27549e-05 | rounding-level difference |
| EmbeddedFile | 0 | 0 | 0.00498911 | 0.000936168 | rounding-level difference |
| XFA | 0 | 0 | -0.00424128 | 0.00359506 | rounding-level difference |
| Colors | 0 | 0 | 0 | 0 | exact match |
| URI | 0 | 0 | 0.00129309 | 4.38985e-06 | rounding-level difference |
| BaseEncoding | 0 | 0 | 0 | 0 | exact match |
| Encoding | 0 | 0 | 0.00437975 | 1.7495e-05 | rounding-level difference |
| ProcSet | 0 | 0 | -0.00104902 | -3.18026e-06 | rounding-level difference |
| Registry | 0 | 0 | 0.00153881 | -0.000535857 | rounding-level difference |
| Resources | 0 | 0 | 0.00162715 | 9.58404e-06 | rounding-level difference |
| www | 0 | 0 | 0.00184123 | -2.21573e-06 | rounding-level difference |
| server | 0 | 0 | -0.000538686 | 0.00341205 | rounding-level difference |
| Root | 0 | 0 | 0.00201709 | -0.000566048 | rounding-level difference |
| BitsPerComponent | 0 | 0 | -0.00354851 | 1.37792e-05 | rounding-level difference |

## 5. Zero-variance features

| Feature | Local values | Status | Author treatment |
| --- | --- | --- | --- |
| Acroform | [0] | exact match | Safe to remove prior to training; the paper does not explicitly state whether Table 5 retained or removed it in every fitted pipeline. |
| Colors | [0] | exact match | Safe to remove prior to training; the paper does not explicitly state whether Table 5 retained or removed it in every fitted pipeline. |
| BaseEncoding | [0] | exact match | Safe to remove prior to training; the paper does not explicitly state whether Table 5 retained or removed it in every fitted pipeline. |

## 6. Published experimental protocol

- **train test split:** Random 75% train / 25% test split with stratification.
- **randomization details:** Random split is stated; random seed is not specified.
- **cross validation:** Best classifier (XGB) underwent random 10-fold cross-validation; stratification for cross-validation is not specified.
- **models evaluated:** ['Random Forest', 'Logistic Regression', 'Decision Tree', 'Gaussian Naive-Bayes', 'eXtreme Gradient Boost']
- **metrics:** ['Accuracy', 'Precision', 'Recall', 'F1 score', 'single-sample inference time']
- **additional analysis:** ROC-AUC is shown graphically; SHAP is calculated for the best-performing model.
- **feature preprocessing:** Features were extracted in numeric format to minimize preprocessing. The per-PDF hash should be removed before ML. Scaling, imputation, encoding, and normalization details are not specified.
- **feature removal:** Acroform, Colors, and BaseEncoding are stated to be safe to remove before training because they have zero variance. Whether they were removed from every reported fit is not explicitly specified.
- **hyperparameters:** Not specified in the paper.

## 7. Published baseline results

| Model | Accuracy | Precision | Recall | F1 | Inference ms |
| --- | --- | --- | --- | --- | --- |
| RF | 0.994084 | 0.994512 | 0.993603 | 0.994033 | 3.92386 |
| LR | 0.907313 | 0.906484 | 0.909382 | 0.907021 | 0.064845 |
| DT | 0.988661 | 0.988427 | 0.988733 | 0.988577 | 0.070683 |
| GNB | 0.621857 | 0.753729 | 0.651035 | 0.590655 | 0.185132 |
| XGB | 0.994906 | 0.995156 | 0.99459 | 0.994863 | 0.564525 |

XGB 10-fold CV mean: {"accuracy": 0.993878, "precision": 0.995663, "recall": 0.990901, "f1": 0.993274}

## 8. SHAP reference importance

Reference only for future sanity checks. Do not select features using these test-set-derived importances.

| Feature | Importance |
| --- | --- |
| JavaScript | 3.47479 |
| contains_text | 1.22153 |
| pdfsize | 1.12653 |
| JS | 1.12628 |
| Registry | 0.636202 |
| XFA | 0.550923 |
| metadata size | 0.503341 |
| stream | 0.441044 |
| URI | 0.377808 |
| pages | 0.375392 |
| xref length | 0.364602 |
| endobj | 0.363546 |
| www | 0.356451 |
| OpenAction | 0.318886 |
| Resources | 0.290378 |
| Encoding | 0.285145 |
| pdf_ver | 0.276523 |
| obj | 0.250006 |
| images | 0.246687 |
| page_command | 0.216136 |
| ProcSet | 0.192889 |
| title length | 0.189564 |
| endstream | 0.183275 |
| BitsPerComponent | 0.148386 |
| EmbeddedFile | 0.131712 |
| ObjStm | 0.083332 |
| Root | 0.075597 |
| trailer | 0.052374 |
| embedded files | 0.051439 |
| startxref | 0.044565 |
| xref | 0.033615 |
| Launch | 0.030032 |
| AA | 0.025128 |
| server | 0.018971 |
| isEncrypted | 0 |
| Acroform | 0 |
| Encrypt | 0 |
| BaseEncoding | 0 |
| Colors | 0 |
| RichMedia | 0 |
| JBIG2Decode | 0 |

## 9. Evaluation protocols

### Protocol P — Paper reproduction

Reproduce the paper as closely as documentation permits: 75/25 random stratified train/test split, five published classical models, the reported metrics, and random 10-fold XGB cross-validation. Undocumented seed, hyperparameters, scaling, and exact zero-variance removal status remain not specified.

### Protocol G — Feature-disjoint generalization

Use the existing deterministic seed-42 duplicate-feature-group-aware 60/20/20 train/validation/test manifest. Identical 41-dimensional feature representations cannot cross partitions.

Protocol G is stricter and has a validation partition; it is not directly equivalent to the paper's reported random 75/25 evaluation and must not be compared numerically as a direct reproduction.

## Terminology corrections

- Call the local CSV checksum a dataset-file SHA-256, not a PDF-file hash.
- Call equal rows after excluding Label identical static feature vectors or duplicate feature groups, not duplicate PDF files.
- The project's duplicate_group_id is a hash of static feature values, not the paper's SHA-256 hash of PDF bytes.

## Risks before training

- The local CSV lacks per-PDF hashes, so raw-file identity and duplicate-PDF claims cannot be checked.
- Protocol P cannot be exactly replicated until the paper's random seed, hyperparameters, and preprocessing details are available.
- Protocol G contains a very large static-feature duplicate group; group-aware splitting is necessary and results are not directly comparable to the paper protocol.
- Special corruption signals (-1 and zero-page cases) are documented values, not missing values; changing them would break paper alignment.

## Scope

Read-only paper-alignment audit. No raw data modification, model training, feature selection, normalization, encoding, imputation, or split change was performed.
