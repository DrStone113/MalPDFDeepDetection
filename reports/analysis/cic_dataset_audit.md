# CIC-Evasive-PDFMal2022 local mirror audit

## Scope and provenance

- Read-only audit of an extracted tabular feature table; no PDF was opened, executed, downloaded, or rendered.
- Source type: third-party mirror; source platform: Kaggle.
- The local file is not claimed to be an official CIC file or byte-identical to the original.
- Filename: `PDFMalware2022.parquet`; relative path: `data\external\cic_evasive_pdfmal2022\PDFMalware2022.parquet`.
- SHA-256: `25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65`; byte size: 885132.
- Actual shape: 10023 rows x 33 columns.

## Official identity comparison

The [official CIC page](https://www.unb.ca/cic/datasets/pdfmal-2022.html) reports 10,025 records: 5,557 malicious and 4,468 benign. The local mirror has 10023 rows, 5555 malicious, and 4468 benign: differences are {'total_records': -2, 'malicious': -2, 'benign': 0}. This is a material mirror discrepancy and must be resolved or explicitly accepted before any cross-dataset benchmark.

The official page also says both 32 extracted features and 37 static representative features in different sections. The actual local schema is therefore the implementation ground truth; it has one identifier, one target, and 31 candidate predictive features.

## Schema and target

| # | Column | dtype | Role |
| --- | --- | --- | --- |
| 1 | FileName | category | identifier |
| 2 | PdfSize | float32 | candidate_predictive_feature |
| 3 | MetadataSize | float32 | candidate_predictive_feature |
| 4 | Pages | float32 | candidate_predictive_feature |
| 5 | XrefLength | float32 | candidate_predictive_feature |
| 6 | TitleCharacters | float32 | candidate_predictive_feature |
| 7 | isEncrypted | float32 | candidate_predictive_feature |
| 8 | EmbeddedFiles | float32 | candidate_predictive_feature |
| 9 | Images | category | candidate_predictive_feature |
| 10 | Text | category | candidate_predictive_feature |
| 11 | Header | category | candidate_predictive_feature |
| 12 | Obj | category | candidate_predictive_feature |
| 13 | Endobj | category | candidate_predictive_feature |
| 14 | Stream | float32 | candidate_predictive_feature |
| 15 | Endstream | category | candidate_predictive_feature |
| 16 | Xref | category | candidate_predictive_feature |
| 17 | Trailer | float32 | candidate_predictive_feature |
| 18 | StartXref | category | candidate_predictive_feature |
| 19 | PageNo | category | candidate_predictive_feature |
| 20 | Encrypt | float32 | candidate_predictive_feature |
| 21 | ObjStm | float32 | candidate_predictive_feature |
| 22 | JS | category | candidate_predictive_feature |
| 23 | Javascript | category | candidate_predictive_feature |
| 24 | AA | category | candidate_predictive_feature |
| 25 | OpenAction | category | candidate_predictive_feature |
| 26 | Acroform | category | candidate_predictive_feature |
| 27 | JBIG2Decode | category | candidate_predictive_feature |
| 28 | RichMedia | category | candidate_predictive_feature |
| 29 | Launch | category | candidate_predictive_feature |
| 30 | EmbeddedFile | category | candidate_predictive_feature |
| 31 | XFA | category | candidate_predictive_feature |
| 32 | Colors | float32 | candidate_predictive_feature |
| 33 | Class | category | target |

Target selected from actual schema: `Class`.

| Raw label | Count | Percentage |
| --- | --- | --- |
| Benign | 4468 | 44.577472% |
| Malicious | 5555 | 55.422528% |

Proposed documentation-only canonical mapping: `{'Benign': 0, 'Malicious': 1}`; valid: `True`. No label was transformed.

## Data quality

| Column | NaN | Blank | Placeholders | Negative | Zero fraction | Constant | Near-constant |
| --- | --- | --- | --- | --- | --- | --- | --- |
| FileName | 0 | 0 | 0 | 0 | - | False | False |
| PdfSize | 0 | 0 | 0 | 302 | 0.000698 | False | False |
| MetadataSize | 0 | 0 | 0 | 302 | 0 | False | False |
| Pages | 0 | 0 | 0 | 302 | 0.036416 | False | False |
| XrefLength | 0 | 0 | 0 | 302 | 0.0001 | False | False |
| TitleCharacters | 0 | 0 | 0 | 302 | 0.587648 | False | False |
| isEncrypted | 0 | 0 | 0 | 302 | 0.961788 | False | False |
| EmbeddedFiles | 0 | 0 | 0 | 302 | 0.949317 | False | False |
| Images | 0 | 0 | 0 | 851 | 0.644382 | False | False |
| Text | 0 | 0 | 0 | 302 | 0.04127 | False | False |
| Header | 0 | 0 | 0 | 14 | 0.444444 | False | False |
| Obj | 0 | 0 | 0 | 770 | 0.005201 | False | False |
| Endobj | 0 | 0 | 0 | 514 | 0.027797 | False | False |
| Stream | 0 | 0 | 0 | 541 | 0.008281 | False | False |
| Endstream | 0 | 0 | 0 | 519 | 0.0118 | False | False |
| Xref | 0 | 0 | 0 | 519 | 0.19668 | False | False |
| Trailer | 0 | 0 | 0 | 541 | 0.117829 | False | False |
| StartXref | 0 | 0 | 0 | 519 | 0.062894 | False | False |
| PageNo | 0 | 0 | 0 | 519 | 0.063018 | False | False |
| Encrypt | 0 | 0 | 0 | 541 | 0.937045 | False | False |
| ObjStm | 0 | 0 | 0 | 541 | 0.766537 | False | False |
| JS | 0 | 0 | 0 | 541 | 0.531346 | False | False |
| Javascript | 0 | 0 | 0 | 541 | 0.514638 | False | False |
| AA | 0 | 0 | 0 | 554 | 0.895594 | False | False |
| OpenAction | 0 | 0 | 0 | 554 | 0.643483 | False | False |
| Acroform | 0 | 0 | 0 | 554 | 0.642557 | False | False |
| JBIG2Decode | 0 | 0 | 0 | 554 | 0.930418 | False | False |
| RichMedia | 0 | 0 | 0 | 554 | 0.939914 | False | False |
| Launch | 0 | 0 | 0 | 554 | 0.932688 | False | False |
| EmbeddedFile | 0 | 0 | 0 | 554 | 0.865265 | False | False |
| XFA | 0 | 0 | 0 | 554 | 0.895031 | False | False |
| Colors | 0 | 0 | 0 | 564 | 0.862416 | False | False |
| Class | 0 | 0 | 0 | 0 | - | False | False |

- Native numeric columns: PdfSize, MetadataSize, Pages, XrefLength, TitleCharacters, isEncrypted, EmbeddedFiles, Stream, Trailer, Encrypt, ObjStm, Colors.
- Text/object/categorical columns: FileName, Images, Text, Header, Obj, Endobj, Endstream, Xref, StartXref, PageNo, JS, Javascript, AA, OpenAction, Acroform, JBIG2Decode, RichMedia, Launch, EmbeddedFile, XFA, Class.
- Constant columns: none; near-constant columns: none.

- Exact duplicate rows excluding first: 0.
- Duplicate predictive vectors excluding first: 0.
- Predictive-vector groups with conflicting labels: 0.
- Identical feature vectors are not called duplicate PDF files; no original-file identity is proven here.

## String and malformed-value audit

| Column | Lexical numeric values | Malformed/non-numeric examples |
| --- | --- | --- |
| Images | 10022 | [{'value': '1(1)', 'count': 1}] |
| Text | 315 | [{'value': 'No', 'count': 5398}, {'value': 'Yes', 'count': 3761}, {'value': 'unclear', 'count': 549}] |
| Header | 27 | [{'value': '\t%PDF-1.3', 'count': 2347}, {'value': '\t%PDF-1.4', 'count': 1911}, {'value': '\t%PDF-1.7', 'count': 1604}, {'value': '\t%PDF-1.6', 'count': 1190}, {'value': '\t%PDF-1.2', 'count': 688}, {'value': '\t%PDF-1.5', 'count': 536}, {'value': '\ta', 'count': 484}, {'value': '\t%PDF-1.0', 'count': 331}, {'value': '\t%PDF-\\x07.3', 'count': 232}, {'value': '\t%PDF-1.1', 'count': 223}, {'value': '\t%PDF-1.3"', 'count': 66}, {'value': '\t%PDF-1.6"', 'count': 61}, {'value': '\t%PDF-1.5"', 'count': 38}, {'value': '\t%PDF-1.4"', 'count': 36}, {'value': '\t%PDF-\\\\\\\\x07', 'count': 33}, {'value': '\t%PDF-1.1"', 'count': 33}, {'value': '\t%PDF-1.', 'count': 29}, {'value': '\t%PDF-11113', 'count': 28}, {'value': '\toccured***', 'count': 22}, {'value': '\t2]', 'count': 17}] |
| Obj | 9999 | [{'value': '(most', 'count': 22}, {'value': '_Pro_Rodeo_Pix_', 'count': 1}, {'value': "_Pro_Rodeo_Pix_'", 'count': 1}] |
| Endobj | 10001 | [{'value': 'pdfid.py', 'count': 22}] |
| Endstream | 10000 | [{'value': 'pdfHeader)', 'count': 22}, {'value': '1(1)', 'count': 1}] |
| Xref | 10001 | [{'value': 'pdfid.py', 'count': 22}] |
| StartXref | 10001 | [{'value': 'bytes[endHeader]', 'count': 22}] |
| PageNo | 9886 | [{'value': '1(1)', 'count': 104}, {'value': 'list', 'count': 22}, {'value': '2(1)', 'count': 5}, {'value': '2(2)', 'count': 4}, {'value': '53(2)', 'count': 1}, {'value': '5(1)', 'count': 1}] |
| JS | 9794 | [{'value': '1(1)', 'count': 226}, {'value': '2(2)', 'count': 2}, {'value': '29(2)', 'count': 1}] |
| Javascript | 9906 | [{'value': '1(1)', 'count': 79}, {'value': '2(1)', 'count': 21}, {'value': '>', 'count': 13}, {'value': '3(1)', 'count': 2}, {'value': '34(2)', 'count': 1}, {'value': '2(2)', 'count': 1}] |
| AA | 10009 | [{'value': '1(1)', 'count': 14}] |
| OpenAction | 9935 | [{'value': '1(1)', 'count': 87}, {'value': '12(2)', 'count': 1}] |
| Acroform | 10010 | [{'value': '1(1)', 'count': 13}] |
| JBIG2Decode | 10017 | [{'value': '1(1)', 'count': 6}] |
| RichMedia | 10019 | [{'value': '1(1)', 'count': 3}, {'value': '2(2)', 'count': 1}] |
| Launch | 10013 | [{'value': '1(1)', 'count': 10}] |
| EmbeddedFile | 9990 | [{'value': '1(1)', 'count': 32}, {'value': '12(2)', 'count': 1}] |
| XFA | 10003 | [{'value': '1(1)', 'count': 20}] |

## Identifier and feature dictionary

- `FileName` is identifier-like: it contains unique hash-like strings and is excluded from the candidate predictive-feature list.
- The full per-column profile and CIC feature dictionary are stored in the accompanying CSV and JSON metadata. Meanings not explicitly documented by the official page are marked unverified.

## Training-readiness conclusion

No model training, label encoding, numeric coercion, imputation, normalization, outlier removal, feature selection, or cross-dataset evaluation was performed. The mirror row/class-count discrepancy and malformed categorical representations require documented review before any future training or evaluation.
