# RIT-PDFMal-2026 dataset inspection

- Dataset filename: `rit-pdfmal-2026.csv`
- SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`
- Byte size: 2319735
- Generated (UTC): 2026-08-28T05:21:41.848540+00:00

## Dimensions

- Rows: 24337
- Columns: 42

## Schema (original column order)

| # | Column | dtype |
| --- | --- | --- |
| 1 | pdfsize | int64 |
| 2 | metadata size | int64 |
| 3 | pages | int64 |
| 4 | xref length | int64 |
| 5 | title length | int64 |
| 6 | isEncrypted | int64 |
| 7 | embedded files | int64 |
| 8 | images | int64 |
| 9 | contains_text | int64 |
| 10 | pdf_ver | float64 |
| 11 | obj | int64 |
| 12 | endobj | int64 |
| 13 | stream | int64 |
| 14 | endstream | int64 |
| 15 | trailer | int64 |
| 16 | xref | int64 |
| 17 | startxref | int64 |
| 18 | page_command | int64 |
| 19 | Encrypt | int64 |
| 20 | ObjStm | int64 |
| 21 | JS | int64 |
| 22 | JavaScript | int64 |
| 23 | AA | int64 |
| 24 | OpenAction | int64 |
| 25 | Acroform | int64 |
| 26 | JBIG2Decode | int64 |
| 27 | RichMedia | int64 |
| 28 | Launch | int64 |
| 29 | EmbeddedFile | int64 |
| 30 | XFA | int64 |
| 31 | Colors | int64 |
| 32 | URI | int64 |
| 33 | BaseEncoding | int64 |
| 34 | Encoding | int64 |
| 35 | ProcSet | int64 |
| 36 | Registry | int64 |
| 37 | Resources | int64 |
| 38 | www | int64 |
| 39 | server | int64 |
| 40 | Root | int64 |
| 41 | BitsPerComponent | int64 |
| 42 | Label | int64 |

## Candidate target / label

Selected candidate: `Label`

All columns are scored using actual header semantics, observed cardinality, and final-column position. Automatic selection requires an exact target-oriented header plus at least two observed values.

| Column | Score | Observed values | Evidence |
| --- | --- | --- | --- |
| Label | 111 | 2 | exact target-oriented header: label |
| isEncrypted | 10 | 2 | no target-oriented name signal |
| embedded files | 5 | 6 | no target-oriented name signal |
| contains_text | 5 | 3 | no target-oriented name signal |
| pdf_ver | 5 | 14 | no target-oriented name signal |
| Encrypt | 5 | 6 | no target-oriented name signal |
| OpenAction | 5 | 5 | no target-oriented name signal |
| RichMedia | 5 | 6 | no target-oriented name signal |
| Launch | 5 | 11 | no target-oriented name signal |
| EmbeddedFile | 5 | 13 | no target-oriented name signal |
| XFA | 5 | 3 | no target-oriented name signal |
| server | 5 | 11 | no target-oriented name signal |

### Target distribution

| Raw label value | Count | Percentage |
| --- | --- | --- |
| 0 | 13235 | 54.382216% |
| 1 | 11102 | 45.617784% |

## Missing-value analysis

Automatic text-to-NA parsing is disabled, so textual tokens remain visible and are reported separately from actual NaN values.

| Column | Actual NaN | Blank strings | Text placeholders | Observed missing |
| --- | --- | --- | --- | --- |
| pdfsize | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| metadata size | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| pages | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| xref length | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| title length | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| isEncrypted | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| embedded files | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| images | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| contains_text | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| pdf_ver | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| obj | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| endobj | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| stream | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| endstream | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| trailer | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| xref | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| startxref | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| page_command | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Encrypt | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| ObjStm | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| JS | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| JavaScript | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| AA | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| OpenAction | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Acroform | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| JBIG2Decode | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| RichMedia | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Launch | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| EmbeddedFile | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| XFA | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Colors | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| URI | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| BaseEncoding | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Encoding | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| ProcSet | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Registry | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Resources | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| www | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| server | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Root | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| BitsPerComponent | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |
| Label | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) | 0 (0.000000%) |

## Duplicate analysis

- Exact duplicate rows excluding the first occurrence: 8966
- Exact duplicate rows including the first occurrence: 9517
- Exact duplicate groups: 551
- Feature duplicate rows excluding the first (ignoring `Label`): 8966
- Feature duplicate groups with conflicting target values: 0

## Column quality

| Column | dtype | Unique values | Dominant value | Dominant percentage |
| --- | --- | --- | --- | --- |
| pdfsize | int64 | 3285 | 9 | 8.345318% |
| metadata size | int64 | 627 | 180 | 30.878909% |
| pages | int64 | 278 | 1 | 52.303078% |
| xref length | int64 | 2007 | 10 | 11.542096% |
| title length | int64 | 231 | 0 | 63.146649% |
| isEncrypted | int64 | 2 | 0 | 98.689239% |
| embedded files | int64 | 6 | 0 | 97.978387% |
| images | int64 | 504 | 0 | 57.665283% |
| contains_text | int64 | 3 | 1 | 55.380696% |
| pdf_ver | float64 | 14 | 1.3 | 28.581994% |
| obj | int64 | 1245 | 9 | 14.800510% |
| endobj | int64 | 1245 | 9 | 13.588363% |
| stream | int64 | 790 | 2 | 18.704031% |
| endstream | int64 | 790 | 2 | 18.630069% |
| trailer | int64 | 28 | 1 | 63.606854% |
| xref | int64 | 28 | 1 | 59.654025% |
| startxref | int64 | 30 | 1 | 64.440975% |
| page_command | int64 | 302 | 1 | 34.075687% |
| Encrypt | int64 | 6 | 0 | 98.668694% |
| ObjStm | int64 | 166 | 0 | 76.237827% |
| JS | int64 | 34 | 0 | 62.201586% |
| JavaScript | int64 | 22 | 0 | 63.524674% |
| AA | int64 | 76 | 0 | 90.409664% |
| OpenAction | int64 | 5 | 0 | 61.638657% |
| Acroform | int64 | 1 | 0 | 100.000000% |
| JBIG2Decode | int64 | 61 | 0 | 99.219296% |
| RichMedia | int64 | 6 | 0 | 99.926039% |
| Launch | int64 | 11 | 0 | 99.116571% |
| EmbeddedFile | int64 | 13 | 0 | 93.092822% |
| XFA | int64 | 3 | 0 | 94.880224% |
| Colors | int64 | 1 | 0 | 100.000000% |
| URI | int64 | 163 | 0 | 82.656038% |
| BaseEncoding | int64 | 1 | 0 | 100.000000% |
| Encoding | int64 | 172 | 0 | 50.112997% |
| ProcSet | int64 | 306 | 0 | 36.175371% |
| Registry | int64 | 57 | 0 | 71.968607% |
| Resources | int64 | 398 | 0 | 28.277931% |
| www | int64 | 198 | 0 | 55.910753% |
| server | int64 | 11 | 0 | 99.379546% |
| Root | int64 | 35 | 1 | 74.380573% |
| BitsPerComponent | int64 | 476 | 0 | 56.601060% |
| Label | int64 | 2 | 0 | 54.382216% |

- Constant columns: ['Acroform', 'Colors', 'BaseEncoding']
- Near-constant threshold: 99.5%
- Near-constant columns: [{'column': 'RichMedia', 'dominant_value': 0, 'dominant_value_count': 24319, 'dominant_value_percentage': 99.926039}]
- String/object columns: None
- Categorical-dtype columns: None
- Numeric columns: ['pdfsize', 'metadata size', 'pages', 'xref length', 'title length', 'isEncrypted', 'embedded files', 'images', 'contains_text', 'pdf_ver', 'obj', 'endobj', 'stream', 'endstream', 'trailer', 'xref', 'startxref', 'page_command', 'Encrypt', 'ObjStm', 'JS', 'JavaScript', 'AA', 'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia', 'Launch', 'EmbeddedFile', 'XFA', 'Colors', 'URI', 'BaseEncoding', 'Encoding', 'ProcSet', 'Registry', 'Resources', 'www', 'server', 'Root', 'BitsPerComponent', 'Label']

## Numeric sanity checks

| Column | Min | Max | Mean | Median | Std. dev. | Negative | Infinities | |x| > 1e12 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pdfsize | 0 | 468246 | 800.934 | 79 | 4772.3 | 0 | 0 | 0 |
| metadata size | 176 | 77185 | 319.701 | 267 | 1241.83 | 0 | 0 | 0 |
| pages | 0 | 2096 | 8.26486 | 1 | 36.6538 | 0 | 0 | 0 |
| xref length | 0 | 263987 | 2454.95 | 36 | 15756.8 | 0 | 0 | 0 |
| title length | 0 | 76993 | 45.2271 | 0 | 1072.77 | 0 | 0 | 0 |
| isEncrypted | 0 | 1 | 0.0131076 | 0 | 0.113738 | 0 | 0 | 0 |
| embedded files | 0 | 8 | 0.0217365 | 0 | 0.170987 | 0 | 0 | 0 |
| images | 0 | 98560 | 31.03 | 0 | 815.299 | 0 | 0 | 0 |
| contains_text | -1 | 1 | 0.552204 | 1 | 0.50049 | 39 | 0 | 0 |
| pdf_ver | 0 | 5 | 1.41616 | 1.4 | 0.30148 | 0 | 0 | 0 |
| obj | 0 | 72292 | 137.792 | 25 | 938.302 | 0 | 0 | 0 |
| endobj | 0 | 72291 | 138.445 | 25 | 946.494 | 0 | 0 | 0 |
| stream | 0 | 15182 | 54.272 | 9 | 306.753 | 0 | 0 | 0 |
| endstream | 0 | 15182 | 54.5259 | 9 | 309.665 | 0 | 0 | 0 |
| trailer | 0 | 91 | 1.16444 | 1 | 1.18872 | 0 | 0 | 0 |
| xref | 0 | 91 | 1.12524 | 1 | 1.20728 | 0 | 0 | 0 |
| startxref | 0 | 156 | 1.35534 | 1 | 1.55384 | 0 | 0 | 0 |
| page_command | 0 | 2789 | 9.68349 | 2 | 46.2332 | 0 | 0 | 0 |
| Encrypt | 0 | 11 | 0.0202161 | 0 | 0.197375 | 0 | 0 | 0 |
| ObjStm | 0 | 1294 | 2.36069 | 0 | 17.5157 | 0 | 0 | 0 |
| JS | 0 | 2469 | 0.637794 | 0 | 16.3721 | 0 | 0 | 0 |
| JavaScript | 0 | 2469 | 0.693635 | 0 | 16.3528 | 0 | 0 | 0 |
| AA | 0 | 3197 | 0.720302 | 0 | 21.1047 | 0 | 0 | 0 |
| OpenAction | 0 | 4 | 0.387147 | 0 | 0.495223 | 0 | 0 | 0 |
| Acroform | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| JBIG2Decode | 0 | 1310 | 0.2926 | 0 | 11.6079 | 0 | 0 | 0 |
| RichMedia | 0 | 32 | 0.00772486 | 0 | 0.36412 | 0 | 0 | 0 |
| Launch | 0 | 443 | 0.0397337 | 0 | 3.12091 | 0 | 0 | 0 |
| EmbeddedFile | 0 | 19 | 0.344989 | 0 | 1.53391 | 0 | 0 | 0 |
| XFA | 0 | 2 | 0.0557587 | 0 | 0.248544 | 0 | 0 | 0 |
| Colors | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| URI | 0 | 39112 | 7.69129 | 0 | 278.593 | 0 | 0 | 0 |
| BaseEncoding | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Encoding | 0 | 2769 | 4.93438 | 0 | 36.6928 | 0 | 0 | 0 |
| ProcSet | 0 | 7491 | 8.68895 | 1 | 67.1949 | 0 | 0 | 0 |
| Registry | 0 | 307 | 1.15154 | 0 | 4.60055 | 0 | 0 | 0 |
| Resources | 0 | 11142 | 15.2016 | 1 | 140.491 | 0 | 0 | 0 |
| www | 0 | 19775 | 4.87184 | 0 | 135.077 | 0 | 0 | 0 |
| server | 0 | 10 | 0.0294613 | 0 | 0.415723 | 0 | 0 | 0 |
| Root | 0 | 157 | 1.43202 | 1 | 1.90993 | 0 | 0 | 0 |
| BitsPerComponent | 0 | 10186 | 18.2765 | 0 | 177.31 | 0 | 0 | 0 |
| Label | 0 | 1 | 0.456178 | 0 | 0.498086 | 0 | 0 | 0 |

## Potential leakage indicators

- Target-related names outside the selected target: None
- Identifier-like columns: None
- Filename/path columns: None
- Source/collection metadata columns: None
- Exact target-match columns: None
- Strong univariate associations (threshold 0.95): None

## Assumptions and scope

- This is a read-only audit; the source CSV is never modified.
- No columns are dropped, imputed, encoded, normalized, or renamed.
- Near-constant means one value occupies at least 99.5% of rows.
- Extremely large means an absolute numeric value greater than 1e12.
- Negative values are flagged as unexpected by a conservative column-name heuristic; review them with dataset documentation.
- Leakage indicators are descriptive flags, not proof that a feature is invalid or should be removed.
