# RIT-PDFMal-2026 and CIC-Evasive-PDFMal2022 schema alignment

## Objective and scope

This is a read-only semantic/schema audit for a future RIT-trained to CIC-evaluated study. No classifier was trained and no cross-dataset performance was calculated.

## Dataset provenance and documentation

- RIT SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- CIC mirror SHA-256: `25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65`; source type/platform: third-party mirror / Kaggle.
- CIC official documentation reports 10,025 records, while the local mirror audit reports 10,023. The mirror is not claimed to be byte-identical to the official file.
- CIC documentation itself describes both 32 extracted features and 37 static representative features. The actual local 31-feature predictor schema is the implementation ground truth.

## Alignment method

Every RIT paper-dictionary feature is classified as EXACT, COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM, AMBIGUOUS, or NO_MATCH. Similar names alone are not treated as evidence: count versus presence, parser semantics, units, special values, and malformed local representations are considered.

## Alignment results

| Status | RIT feature count |
| --- | --- |
| EXACT | 6 |
| COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM | 0 |
| AMBIGUOUS | 24 |
| NO_MATCH | 11 |

### Common strict

Count: 6. These are in RIT paper-dictionary order and require no transform.

| Canonical | RIT column | CIC column | Reason |
| --- | --- | --- | --- |
| metadata_size | metadata size | MetadataSize | Both dictionaries describe metadata-section size; compatible numeric quantity, with CIC's observed -1 raw sentinel retained and separately audited. |
| xref_length | xref length | XrefLength | Both dictionaries describe the Xref length/entry quantity; local maxima and numeric representation are compatible evidence, while CIC -1 remains an unverified raw sentinel. |
| title_length | title length | TitleCharacters | Both dictionaries describe the number of title characters; compatible numeric character count, with CIC's raw -1 sentinel retained. |
| embedded_files | embedded files | EmbeddedFiles | Both dictionaries describe a count of embedded files and use a numeric local representation; no unit conversion is required. |
| trailer | trailer | Trailer | Both dictionaries describe a count of PDF trailers and use numeric local representations. |
| objstm | ObjStm | ObjStm | Both dictionaries describe stream objects (ObjStm) as a numeric count. |

### Common transformable

Count: 6. It contains exact mappings plus only reviewed deterministic transforms; no ambiguous feature is included.

| Canonical | RIT column | CIC column | Status |
| --- | --- | --- | --- |
| metadata_size | metadata size | MetadataSize | EXACT |
| xref_length | xref length | XrefLength | EXACT |
| title_length | title length | TitleCharacters | EXACT |
| embedded_files | embedded files | EmbeddedFiles | EXACT |
| trailer | trailer | Trailer | EXACT |
| objstm | ObjStm | ObjStm | EXACT |

### Transform specification

No COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM feature is included in this audit. The transform specification is intentionally empty rather than coercing malformed CIC categories or inferring units.

## Descriptive domain-shift evidence

Class balance is reported below and in `reports/tables/rit_cic_alignment/class_balance_comparison.csv`. Only COMMON_STRICT feature summaries are reported in `reports/tables/rit_cic_alignment/distribution_comparison.csv`; range and distribution similarities are descriptive and do not prove semantic equivalence.

| Dataset | Raw label | Canonical label | Count | Percentage |
| --- | --- | --- | --- | --- |
| RIT-PDFMal-2026 | 0 | 0 | 13235 | 54.3822 |
| RIT-PDFMal-2026 | 1 | 1 | 11102 | 45.6178 |
| CIC-Evasive-PDFMal2022 mirror | Benign | 0 | 4468 | 44.5775 |
| CIC-Evasive-PDFMal2022 mirror | Malicious | 1 | 5555 | 55.4225 |

## Important exclusions

CIC Text is not equated with RIT contains_text because the latter is a documented 50-character threshold signal. CIC Header is not converted to RIT pdf_ver. CIC Colors is not equated with RIT Colors because their documented meanings differ. CIC category columns containing values such as `1(1)`, `pdfid.py`, or `bytes[endHeader]` are not silently coerced.

## File-identity limitation

RIT's local CSV does not contain the original per-PDF hash field, so overlap of original PDF files between RIT and CIC cannot be established. Feature-vector similarity is not PDF-file identity.

## Conclusion

The strict common space is deliberately small. It is preferable to an artificial larger mapping that assumes categorical parsing, units, sentinels, or keyword-count equivalence not verified by the documentation. CV10 and Protocol G remain distinct prior evaluations; this audit makes no claim about cross-dataset generalization.
