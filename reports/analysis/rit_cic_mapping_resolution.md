# RIT-to-CIC ambiguous feature mapping resolution

## Scope

This v2 review revisits every mapping that was AMBIGUOUS in the prior alignment using the RIT paper dictionary, CIC documentation, and observed local raw representations. It performs no data cleaning, target transformation, training, or cross-dataset evaluation.

## Source under review

- CIC file: `PDFMalware2022.parquet`; SHA-256: `25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65`; third-party mirror / Kaggle.
- This is not an automatic source switch. The separate source-fidelity audit records mirror limitations.

## Status counts

| Status | Prior | v2 |
| --- | --- | --- |
| EXACT | 6 | 6 |
| COMPATIBLE_AFTER_DOCUMENTED_TRANSFORM | 0 | 0 |
| AMBIGUOUS | 24 | 19 |
| NO_MATCH | 11 | 16 |

## Reclassified mappings

| RIT feature | CIC feature | Prior | v2 | Reason |
| --- | --- | --- | --- | --- |
| pdf_ver | Header | AMBIGUOUS | NO_MATCH | CIC documents Header as presence of a valid PDF header, while RIT pdf_ver is a numeric extracted version. Header validity/version-like strings are not a version measurement and no deterministic conversion is documented. |
| obj | Obj | AMBIGUOUS | NO_MATCH | CIC documents Obj as number of indirect objects, whereas RIT counts occurrences of the raw string obj. These are distinct parser-level quantities; similar names do not establish equality. |
| page_command | PageNo | AMBIGUOUS | NO_MATCH | RIT counts the /Page string. CIC PageNo is not described by CIC as a /Page-keyword count, so the local column is not a documented equivalent. |
| Encrypt | Encrypt | AMBIGUOUS | NO_MATCH | CIC documentation defines document encryption generally through isEncrypted, not the separate local Encrypt field as a /Encrypt occurrence count. Its distinct local semantics remain undocumented. |
| EmbeddedFile | EmbeddedFile | AMBIGUOUS | NO_MATCH | CIC documentation defines EmbeddedFiles as number of embedded files, but does not define the separate local EmbeddedFile field as a /EmbeddedFile occurrence count. |

## Common feature spaces

- COMMON_STRICT v2 (6): metadata_size, xref_length, title_length, embedded_files, trailer, objstm.
- COMMON_TRANSFORMABLE v2 (6): metadata_size, xref_length, title_length, embedded_files, trailer, objstm.
- No transform is listed unless it is deterministic, total over observed values, documented, target-independent, and explicit about information loss. None met that bar here.

## Training-readiness assessment

| Track | Readiness | Feature count | Features | Limitation |
| --- | --- | --- | --- | --- |
| S — STRICT | future design only | 6 | metadata_size, xref_length, title_length, embedded_files, trailer, objstm | A six-feature conservative baseline can be scientifically valid, but it is a limited representation of a full static PDF detector and requires separate source/protocol authorization. |
| T — TRANSFORMABLE | future design only | 6 | metadata_size, xref_length, title_length, embedded_files, trailer, objstm | No additional documented total deterministic transform survived this review, so Track T currently equals Track S. |
| A — AMBIGUOUS | not training-ready | 19 | pdfsize, pages, isEncrypted, images, contains_text, endobj, stream, endstream, xref, startxref, JS, JavaScript, AA, OpenAction, Acroform, JBIG2Decode, RichMedia, Launch, XFA | Ambiguous semantic mappings, units, sentinels, malformed raw tokens, or parser differences remain unresolved. They must not enter a common feature space. |

## Six-feature baseline caution

A future six-feature strict baseline can be scientifically valid because every included feature has a conservative documented alignment. It must be presented as a limited feature-space baseline, not as the full detector capability or an external-generalization conclusion.

## Remaining limitations

- This is a semantic/source audit, not a cross-dataset experiment; no model was fit or evaluated.
- Distribution similarity is not treated as evidence of semantic equivalence.
- Malformed or mixed CIC raw tokens are not cleaned, parsed heuristically, or encoded in this audit.
- No transform may use labels, fit data-dependent parameters, or discard unsupported raw values.
