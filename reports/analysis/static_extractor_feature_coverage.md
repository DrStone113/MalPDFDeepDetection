# Static PDF extractor feature coverage

## Scope and safety

This is a **RIT-schema-oriented static extractor**, not a proven RIT-compatible feature generator and not an ML predictor. It reads local PDF bytes and parser dictionaries only. It never executes JavaScript or embedded files, follows URIs, opens a viewer, launches applications, extracts payloads, or invokes model inference.

The public local RIT CSV has no corresponding PDFs or per-PDF hashes. Therefore record-by-record equivalence with the original feature-generation pipeline cannot be measured. Raw lexical counts and parser-derived structural diagnostics are deliberately reported as different concepts.

## Coverage summary

- IMPLEMENTED_VERIFIED_SEMANTICS: 31 / 41
- IMPLEMENTED_PROVISIONAL: 7 / 41
- AMBIGUOUS: 3 / 41
- UNSUPPORTED: 0 / 41

## Protocol G G-drop3constant compatibility gate

- Expected model features: 38
- Exact-semantics numeric features currently compatible by implementation status: 28
- Gate result: **FAIL**
- This failure is intentional safety behavior: provisional or ambiguous mappings, missing values, non-numeric values, NaN, and infinity are never filled or coerced.
- Blocking required features: `pdfsize` (status is AMBIGUOUS), `metadata size` (status is AMBIGUOUS), `pages` (status is IMPLEMENTED_PROVISIONAL), `xref length` (status is AMBIGUOUS), `title length` (status is IMPLEMENTED_PROVISIONAL), `embedded files` (status is IMPLEMENTED_PROVISIONAL), `images` (status is IMPLEMENTED_PROVISIONAL), `contains_text` (status is IMPLEMENTED_PROVISIONAL), `pdf_ver` (status is IMPLEMENTED_PROVISIONAL), `ObjStm` (status is IMPLEMENTED_PROVISIONAL)

## Feature-by-feature coverage

| RIT feature | Meaning | Implementation | Status | Unit | Special-value handling | Protocol G used | Local SHAP rank | Limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pdfsize | Size of the PDF file in kilobytes. | exact byte size plus unassigned KiB candidate | AMBIGUOUS | bytes (candidate KiB diagnostic) | Not specified in the paper. | yes | 2 | Historical KB conversion is undocumented; canonical value is null. |
| metadata size | Size of metadata extracted from the PDF file, in bytes. | metadata presence/entry-count diagnostic only | AMBIGUOUS | unavailable | Not specified in the paper. | yes | 5 | Historical extracted-metadata byte representation is undocumented. |
| pages | Number of pages in the PDF file. | pypdf page-tree count | IMPLEMENTED_PROVISIONAL | count | 0 is documented as occurring in deliberately corrupted malicious PDFs. | yes | 8 | Parser differences and malformed-file behavior cannot be compared with original extractor. |
| xref length | xref length as extracted from the file header. | raw xref token diagnostic only | AMBIGUOUS | unavailable | Not specified in the paper. | yes | 9 | Paper does not define the header-derived xref-length algorithm. |
| title length | Number of characters in the file title. | pypdf /Title character length | IMPLEMENTED_PROVISIONAL | characters | Not specified in the paper. | yes | 18 | Metadata decoding/normalization may differ from the original extractor. |
| isEncrypted | 1 if the file is encrypted; 0 otherwise. | pypdf encryption flag without decryption | IMPLEMENTED_VERIFIED_SEMANTICS | 0/1 | Not specified in the paper. | yes | 34 | Passwords are never requested or attempted. |
| embedded files | Number of embedded files inside the PDF, as extracted from the header. | bounded parser traversal of /EF file-specification dictionaries | IMPLEMENTED_PROVISIONAL | count | Not specified in the paper. | yes | 29 | May differ from the paper's header-extraction method. |
| images | Number of images in the PDF file. | unique parser-derived /Image XObjects | IMPLEMENTED_PROVISIONAL | count | -1 means the file is corrupted and the number of images cannot be shown. | yes | 6 | No rendering/export; parser handling may differ from PDFMalExtract. |
| contains_text | Whether the file contains at least the default threshold of 50 text characters. | pypdf text length threshold of 50 characters | IMPLEMENTED_PROVISIONAL | -1/0/1 concept | 1: threshold met; 0: threshold not met; -1: corrupted file and text could not be read. | yes | 4 | Failures remain null, never mapped to RIT -1 without equivalence evidence. |
| pdf_ver | PDF version extracted from the file header. | literal %PDF- header numeric parse | IMPLEMENTED_PROVISIONAL | numeric version | The paper documents max 5 although the highest valid PDF version is 2.0; it attributes such invalid values to many malicious samples. Meaning of 0 is not explained. | yes | 10 | Unusual headers are retained; value 0 semantics remain unverified. |
| obj | Number of occurrences of the string "obj" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 7 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| endobj | Number of occurrences of the string "endobj" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 23 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| stream | Number of occurrences of the string "stream" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 16 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| endstream | Number of occurrences of the string "endstream" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 27 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| trailer | Number of occurrences of the string "trailer" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 30 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| xref | Number of occurrences of the string "xref" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 25 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| startxref | Number of occurrences of the string "startxref" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 31 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| page_command | Number of occurrences of the string "/Page" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 21 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Encrypt | Number of occurrences of the string "/Encrypt" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 35 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| ObjStm | Number of occurrences of the string "/ObJStm" in the PDF file. | token-aware raw /ObjStm count | IMPLEMENTED_PROVISIONAL | count | Not specified in the paper. | yes | 28 | Paper spells the token /ObJStm; standard PDF spelling is /ObjStm. |
| JS | Number of occurrences of the string "/JS" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 11 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| JavaScript | Number of occurrences of the string "/JavaScript" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 1 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| AA | Number of occurrences of the string "/AA" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 33 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| OpenAction | Number of occurrences of the string "/OpenAction" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 13 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Acroform | Number of occurrences of the string "/Acroform" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | no | unavailable | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| JBIG2Decode | Number of occurrences of the string "/JBIG2Decode" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 36 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| RichMedia | Number of occurrences of the string "/RichMedia" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 38 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Launch | Number of occurrences of the string "/Launch" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 37 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| EmbeddedFile | Number of occurrences of the string "/EmbeddedFile" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 24 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| XFA | Number of occurrences of the string "/XFA" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 15 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Colors | Number of occurrences of the string "/Colors > 2^24" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | no | unavailable | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| URI | Number of occurrences of the string "/URI" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 3 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| BaseEncoding | Number of occurrences of the string "/BaseEncoding" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | no | unavailable | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Encoding | Number of occurrences of the string "/Encoding" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 14 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| ProcSet | Number of occurrences of the string "/ProcSet" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 20 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Registry | Number of occurrences of the string "/Registry" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 12 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Resources | Number of occurrences of the string "/Resources" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 17 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| www | Number of occurrences of the string "/www" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 19 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| server | Number of occurrences of the string "/server" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 32 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| Root | Number of occurrences of the string "/Root" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 22 | A raw string occurrence is not asserted to be a parser-confirmed active action. |
| BitsPerComponent | Number of occurrences of the string "/BitsPerComponent" in the PDF file. | token-aware raw lexical count | IMPLEMENTED_VERIFIED_SEMANTICS | count | Not specified in the paper. | yes | 26 | A raw string occurrence is not asserted to be a parser-confirmed active action. |

## Threats to validity

- The original RIT raw PDFs and feature-extraction implementation are unavailable locally.
- pypdf behavior can differ from the original parser, especially for malformed/encrypted PDFs.
- Static inspection cannot observe runtime behavior and does not validate live malware samples.
- Parser failure is represented separately from RIT sentinels such as `contains_text=-1`, `images=-1`, and `pages=0`; no value is cleaned, clipped, replaced, or imputed.
