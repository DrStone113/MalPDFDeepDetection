# Static extractor RIT compatibility resolution

## Scope

This v2 report preserves the prior v1 coverage result and resolves only its ten Protocol G blockers using the released PDFMalExtract v0.1 implementation, not model performance or dataset-distribution matching. The source uses PyMuPDF, so this project pins the same upstream-tested PyMuPDF version for canonical RIT metadata extraction. pypdf remains a separate, read-only structural-diagnostics parser.

- PDFMalExtract source: [https://github.com/Mo-Alani/PDFMalExtract](https://github.com/Mo-Alani/PDFMalExtract), revision `1aaba0896ae395ddadbf1010ab9e887eedc38ea1`, `PDFMalExtract.py`.
- Runtime provenance: Python `3.11.0`, PyMuPDF `1.26.7` (required `1.26.7`).
- Safety: the implementation opens bytes in memory, never evaluates JavaScript, follows URIs, extracts attachment payloads, opens a viewer, invokes an external application, or runs ML inference.

## Before and after

| State | Verified | Provisional | Ambiguous | Unsupported | Protocol G schema gate |
| --- | ---: | ---: | ---: | ---: | --- |
| v1 baseline | 31 | 7 | 3 | 0 | 28 / 38 FAIL |
| v2 implementation | 41 | 0 | 0 | 0 | 38 / 38 PASS |

The PASS is a **schema-level** result: all 38 required feature definitions now have verified deterministic representations. Every actual input still passes the per-file gate only if all values are present, numeric, finite, and extracted without an incompatible failure state.

## Resolution table

| Feature | Previous status | Canonical measurement | Unit / representation | Evidence | Synthetic validation | Final status | Remaining limitation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pdfsize | AMBIGUOUS | int(file_size_bytes / 1000) | decimal kilobytes, truncated integer | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pdfsize_is_decimal_and_truncated_not_binary_kibibytes | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| metadata size | AMBIGUOUS | len(str(PyMuPDF Document.metadata).encode('utf-8')) | UTF-8 bytes | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_metadata_and_title_contracts_cover_absent_ascii_unicode_and_xmp | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| pages | IMPLEMENTED_PROVISIONAL | PyMuPDF Document.page_count | count | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pages_xref_images_and_attachments_use_reference_counts | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| xref length | AMBIGUOUS | PyMuPDF Document.xref_length() | PyMuPDF xref length count | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pages_xref_images_and_attachments_use_reference_counts | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| title length | IMPLEMENTED_PROVISIONAL | len(metadata['title']) if metadata['title'] else 0 | Python string characters | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_metadata_and_title_contracts_cover_absent_ascii_unicode_and_xmp | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| embedded files | IMPLEMENTED_PROVISIONAL | PyMuPDF Document.embfile_count() | attachment count | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pages_xref_images_and_attachments_use_reference_counts | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| images | IMPLEMENTED_PROVISIONAL | sum(len(page.get_images()) for every page) | per-page image-reference count | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pages_xref_images_and_attachments_use_reference_counts | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| contains_text | IMPLEMENTED_PROVISIONAL | aggregate page.get_text(); 1 iff accumulated length > 50, 0 otherwise, -1 only on released outer-loop failure | -1 / 0 / 1 | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_contains_text_distinguishes_threshold_and_failure_sentinel | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| pdf_ver | IMPLEMENTED_PROVISIONAL | float(metadata['format'][4:7]) | float | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_pdf_version_preserves_normal_unusual_and_malformed_states | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |
| ObjStm | IMPLEMENTED_PROVISIONAL | raw bytes.count(b'/ObjStm') | raw byte-substring count | Released PDFMalExtract v0.1 PDFMalExtract.py at 1aaba0896ae395ddadbf1010ab9e887eedc38ea1; uses PyMuPDF 1.26.7. | test_objstm_and_raw_counting_reproduce_pdfmalextract_overlap_rules | IMPLEMENTED_VERIFIED_SEMANTICS | None for source-defined normal representation. |

## Special-value contract

- `contains_text`: PDFMalExtract aggregates text and sets `1` only once length is strictly greater than 50; it sets `-1` only in its outer text/attachment exception path. A page-level text failure is recorded separately and does not automatically become `-1`.
- `images`: `-1` is used only for the released image-loop exception path. A generic pypdf failure is not converted to this sentinel.
- `pages`: a returned `0` from `Document.page_count` is a valid source value. Current extractor failures are `null` plus a structured issue, never silently `0`.
- `pdf_ver`: the exact source slice is parsed as a float. Out-of-spec values such as `5.0` are preserved; malformed/missing headers remain unavailable rather than normalized.

## Additional raw-counter correction

During source comparison, v1's token-boundary counters were corrected to the released raw `bytes.count` contract, including its overlap subtractions for `obj`, `stream`, `xref`, and `/Page`, and its literal `j/BaseEncoding` quirk. This affects an existing non-model-required constant feature but is documented and regression-tested rather than silently changed.

## Limitations and next step

The original RIT PDFs are still unavailable, so record-level equality cannot be demonstrated. The public source revision is the strongest available methodology evidence, but cannot prove it was the exact checkout used to build the local CSV. PyMuPDF behavior is version-sensitive, hence the exact pin and recorded runtime version. The source implementation's error-path sentinels are reproduced only where explicitly defined; no missing value is imputed. Feature compatibility is now satisfied, but this task performed no model loading, training, scoring, or prediction. A separately authorized next task may assess inference enablement.
