# CIC-Evasive-PDFMal2022 source-fidelity audit

## Scope

This is a read-only comparison of local extracted tabular mirrors. No PDF was opened, no raw source was changed, and no model training or cross-dataset classification was performed.

## Documentary reference

The [CIC documentation](https://www.unb.ca/cic/datasets/pdfmal-2022.html) reports 10025 records: 5557 malicious and 4468 benign. It also states both 32 extracted and 37 representative static features; this inconsistency is retained rather than resolved by assumption.

## Source inventory

| File | Format | SHA-256 | Physical rows | Recognized labels | Benign | Malicious | Unexpected labels | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PDFMalware2022.csv | csv | 61686c9b323cb41bf8c048e5e4fe1e43eaf7d8d634667dc256a1349d6242b489 | 10026 | 10025 | 4468 | 5557 | {'nan': 1} | TRANSFORMED |
| PDFMalware2022.parquet | parquet | 25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65 | 10023 | 10023 | 4468 | 5555 | {} | TRANSFORMED |
- `PDFMalware2022.csv` has 1 unexpected-target physical row(s): 0 are all textual `nan` across fields and 0 actual NaN cell(s) occur in those rows. They were reported, not removed.

## Mirror-to-mirror evidence

- Normalized schema order equal: `True`; raw header order equal: `False`.
- Common identifier records: 10023; larger-only: 2 with labels {'Malicious': 2}; smaller-only: 0.
- Shared label mismatches: 0; shared records with at least one semantic feature difference: 893; strict record-wise subset: `False`.

## Fidelity interpretation

`FULL_COUNT_MATCH` would require a physical 10,025-row source with exactly the published benign/malicious totals and no unexpected label. `SUBSET_OR_TRUNCATED` captures a smaller clean source. `TRANSFORMED` records a physical/count/value-representation discrepancy. A match of counts alone never establishes official byte-level provenance.

## Recommendation

- Candidate: `PDFMalware2022.csv`; SHA-256: `61686c9b323cb41bf8c048e5e4fe1e43eaf7d8d634667dc256a1349d6242b489`.
- Provisional candidate only: its recognized label records match published class totals, but its physical source table has an unexpected raw-label row and third-party provenance remains unresolved. Do not switch automatically.

## Limitations

- All local copies are third-party mirrors; no byte-level official-source provenance was supplied.
- Identifier matching is performed only in memory and individual identifiers are never written to reports.
- Semantic value comparison normalizes only lexical numeric serialization (for example 1 and 1.0), not malformed tokens or category encodings.
- No raw source file, PDF, model, or training/evaluation pipeline was modified or executed.
