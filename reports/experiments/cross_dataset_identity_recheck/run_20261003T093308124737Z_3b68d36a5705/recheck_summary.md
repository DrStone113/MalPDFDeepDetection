# Identity and label recheck

The independent CSV dictionary join confirms the previous counts: 8,386 matching CIC identifiers and 3,727 conditional label disagreements. The source PDF byte checksums were reverified for 16 samples; no mismatch was found. Source-manifest, training-table and split labels agree exactly, and both domains use Label=1 malicious. No positional join or inverted class mapping was found.

All 8,386 matching source rows use `publisher_reported_malicious_not_independently_verified` provenance from the malware archive. Among the matching target identifiers, CIC labels 4,659 Malicious and 3,727 Benign. This does not establish that 3,727 files are mislabeled: CIC FileName checksum semantics and the actual target PDF bytes have not been verified. Neither label source has been adjudicated.

The completed v3 experiment used the 19,958-row raw public-PDF cohort; its reported 99.9259% accuracy concerns that cohort's 4,050-row locked Protocol G Test and archive-derived labels. It is not a cross-dataset metric or independent validation of the labels. Original results remain preserved with this limitation; no model, label, split or threshold was changed.

Cross-dataset inference remains blocked by missing target Vision input, incomplete feature compatibility, candidate identity overlap and unresolved label provenance.
