# STRICT6 cross-dataset threats to validity

This template accompanies a future RIT-PDFMal-2026 to CIC-Evasive-PDFMal2022 STRICT6 result. It is not a result report and contains no benchmark metrics.

- The selected CIC CSV is a transformed third-party mirror, not a publisher-byte-verified original.
- One physical pseudo-row is excluded only because its raw target is not explicitly `Benign` or `Malicious`; no other source rows are cleaned or dropped.
- The common model space contains only six documented strict matches: `metadata_size`, `xref_length`, `title_length`, `embedded_files`, `trailer`, and `objstm`.
- Six features do not represent the full RIT static detector capability.
- Local CIC mirrors have semantic differences; each STRICT6 feature must pass the mirror-stability preflight before any model is fitted.
- Original-PDF identity overlap between RIT and CIC cannot be verified because the local RIT table has no per-file SHA-256 field. The datasets are not claimed file-disjoint.
- The datasets use different collection and feature-extraction pipelines and have different class distributions.
- STRICT6 transfer is neither temporal validation nor dynamic malware analysis.
- The direct-transfer baseline performs no domain adaptation, target-dataset scaling, joint normalization, distribution matching, or target-based feature selection.
- Within-domain six-feature controls are necessary context; they do not replace Protocol P or Protocol G.
