# Bulk extraction recovery — 2026-11-19

The old bulk writer and its two children were stopped after verifying their process identities. All eight checkpoint markers and 40 output files retained their SHA-256 values. The old job and claim files also retained their hashes. The selection has 41,727 documents. The original 4,000 tabular identities match the pinned manifests and still partition into 3,903 graphs and 97 unavailable records.

The native Linux verification exercised the new bounded worker on a reviewed benign fixture under a 256-FD process limit. Baseline readback selected 128 identities from existing structured artifacts. See the linked plan for pilot and resume status.

[Recovery plan](../../plans/bulk-extractor-recovery/plan.md)
