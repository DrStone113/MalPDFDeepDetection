# CIC cross-dataset candidate identity audit

The preflight remains blocked. Exact case-insensitive identifier matching found **8,386/10,023** CIC `FileName` values equal to actual SHA-256 values in the source-PDF manifest. Counts by original partition: {'train': 5046, 'test': 1673, 'validation': 1667}. All matched source rows originate from `zenodo_malware_pdf_2011`.

The linked source/target labels disagree on **3,727** rows. This is conditional evidence from identifier equality, not verified CIC PDF byte identity; both labels are preserved. Transition counts: {'source_1_target_0': 3727, 'source_1_target_1': 4659}. Do not reinterpret file names as verified hashes, silently relabel samples, or treat nonmatching identifiers as proof of independence.

Actual target PDF bytes and checksum semantics must be verified before excluding known duplicate/related files, resolving label provenance, and locking a usable external evaluation cohort. No inference, training, calibration, threshold adaptation or original Test reevaluation occurred. Raw identities and the row-level join stay in ignored artifacts.

The parent preflight comparison is `reports/experiments/cross_dataset_evasion_v3/run_20261003T091848313122Z_3b68d36a5705/cross_dataset_comparison.csv`; its CIC metrics remain N/A.
