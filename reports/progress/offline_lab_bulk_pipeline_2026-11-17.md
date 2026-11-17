# Offline REMnux `Lab` Bulk Extraction Integration (`pdf-static-bulk`) — 2026-11-17

Base commit: `11775cfc953129f8c4537518356bab4638912db9` (`main`).

## Summary of Architecture & Transition

Following exhaustion of Camber Cloud monthly `Student` quota (`CPU usage: 100% used`, `GPU usage: 86.7% used`), bulk feature extraction across the `~44k` corpus moved to the local isolated REMnux `Lab` VM (`8 vCPU`, `7.8 GiB` RAM + `4.0 GiB` Swap, `44 GB` free disk, `.venv` Python `3.12.3` with `torch 2.11.0+cpu`, `malpdf-firewall` in `phase2_locked`, `Arlington` pinned at `b7d880b7a3d3c8f505c025f17763397475e90503`).

### 1. Combined Clean Manifest & Streaming Merge ([bulk_pipeline.py](../../src/malpdf/extraction/bulk_pipeline.py))
- Extended `_classify_row_provenance` to recognize `source_manifest.csv` provenance labels (`zenodo_clean_pdf_9000` → `0`, `zenodo_malware_pdf_2011` → `1`) alongside `bulk_20261116/manifest.csv` (`vapd_v5`, `govdocs1_sample`, `safedocs_*`, `zenodo_3464032_malware_2017`).
- Added `cic_split_manifest_csv` to `_load_cic_overrides` / `build_clean_corpus_manifest` so only `cohort == "cic"` rows (`1,452` Protocol G samples across `train=870`, `validation=291`, `test=291`) receive `cic_protocol_g_verified`, preventing non-CIC baseline entries in `source_manifest.csv` from receiving `cic` precedence; added manifest-relative fallback lookup (`mpath.parent / relpath`) and tightened per-chunk `data/raw` boundary resolution.
- Refactored `merge_bulk_chunks` to stream per-chunk `index_measured_graphs_v2` validation and store compact `corpus_metadata.csv` scalar tuples instead of buffering all full `23D` graph/tabular JSON objects in RAM (`8 GiB` VM safe), and aggregated `primary_available_count`, `timeout_count`, and `peak_rss_bytes` into `summary.json`.

### 2. Zero-Argument Offline Runner Kind `pdf-static-bulk` ([lab_jobs.py](../../scripts/lab/lab_jobs.py), [lab_runner.py](../../scripts/lab/lab_runner.py), [offline_prepare.py](../../scripts/lab/offline_prepare.py))
- Added `pdf-static-bulk` to `PDF_KINDS` (`workers=5`, `chunk_size=500`, `file_wall_seconds=45`, `file_cpu_seconds=35`, `file_memory_bytes=1536 MiB`, `file_max_bytes=50 MiB`, `device="cpu"`, `output_root="data/processed/bulk_extract"`).
- Enforces `jobs.preflight('offline', attested=True)`, `require_extraction_lab(True)`, `claim.json` console ownership, and isolated child worker bounds (`CodeInspectionLimits`) while supporting chunked SHA-256 checkpoint resume (`resumed_from_checkpoint`) across interruptions on `lab run`.
- Updated [lab_runner.md](../../docs/lab_runner.md) and [README.md](../../docs/README.md).

## Windows DEV Pre-Deployment Verification

- Targeted pytest (`test_hybrid_gpu_extraction.py`, `test_lab_halt_reporting.py`, `test_cic_full_cohort.py`, `test_bulk_pdf_acquisition.py`, `test_extraction_quality_gate.py`, `test_graph_projection_v2.py`): **`88 passed in 10.13s`** (including new tests `test_build_clean_corpus_manifest_supports_multi_cohort_v4_and_cic_split` and `test_pdf_static_bulk_policy_and_dynamic_summary_validation`).
- `scripts/lab/check_local.py`: `status: "passed"` (`403` AST files, `237/237` synthetic tests, `dependency_checks`, `pip_check`, `diff_check`, `repository_content_guard`).
- Comment audit across all `6` modified Python files (`tokenize.COMMENT`): `0` comments.
- Pre-commit `scripts/security/check_repo_content.py`: passed (`2,478` tracked index files).

## Remote REMnux `Lab` Deployment & Queued `pdf-static-bulk` Job (`7b15cc6`)

- Synced commit `7b15cc602bb3d8563a419647a2d84ad8d723c038` onto `/home/remnux/MalPDFDeepDetection` over Host-Only `ssh remnux-lab` (`malpdf-firewall` kept in `phase2_locked`, `nat_up: false`, `host_only_if: "ens34"`).
- `Lab` `.venv` (`Python 3.12.3`, `torch 2.11.0+cpu`): `pytest tests/test_hybrid_gpu_extraction.py tests/test_lab_halt_reporting.py -q` -> **`59 passed in 7.00s`**.
- Upgraded `malpdf-gateway` (`acdcc67456ef07ba91a82113e773dda3d6e34a948949f4b054f7116d120deebe`) and offline `malpdf-runner` (`011697ca99fee6566055ecf3ee419a54d66fba8e882c1dd0c5fde2a0fef830e5`).
- Verified remote control plane from Windows DEV:
  - `.\lab.ps1 verify` -> `verified: true`, `policy_sha256: "232ae351536fd4853f9be28be5b70ab623114a0280810a71e871ae30a534dd36"`, `profiles: ["syntax", "synthetic"]`.
  - `.\lab.ps1 status` -> `installed: true`, `host_only_ready: true`, `offline_guest_ready: false`, `schema_version: 3`.
  - `.\lab.ps1 test -Mode synthetic` -> `status: "passed"` (`job_id: "edd21884f326455613af7f639d649f69d0f8a8d8791034715226b67123d86569"`, `syntax: 403 passed / 0 failed`, `synthetic: 6 passed / 0 failed`).
- Queued zero-argument offline `pdf-static-bulk` job on `Lab`:
  - `job_id`: `a273d8be75491c24bcecb332ccd427cf9f5fb3bcbdf6ca3d7cc90fe686d38ba0` (`status: "queued"`, `mode: "offline"`).
  - `/var/lib/malpdf/jobs/a273d8be.../bulk_plan.json`: `planned_denominator: 41727` unique clean PDFs (`selection_sha256: "5b6134576e836c5d9f8d8f41a80e3e471806944a4cef6643bca6952a9e8ae3b1"`), `raw_rows: 73462`, `skipped_non_dataset: 2273`, `cic_override_applied: 1452`, `labeled_0: 9638`, `labeled_1: 11785`, `unlabeled_or_unverified: 20304`.
  - `/usr/local/bin/lab status` / `lab preflight`: `pending_jobs: 1`, `network_changed: false`, `credentials: []`.
  - Operator handoff ready: disconnect VMware `Lab` NICs (`NAT` and `Host-Only`) and execute `lab run` in the REMnux console.
