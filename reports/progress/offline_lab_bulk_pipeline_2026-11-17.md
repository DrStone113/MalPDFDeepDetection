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
