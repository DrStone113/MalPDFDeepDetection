# Hybrid CPU+GPU Bulk Extraction & Cloud Ephemeral Pipeline — 2026-11-16

Base commit: `2e276d8d8fedd98b664748d924873867a9f2f928` (`main`).

## Summary of Engineering Changes

Implemented a hybrid **CPU + GPU** bulk static extraction and clean corpus curation pipeline enabling unattended, checkpointed extraction of the `~41.7k`-PDF deduplicated dataset directly inside a user-authorized ephemeral cloud GPU environment (`GPU · Xsmall: 8 CPU / 32 GB RAM / 1 GPU`) without sacrificing per-file timeouts or routing raw malware PDFs through Windows DEV.

### 1. Hybrid CPU+GPU Tensor Acceleration (`src/malpdf/extraction/gpu_accel.py`)
- **Single-Context Coordinator Design:** Multi-core CPU parser workers remain isolated spawned processes (`PyMuPDF`, `pikepdf`/`qpdf`, `pypdf`, `Arlington`, `streams`, `carving`, `JS AST`) while a single coordinator CUDA context executes dense tensor kernels in batches, avoiding per-worker CUDA VRAM duplication.
- **GPU-Batched 16-Step RWSE (`compute_rwse_batch_torch`):** Packs non-empty graphs (`num_nodes <= 200`) into padded `(B, max_N, max_N)` `float32` tensors and runs `torch.bmm` on CUDA (`cuda` fallback to `cpu`). Integrated into [graph_projection_v2.py](../../src/malpdf/extraction/graph_projection_v2.py) via shared `_prepare_graph_projection_v2` / `_finalize_graph_projection_v2` helpers (`project_graph_bundles_batch_v2`) and [quality_gate.py](../../src/malpdf/extraction/quality_gate.py) (`evaluate_sample_quality_v2(..., projected_v2=...)`).
- **GPU-Batched `256×256` Markov Matrices (`byte_transition_matrices_batch`):** Streams packed `uint8` buffers to GPU (avoiding `8×` host-to-device integer expansion), removes inter-sample boundary transitions, computes all `(B, 256, 256)` transition histograms in a single `torch.bincount`, and row-normalizes to `float32` (chunked accumulation for buffers exceeding `max_batch_bytes`).
- **Vectorized Raw Byte Entropy (`window_entropy_batch` & [raw.py](../../src/malpdf/extraction/raw.py)):** Replaced pure-Python `Counter(data)` loops in `inspect_raw_layout` with NumPy `np.bincount`, plus optional GPU window-entropy kernels (`window_entropy_batch`).

### 2. Generous Timeouts Without Unused-Stage Overhead
- Added `include_byte_images: bool = True` across [orchestrator.py](../../src/malpdf/extraction/orchestrator.py) (`extract_pdf`) and [profile_worker.py](../../src/malpdf/static/profile_worker.py) (`profile_pdf`, `_profile_pdf`, `_profile_child`).
- Bulk pipeline keeps full generous per-PDF budgets (`wall_seconds=45`, `cpu_seconds=35`, `memory_bytes=2 GiB`, `max_file_bytes=50 MiB`) while skipping `byte_images` raster generation (`include_byte_images=False`), preserving `parse_pdf`, `stream_decode`, `carving`, `raw_forensic`, `Arlington`, `script_semantics`, and `23D` projections.

### 3. Corpus Hygiene, Label Provenance & Chunked Cloud Runner
- **Acquisition Hardening ([acquire_bulk_pdf_corpus.py](../../scripts/lab/acquire_bulk_pdf_corpus.py)):** Fixed `extract_7z_archive` so `.json` / `METADATA_SUFFIXES` / `SKIP_SUFFIXES` are never ingested as PDFs (blocking the `2,261` `.json` non-PDF records observed in `2017-12-05-PDF.7z`), added `is_non_dataset_member` excluding `11` `matplotlib` icon PDFs and `Artifact_Documentation__USENIX_Security_25.pdf` in `vapd_v5`, added encrypted-ZIP password support to `extract_zip_archive`, and added `py7zr` fallback when `/usr/bin/7z` is absent.
- **Clean Provenance & Chunked Pipeline ([bulk_pipeline.py](../../src/malpdf/extraction/bulk_pipeline.py)):** `build_clean_corpus_manifest` deduplicates by SHA-256 and enforces strict label precedence (`cic_protocol_g_verified` > `zenodo_clean_9000`/`vapd_v5 D1/ben` (`0`) and `zenodo_malware_2011`/`vapd_v5 D1/mal` (`1`) > `cve_t4pdf` (`1`) > `unverified_zenodo_2017` (`None`) > `govdocs1_sample` (`None`) > `safedocs` (`None`)), preventing the `652` CIC benign PDFs inside `2017-12-05-PDF.7z` from being mislabeled as malware.
- **Cloud CLI & Starter Notebook ([cloud_bulk_extract.py](../../scripts/cloud_bulk_extract.py), [cloud_bulk_extract.ipynb](../../notebooks/cloud_bulk_extract.ipynb)):** Supports `--setup-arlington` (pinned `b7d880b7a3d3c8f505c025f17763397475e90503`), `--acquire`, `--extract` (resumable `500`-PDF chunks with SHA-256 chunk verification, `allow_pickle=False` sharded `markov_f32.npz`, optional `--prune-raw-after-chunk`), and `--benchmark-only`.
- **Governance Sync:** Updated [AGENTS.md](../../AGENTS.md), [.agents/rules/AGENTS.md](../../.agents/rules/AGENTS.md), [agent_security_and_safe_corpus.md](../../docs/agent_security_and_safe_corpus.md), and [docs/README.md](../../docs/README.md).

## Verification (Windows DEV — Synthetic Fixtures & RTX 5060 Ti CUDA)

- Targeted pytest (`test_hybrid_gpu_extraction.py`, `test_bulk_pdf_acquisition.py`, `test_graph_projection_v2.py`, `test_pdf_transgraph_v2.py`, `test_extraction_quality_gate.py`): **`39 passed in 7.14s`** (covering both `cpu` and `cuda`).
- `scripts/lab/check_local.py`: `passed` (`402` AST files, `237/237` synthetic tests, `dependency_checks`, `pip_check`, `diff_check`, `repository_content_guard`).
- `scripts/security/check_repo_content.py`: passed (`2,464` tracked index files checked against `HEAD`).
- Comment audit across 10 modified/added Python files (`tokenize.COMMENT`): `0` comments.
- Measured steady-state RTX 5060 Ti (`cuda:0`, PyTorch `2.11.0+cu128`) vs CPU (`Intel i5-14400F`):
  - `Markov 32 × 512 KiB`: CPU `0.109s` → CUDA `0.031s` (`3.5×` faster after `1.406s` one-time CUDA warmup).
  - `RWSE 128 × 180 nodes`: CPU `0.157s` → CUDA `0.031s` (`5.1×` faster).

## Remaining Scope

- Full ~41.7k cloud bulk acquisition & extraction (`scripts/cloud_bulk_extract.py --execute-cloud-extraction --acquire --extract`) is ready to execute in the user's Cloud `GPU · Xsmall` container; real-PDF extraction was not run on Windows DEV.

## 2026-11-17 Update — Cloud Acquisition Complete & `BUG-010` Worker Speed/Stability Fix

- **Camber `--acquire` Completed (`CPU · Xxsmall`, `errors=[]`):** Acquired `19,401,175,744` B (`49,775` extracted records → `41,581` unique SHA-256 PDFs across `zenodo_3464032_malware_2017` `10,500`, `vapd_v5` `19,276`, `govdocs1_sample` `5,000`, and `15` `safedocs` shards).
- **Diagnosed `chunk_00000`/`chunk_00001` Failure & Fixed `BUG-010`:**
  - Separated static/v8 feature extraction into [v8_features.py](../../src/malpdf/static/v8_features.py) and converted [inference/__init__.py](../../src/malpdf/inference/__init__.py) to lazy `__getattr__`, cutting `evidence_policy_v9` module load from `1,810` modules down to `623` (`0` `sklearn`/`scipy`/`joblib`/`xgboost`/`lightgbm`/`catboost` imports inside PDF workers, eliminating `joblib` `[Errno 27]` warnings under `RLIMIT_FSIZE=0`).
  - Enabled coalesced checkpoints (`coalesce_checkpoints=True` / `MALPDF_COALESCE_CHECKPOINTS=1`) for bounded bulk runs in [checkpointing.py](../../src/malpdf/extraction/checkpointing.py), [profile_worker.py](../../src/malpdf/static/profile_worker.py), [orchestrator.py](../../src/malpdf/extraction/orchestrator.py), and [bulk_pipeline.py](../../src/malpdf/extraction/bulk_pipeline.py), preserving `CheckpointScheduler` defaults and dropping local in-process extraction of `tests/fixtures/real_benign_document.pdf` from `14.28s` (`34.73s` with `emit()` callbacks) to `0.688s` (`usable_complete_projection`, `82` GNN nodes).
  - Deferred parent CUDA initialization until after `extract_pdfs` completes per chunk ([bulk_pipeline.py](../../src/malpdf/extraction/bulk_pipeline.py), [cloud_bulk_extract.py](../../scripts/cloud_bulk_extract.py)), fixed signal `-9`/`-24` classification on silent child exits in [profile_worker.py](../../src/malpdf/static/profile_worker.py), and split [cloud_bulk_extract.ipynb](../../notebooks/cloud_bulk_extract.ipynb) into Phase 1 (`CPU · Xxsmall` `--acquire`) and Phase 2 (`GPU · Xsmall` `--extract`).

## 2026-11-17 Update — `BUG-011` Resolved (`__mp_main__` `torch`/CUDA Re-import Under `multiprocessing.spawn`)

- **Empirical Isolation on Camber `GPU · Xsmall` (`1ccdbb3`):**
  - Container telemetry showed healthy headroom (`NVIDIA L4`, `cuda_available=True`, `cpu_count=8`, cgroup `memory.max=30,064,771,072` with `memory.current=1,986,224,128`, `pids.max=37,014`, `pids.current=51`, `RLIMIT_AS=(-1, -1)`).
  - Running `bp.run_hybrid_bulk_extraction(entries[:6], ...)` via `python -c` on the same pod succeeded `6/6` (`{'bounded_complete': 6}`, `0001dcb7...` produced `1,744` evidence records), whereas `scripts/cloud_bulk_extract.py --extract --chunk-size 500` yielded `0/500` usable graphs (`471 unavailable_worker_failure` + `29 unavailable_unclassified_empty`, `cpu_seconds=870.183`, including `index 0` `0001dcb7...` failing with `status='resource_limit'`).
- **Root Cause (`BUG-011`):** Running a `.py` CLI script causes Python `multiprocessing.get_context("spawn")` to set `init_main_from_path = scripts/cloud_bulk_extract.py`, re-importing `cloud_bulk_extract.py` -> `bulk_pipeline.py` -> `gpu_accel.py` -> `torch 2.11.0+cu130` (`1,098` modules) inside **every single spawned PDF worker** before `run_child` and `_apply_code_limits(RLIMIT_AS=2 GiB)`. CUDA/PyTorch virtual address mappings saturated `RLIMIT_AS = 2 GiB`, triggering C/C++ `ENOMEM`/signal aborts and Python `MemoryError`s inside all `500` workers.
- **Fix Applied:**
  - Restricted [cloud_bulk_extract.py](../../scripts/cloud_bulk_extract.py) module top-level to stdlib imports only (deferring `numpy`, `acquire_bulk_pdf_corpus`, `arlington_model`, `bulk_pipeline`, `gpu_accel`, and `execution` into their respective functions: `80` modules vs `1,098`, `0` `torch`/`numpy`/`malpdf` on import).
  - Converted `resolve_extraction_device`, `hardware_profile`, and `byte_transition_matrices_batch` in [bulk_pipeline.py](../../src/malpdf/extraction/bulk_pipeline.py) to lazy wrappers and moved `numpy` import inside `include_markov` (`237` modules, `0` `torch`/`gpu_accel` on import).
  - Added `test_cloud_bulk_extract_spawn_worker_avoids_torch_and_ml_imports` in [test_hybrid_gpu_extraction.py](../../tests/test_hybrid_gpu_extraction.py).
