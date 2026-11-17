# [BUG-011] Worker crash (`471 unavailable_worker_failure` + `29 resource_limit`) do `multiprocessing.spawn` nạp `__mp_main__` chứa `torch`/CUDA trước `RLIMIT_AS = 2 GiB`

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-011` |
| **Ngày ghi nhận** | `2026-11-17` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Gãy 500/500 mẫu khi chạy CLI `cloud_bulk_extract.py`) |
| **Phân loại lỗi** | `RESOURCE_OOM` / `WORKER_ISOLATION` |
| **Thành phần ảnh hưởng** | `scripts/cloud_bulk_extract.py`, `src/malpdf/extraction/bulk_pipeline.py` |
| **Hồ sơ liên quan** | `docs/bugs/BUG-010-cloud-worker-starvation-coalesce-ml-import.md`, commit `1ccdbb3` |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Sau khi áp dụng `BUG-010` (`1ccdbb3`), chạy Phase 2 (`--extract` qua CLI `scripts/cloud_bulk_extract.py`) trên container Camber `GPU · Xsmall` (`8 CPU / NVIDIA L4`, cgroup `memory.max = 30,064,771,072` B, `memory.current = 1,986,224,128` B, `pids.max = 37,014`, `RLIMIT_NOFILE = (4096, 1048576)`, `RLIMIT_AS = (-1, -1)` ở parent) vẫn cho `chunk_00000` **0/500 GNN graph**:

### Log / Bằng chứng đối chiếu trực tiếp trên cùng container `GPU · Xsmall`
```text
{"event": "chunk_completed", "chunk_id": 0, "total_chunks": 84, "count": 500, "gnn_graphs": 0, "unavailable_graphs": 500, "markov_matrices": 500, "status_counts": {"partial": 471, "resource_limit": 29}, "cpu_seconds": 870.183, "gpu_projection_markov_seconds": 8.036, "device": "cuda", "resumed_from_checkpoint": false}

Chunk 0 dispositions: Counter({'unavailable_worker_failure': 471, 'unavailable_unclassified_empty': 29})
First tab: {'index': 0, 'sha256': '0001dcb7233c85770732d138fcfe529f611b609de36e719542c1ec5dedbb508d', 'status': 'resource_limit', 'sample_disposition': 'unavailable_unclassified_empty', 'excluded_feature_count': 13}
```

Nhưng ngay trong cùng cell đó trên chính pod `GPU · Xsmall`, khi gọi trực tiếp `bp.run_hybrid_bulk_extraction(entries[:6], workers=6, chunk_size=6, device="auto", ...)` qua `python -c`:
```text
6-PDF bulk summary: 6 0 {'bounded_complete': 6}
DIAG: (0, 'bounded_complete', 'complete', -9, 1744, None, None) tb= None err=
DIAG: (1, 'bounded_complete', 'complete', -9, 3731, None, None) tb= None err=
DIAG: (2, 'bounded_complete', 'complete', -9, 3409, None, None) tb= None err=
DIAG: (3, 'bounded_complete', 'complete', -9, 1087, None, None) tb= None err=
DIAG: (4, 'bounded_complete', 'partial', -9, 1474, None, None) tb= None err=
DIAG: (5, 'bounded_complete', 'partial', -9, 1573, None, None) tb= None err=
```

### Điều kiện tái hiện
- Chạy qua entrypoint `.py` (`python scripts/cloud_bulk_extract.py ... --extract`) trên Linux với giới hạn bounded worker (`RLIMIT_AS = 2 GiB`).
- Ngược lại, chạy qua `python -c "..."` (`sys.modules['__main__']` không có `__file__`) thành công `6/6` (và trước đó `8/8`) trên cùng các PDF `entries[:6]` (`0001dcb7...` đạt `1,744` evidence records, `peak_rss_bytes = 284,889,088`).

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

1. **Tại sao cùng tệp `entries[0]` (`0001dcb7...`) chạy ở đầu lô lại ra `resource_limit` (`excluded_feature_count: 13`, mất `StaticPDFAnalyzer`) khi gọi qua `scripts/cloud_bulk_extract.py`, nhưng thành công `bounded_complete` (`1,744` records) khi gọi qua `python -c`?**
   Vì `python -c` không thiết lập `init_main_from_path` trong `multiprocessing.spawn.get_preparation_data`, nên process con không import module `__main__`; còn `python scripts/cloud_bulk_extract.py` có `__main__.__file__` nên `multiprocessing.get_context("spawn")` gán `'init_main_from_path': '.../scripts/cloud_bulk_extract.py'`.
2. **Tại sao việc `spawn` import `scripts/cloud_bulk_extract.py` làm mọi worker con (`500/500`) kiệt quệ?**
   Vì `scripts/cloud_bulk_extract.py` import ở top-level cả `malpdf.extraction.bulk_pipeline` lẫn `malpdf.extraction.gpu_accel` (mà `gpu_accel.py` và `bulk_pipeline.py` cùng import `torch` + CUDA `2.11.0+cu130` ở top-level -> tổng cộng `1,098` modules cho `scripts.cloud_bulk_extract` / `1,086` cho `bulk_pipeline`, so với chỉ `146` modules khi import sạch `worker_diagnostics` + `profile_worker` + `arlington_model`).
3. **Tại sao import `torch` ở top-level trong worker con lại gây `471 worker_error` và `29 resource_limit` mà `WorkerDiagnostics` không chụp được Python traceback?**
   Vì `spawn_main()` thực thi `import __mp_main__` (`scripts/cloud_bulk_extract.py` -> `torch`) **trước khi** `run_child()` cài pipe bắt `stderr`/`traceback`, và sau đó `_profile_child()` gọi `_apply_code_limits(limits)` áp đặt `resource.setrlimit(RLIMIT_AS, (2 GiB, 2 GiB))`. Thư viện `torch 2.11.0+cu130` (CUDA/cuBLAS/cuDNN/OpenMP) đã map lượng lớn không gian địa chỉ ảo (`VmSize` gần/vượt ngưỡng `2 GiB` trước `RLIMIT_AS`), khiến các lần `malloc`/`mmap` kế tiếp của C/C++ parser (`pypdf`/`PyMuPDF`/`pikepdf`) thất bại (`ENOMEM` -> `abort`/`SIGSEGV` -> `worker_exit` `partial`/`unavailable_worker_failure` x471, hoặc Python `MemoryError`/tín hiệu -> `resource_limit`/`unavailable_unclassified_empty` x29), đồng thời `6` worker phải nạp lạnh PyTorch/CUDA `500` lần tốn `870.183s`.

### Cơ chế kỹ thuật tầng sâu (Deep Mechanics)
- Khác với `fork`, `multiprocessing.get_context("spawn")` khởi tạo tiến trình Python mới hoàn toàn, nhưng vẫn tự động đọc `init_main_from_path` của tiến trình cha nếu `__main__` là file `.py` không chạy dưới dạng `-m`.
- Mọi top-level import trong file CLI entry script (và chuỗi phụ thuộc trực tiếp không lười biếng của nó như `bulk_pipeline.py` -> `gpu_accel.py` -> `torch`) sẽ bị thực thi bên trong **tất cả các worker phân tích tĩnh độc hại**, phá vỡ nguyên tắc cô lập dung lượng ảo (`RLIMIT_AS = 2 GiB`) và kéo chi phí khởi tạo GPU framework vào từng worker CPU.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh
- Không nới lỏng hoặc bỏ `RLIMIT_AS = 2 GiB` trong `_apply_code_limits()` để chứa PyTorch trong worker parser.
- Không monkeypatch internals không chuẩn của `multiprocessing.spawn.get_preparation_data`.

### Giải pháp kỹ thuật chuẩn & Anti-Regression Invariant
1. **Giữ CLI entrypoint `scripts/cloud_bulk_extract.py` thuần stdlib ở top-level:** Chuyển toàn bộ import nặng/chuyên dụng (`numpy`, `acquire_bulk_pdf_corpus`, `arlington_model`, `bulk_pipeline`, `gpu_accel`, `execution`) và cập nhật `sys.path` qua `_ensure_repo_paths()` vào bên trong từng hàm (`setup_arlington`, `run_acquire`, `run_benchmark`, `main`). Khi `spawn` tái nạp `cloud_bulk_extract.py` làm `__mp_main__`, tiến trình con chỉ nạp `~80` module stdlib (`0` `torch`, `0` `numpy`, `0` `malpdf`).
2. **Tách `gpu_accel`/`torch` (và `numpy`) thành lazy import trong `src/malpdf/extraction/bulk_pipeline.py`:** Chuyển `resolve_extraction_device`, `hardware_profile`, và `byte_transition_matrices_batch` thành thin lazy wrapper import từ `malpdf.extraction.gpu_accel` tại thời điểm gọi (giữ nguyên tên symbol ở cấp module để tương thích `monkeypatch` trong test), và import `numpy` lười biếng bên trong nhánh `if include_markov:` của `_process_chunk`.
3. **Bất biến (Invariant):** Mọi CLI entrypoint hoặc orchestrator khởi chạy `multiprocessing.get_context("spawn")` cho worker bị giới hạn `RLIMIT_AS` tuyệt đối không được import `torch`, `sklearn`, `scipy`, `joblib`, hoặc module CUDA nào ở cấp top-level.
4. **Kiểm thử hồi quy:** Thêm `test_cloud_bulk_extract_spawn_worker_avoids_torch_and_ml_imports` vào `tests/test_hybrid_gpu_extraction.py` mô phỏng trực tiếp `sys.modules['__main__'].__file__ = scripts/cloud_bulk_extract.py` + `multiprocessing.get_context('spawn')` để khẳng định `'torch'`, `'numpy'`, `'scipy'`, `'sklearn'`, `'joblib'`, `'malpdf.extraction.gpu_accel'` đều vắng mặt trong process con `spawn`, và import `bulk_pipeline` cũng không kéo theo `torch`/`gpu_accel`.
