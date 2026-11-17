# [BUG-010] Suy kiệt tài nguyên / `unavailable_worker_failure` và nút thắt `O(N²)` deepcopy + import ML thừa trong worker PDF chế độ `bounded`

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-010` |
| **Ngày ghi nhận** | `2026-11-17` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` |
| **Phân loại lỗi** | `RESOURCE_OOM` |
| **Thành phần ảnh hưởng** | `src/malpdf/extraction/checkpointing.py`, `src/malpdf/inference/__init__.py`, `src/malpdf/inference/evidence_policy_v9.py`, `src/malpdf/static/v8_features.py`, `src/malpdf/static/profile_worker.py`, `src/malpdf/extraction/bulk_pipeline.py`, `scripts/cloud_bulk_extract.py` |
| **Hồ sơ liên quan** | `reports/progress/cloud_hybrid_extraction_2026-11-16.md`, `docs/bugs/README.md` |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Khi chạy batch trích xuất Cloud Hybrid CPU+GPU trên Camber (`GPU · Xsmall`: 8 CPU / 32 GB RAM / 1 NVIDIA L4 GPU, `chunk_size=500`, `wall_seconds=45`, `cpu_seconds=35`, `memory_mb=2048`):
- Hai chunk đầu tiên (`chunk_00000` và `chunk_00001`) đều trả về `gnn_graphs: 0`, `unavailable_graphs: 500`, `status_counts: {"partial": 469, "resource_limit": 31}` (`cpu_seconds: 712.391s` và `696.785s`).
- Phân tích `unavailable_records.json` của `chunk_00000` cho thấy `{'unavailable_worker_failure': 469, 'unavailable_unclassified_empty': 31}`, đồng thời bản ghi `e0` đầu bảng chỉ có `excluded_feature_count: 13` (tức worker chết trước khi `StaticPDFAnalyzer`/`analysis_v9` ghi xong), trong khi chạy riêng lẻ chính `e0` lại đạt `usable_complete_projection` với `67` node GNN (`peak_rss_bytes: 285 MB`), kèm cảnh báo `joblib` `[Errno 27] File too large` trên `stderr`.
- Profile `cProfile` cục bộ trên `tests/fixtures/real_benign_document.pdf` cho thấy một file PDF 1 trang nhỏ tốn `14.28s` (`inspect_evidence_v9` `6.0s`, `inspect_parser_views` `4.6s`, `inspect_raw_forensic` `3.3s`) và khi bật checkpoint callback ở chế độ `bounded`, `inspect_parser_views` + `inspect_raw_forensic` tốn tới **`34.729s`** (`31.444s` nằm trong `copy.deepcopy()` qua `599 + 322 = 921` lần gọi `emit()`).

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys)

1. **Tại sao `parser_views` + `raw_forensic` đốt `34.7s` trên một file nhỏ và nhiều PDF đụng `wall_timeout` / `SIGXCPU`?**
   `CheckpointScheduler` (`src/malpdf/extraction/checkpointing.py`) gán `self.coalesce = is_vm(limits)` nên trong chế độ `bounded` (`45s / 35s`), mỗi PDF object đều chạy `copy.deepcopy(result)` và `json.dumps(result)` (`O(N²)`).
2. **Tại sao mỗi tiến trình con `spawn` của PDF lại nạp `1,810` module Python (`sklearn`, `scipy`, `pandas`, `joblib`) và văng `joblib [Errno 27]`?**
   `evidence_v9.py` gọi `from malpdf.inference.evidence_policy_v9 import derive_feature_provenance`; do `src/malpdf/inference/__init__.py` eager-import `deployment.py` & `predictor.py`, và `evidence_policy_v9` lại import `v8_feature_values` từ `experiments/cic_v8.py`, toàn bộ stack ML + `joblib` (vốn đụng `RLIMIT_FSIZE=0`) bị nạp lặp lại trong từng worker `spawn` (`RLIMIT_AS=2 GiB`).
3. **Tại sao khi `workers=8` chạy đồng thời trên pod `GPU · Xsmall`, 8 worker `spawn` dễ chết sớm trước `StaticPDFAnalyzer` và phần lớn bị gắn nhãn `"worker_exit"` (`unavailable_worker_failure`)?**
   Ngoài áp lực đồng thời của 8 tiến trình `spawn` cùng unpickle + import `1,810` module từ Lustre trong khi parent đã khởi tạo CUDA, nhánh `elif exited:` trong `profile_worker.py` chưa kiểm tra `process.exitcode in (-9, -24)` trước khi kết luận `worker_error` (chỉ kiểm tra ở nhánh `if ready:` khi pipe văng `EOFError`).

---

## 3. Giải pháp & Ràng buộc Bất biến (Resolution & Invariants)

1. **Tách helper `v8_features` thuần Python không kéo runtime ML (`src/malpdf/static/v8_features.py`) & lazy-load `src/malpdf/inference/__init__.py`:**
   - Di chuyển `PROFILE_VARIANTS`, `AST_NODE_TYPES`, `advanced_features`, `profile_feature_values`, `v8_feature_values` về `malpdf.static.v8_features` và re-export lại từ các module `experiments` cũ để không trùng lặp logic.
   - Đổi `src/malpdf/inference/__init__.py` sang PEP 562 `__getattr__`, giúp `import malpdf.inference.evidence_policy_v9` không kéo `sklearn`/`scipy`/`joblib`/`xgboost`/`lightgbm`/`catboost`.
2. **Hỗ trợ coalesced checkpoints cho bulk bounded extraction (`MALPDF_COALESCE_CHECKPOINTS=1` / `coalesce_checkpoints=True`):**
   - Giữ nguyên hành vi mặc định của `CheckpointScheduler(CodeInspectionLimits())` cho các test cadence hiện có; truyền `coalesce_checkpoints=True` từ `bulk_pipeline` qua `extract_pdf` → `profile_pdf` → `_profile_child`.
   - Khởi tạo CUDA (`resolve_extraction_device`, `hardware_profile`) sau bước CPU worker trong `bulk_pipeline.py` và `scripts/cloud_bulk_extract.py`.
   - Sửa `elif exited:` trong `profile_worker.py` để ghi nhận đúng `resource_limit_or_signal` khi `process.exitcode in (-9, -24)`.

### Quy tắc bất biến chống hồi quy (Anti-Regression Invariants)
- Worker phân tích PDF tĩnh (`evidence_v9`, `evidence_policy_v9`) **tuyệt đối không** được import `sklearn`, `scipy`, `joblib`, `xgboost`, `lightgbm`, hoặc `catboost`.
- Chế độ bulk extraction phải bật `coalesce_checkpoints=True` để tránh `O(N²)` `deepcopy`, đồng thời không kích hoạt `torch.cuda` ở parent trước khi pool worker CPU hoàn tất.
