# Hỗ trợ PDF đến 100 MB, tăng tốc quét & tách pha Upload vs Quét — 2026-11-21

[Space MalPDF](https://huggingface.co/spaces/DrStone113/malpdfdetection) ([runtime](https://drstone113-malpdfdetection.hf.space)) đã chuyển sang trạng thái `RUNNING` (`hw=zero-a10g`) trên commit [`ea8fde9`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/ea8fde927bb7f2fa1e73d7c989df0a0b551d56e9), cập nhật fast-forward từ [`dce6d3b`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/dce6d3b09e36de4db58d8a03a510e56d5b4e2377).

## Nguyên nhân gốc rễ đã xử lý

1. **Chặn tệp lớn ở 2 tầng**:
   - `_validate_pdf_bytes()` trong backend (`src/malpdf/web/app.py`, `production/web_service.py`) và `InstantPDFIngestion` (`src/malpdf/scanner/ingestion.py`) đều giới hạn `32 MiB` (HTTP `413 size_limit_exceeded`).
   - `count_escaped_pdf_names()` trong `src/malpdf/static/obfuscation.py` ném `ValueError("PDF bytes must be nonempty and within the 10 MiB cap")` khi `ONNXThreatTaxonomyClassifier` / `ThreatTaxonomyClassifier` chạy trên tệp `> 10 MiB`.
2. **Nghẽn hiệu năng khi quét trên máy chủ**:
   - `_index_physical_object_spans()` quét regex toàn bộ tệp PDF tìm mọi `obj...endobj` dù `PdfReader.xref` đã có sẵn bảng offset O(1).
   - `_measure_byte_image_file_ratios()` nén PNG thật và tính SHA-256 trên tới 256 tile trong lúc chấm điểm dù chỉ trả về tỷ lệ byte được lập kế hoạch.
   - `scan_raw_pdf_tokens()` chạy quét toàn bộ byte hai lần (một lần trong `ingestion.py` với đủ 31 token nghiên cứu, một lần trong `taxonomy.py` / `onnx_taxonomy.py`).
   - `_extract_object_metadata()` sao chép toàn bộ buffer stream lớn (`bytes(raw_stream_buf)`) thay vì cắt mẫu 64 KiB đầu khi phân tích metadata.
   - Giao diện trước đây dùng `fetch('/api/scan')` không bắt tiến trình `xhr.upload.onprogress` và đặt bộ đếm thời gian giả lập ngay từ lúc chọn tệp, khiến người dùng không phân biệt được lúc mạng đang đẩy tệp lên với lúc máy chủ đang phân tích.

## Thay đổi đã triển khai

- `src/malpdf/static/obfuscation.py`: thêm regex một lượt `ESCAPED_PDF_NAME`, nhánh bỏ qua nhanh khi không có `#`, và tham số tùy chọn `max_bytes` (giữ nguyên mặc định `MAX_PDF_BYTES = 10 MiB` cho kiểm thử nghiên cứu `test_safe_stacking_v3.py`).
- `src/malpdf/scanner/ingestion.py`: nâng `DEFAULT_MAX_PDF_BYTES = 100 * 1024 * 1024`, tra offset O(1) qua `_build_xref_offset_map` (kèm fallback regex giới hạn `<= 8 MiB` và tìm `endobj` bằng `bytes.find` chỉ cho `<= 200` nút đồ thị), bỏ nén PNG thừa trong `_measure_byte_image_file_ratios`, cắt mẫu 64 KiB trong `_extract_object_metadata`, chỉ đếm đúng 18 token dùng bởi bộ quét và trả lại `raw_tokens` cho bộ phân loại taxonomy tái sử dụng.
- `src/malpdf/scanner/taxonomy.py`, `production/onnx_taxonomy.py`, `onnx_taxonomy.py` trên Space: truyền `max_bytes=max(MAX_PDF_BYTES, len(raw_pdf_bytes))` và tái sử dụng `ingest_data["raw_tokens"]`.
- `src/malpdf/web/app.py`, `production/web_service.py`, `web_service.py` trên Space: nâng `MAX_UPLOAD_BYTES` lên mặc định **100 MiB** (cấu hình được qua `MALPDF_MAX_UPLOAD_MB`) và công khai `max_upload_bytes` / `max_upload_mb` ở `/api/health`.
- `src/malpdf/web/store.py`: bổ sung ngưỡng bộ nhớ đệm `max_total_bytes = 512 MiB` với cơ chế tự giải phóng job cũ (`_enforce_memory_budget`) trong `create_job` và `attach_sanitized`.
- `src/malpdf/web/templates/index.html` & `src/malpdf/web/static/dashboard.css`: nâng cấp `handleFileSelect` dùng `XMLHttpRequest` để tách hẳn **Giai đoạn 1/2 • Đang tải tệp lên** (biểu tượng `cloud_upload`, tiến độ `%` thật, MB đã gửi, tốc độ MB/s, ETA, nút `Hủy`, ẩn tia laser quét) sang **Giai đoạn 2/2 • Đang quét trên máy chủ** (bật tia laser quét, đếm giây xử lý thực tế, kiểm tra giới hạn dung lượng ngay ở trình duyệt trước khi gửi).

## Kết quả đo hiệu năng & kiểm thử

- **Thời gian quét đầy đủ `ONNXMalPDFScannerEngine.scan_bytes(..., explain=True)` trên Windows DEV** (trên bản sửa từ `tests/fixtures/real_benign_document.pdf` chèn payload `os.urandom`):
  - `1.31 MiB`: `62.4 ms` (`prediction_available=True`, `ml_weights_loaded=True`)
  - `8.31 MiB`: `147.1 ms` (so với `481.7 ms` chỉ riêng `ingest()` + `286.3 ms` ONNX XAI trước tối ưu trên mẫu synthetic 8.03 MiB)
  - `25.32 MiB`: `401.5 ms` (trước đây lỗi ở ngưỡng `10 MiB` và `ingest()` mất `1,189.9 ms`)
  - `45.32 MiB`: `744.5 ms` (trước đây bị chặn kép ở `10 MiB` và `32 MiB`; `ingest()` trước tối ưu mất `2,151.8 ms`)
- **Kiểm thử tự động & trình duyệt**:
  - `pytest tests/test_web_app.py tests/test_onnx_production.py tests/test_safe_stacking_v3.py::test_escaped_name_count_is_an_actual_raw_measurement_not_encoding_proxy -q` → `20 passed` (ghi nhận thêm: toàn bộ suite `tests/test_safe_stacking_v3.py` có 8 test `run_safe_stacking_v3` không liên quan fail sẵn trên Windows do `\\` trong `Path` theo kiểm tra của `late_fusion_runner.py`).
  - Playwright trên DEV với `tests/fixtures/real_threat_document.pdf` và mẫu `8.3 MB` (throttled qua CDP `uploadThroughput=1500 KB/s` để quan sát pha tải lên): xác nhận Giai đoạn 1/2 (`data-phase="uploading"`, laser ẩn, `#doc-upload-badge` hiện), Giai đoạn 2/2 (`data-phase="scanning"`, laser bật), kiểm tra từ chối tức thì `>100 MB` không gửi request, desktop `1440x900` và mobile `390x844` không tràn ngang, `0` lỗi console/page/request.
- **Xác minh Live Hugging Face Space (chỉ đọc)** (`https://drstone113-malpdfdetection.hf.space`, commit `ea8fde927bb7f2fa1e73d7c989df0a0b551d56e9`):
  - `GET /api/health` → HTTP `200`, `status="healthy"`, `max_upload_bytes=104857600`, `max_upload_mb=100`, ONNX models loaded.
  - `GET /` → HTTP `200`, khớp SHA-256 `f49e4f38f99cf0a8718049745bdadac946abcefaf73308305d65a12c34299a04`, có đủ `scan-phase-badge`, `doc-upload-badge` và `HELD_FOR_REVIEW`.
  - `GET /assets/dashboard.css` → HTTP `200`, khớp SHA-256 `bbeeff06364a3f661d47eae10ec3eac2f32d8cba2c158098dc9b1a61c53fb050`.
  - `GET /api/scans` → HTTP `200`, `Cache-Control: no-store`.
  - Lưu ý vận hành: tầng backend & trình duyệt hiện hỗ trợ đến `100 MiB` mỗi tệp qua `POST /api/scan`; tuy nhiên trên bản cloud công khai `hf.space`, reverse proxy phía ngoài của Hugging Face có thể vẫn áp trần dung lượng HTTP POST đơn lẻ thấp hơn — nếu gặp lỗi `413` từ proxy với tệp cực lớn, có thể bổ sung cơ chế cắt mảnh (`chunked upload`).
