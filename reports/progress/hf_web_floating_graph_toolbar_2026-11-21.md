# Phát hành thanh công cụ nổi trên sơ đồ PDF lên Hugging Face — 2026-11-21

[Space MalPDF](https://huggingface.co/spaces/DrStone113/malpdfdetection) ([runtime](https://drstone113-malpdfdetection.hf.space)) đã chuyển sang trạng thái `RUNNING` (`hw=zero-a10g`) trên commit [`69ecdac`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/69ecdacb40ff25e2aadb1935d0ee72699798ccea), cập nhật fast-forward từ [`c64d3a3`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/c64d3a3aed8963c420a693276ca1a8357490277d).

## Thay đổi đã đẩy lên Space (2 tệp)

- `src/malpdf/web/templates/index.html` (`sha256: e5d0c00795c3e83ae06d0af75ea7d08c6c9bc6ed228474f487dd425a95b7b3fe`, `303,834` bytes):
  - Bọc `#vis-container` trong `#vis-stage-wrap` (`position: relative; border-radius: 0.75rem; overflow: hidden`) và đặt `#graph-floating-toolbar` (`.graph-floating-dock` kính mờ) nổi phía trên vùng vẽ sơ đồ như phần tử anh em cùng cấp với `#vis-container` để `vis.Network` không ghi đè thanh công cụ khi khởi tạo lại.
  - Đưa toàn bộ 6 nút điều khiển (`Mạng lưới`, `Phân tầng`, `Tự gộp trang dài`, `Chỉ hiện nhánh nguy hiểm`, `Độ nảy vật lý`, `Căn giữa`) vào thanh nổi cuộn ngang gọn trên di động (`overflow-x-auto no-scrollbar whitespace-nowrap shrink-0`), đồng bộ lớp CSS trong JS (`setGraphLayoutMode`, `toggleCompactPagesMode`, `toggleThreatOnlyFilter`, `inspectAndAblateNode`), chỉnh chiều cao `#vis-container` thành `clamp(460px, calc(100vh - 220px), 860px)`, thêm `pt-16` cho `#vis-empty-placeholder`, và chuyển thanh chú giải sang cuộn ngang một hàng trên màn hình hẹp.
  - Giữ nguyên logic `HELD_FOR_REVIEW` riêng của Space, toàn bộ thiết kế lai `Hybrid v3` + animation canvas, và giữ nguyên Git LFS pointers của `models/*.onnx` (không stage các bản binary local hay `__pycache__/`).
- `src/malpdf/web/static/dashboard.css` (`sha256: 356d567015af1644a73fe66ab501d4bff0d4cd241f1852616b62620781edf2c6`, `34,596` bytes): biên dịch lại bằng `tailwindcss@3.4.17 --minify` từ template của Space.

## Xác minh trước khi đẩy & Live read-only trên Space

- Tiền phát hành: kiểm tra diff đúng 2 tệp mục tiêu trong `artifacts/hf-web-release-20261120`, không phát hiện khóa API nhúng trong HTML DEV hoặc HTML Space, và kiểm chứng trước đó trên DEV bằng Playwright (`1440x900` & `390x844`) cùng `pytest tests/test_web_app.py tests/test_onnx_production.py`.
- Xác minh live chỉ đọc trên `https://drstone113-malpdfdetection.hf.space` (không tải tệp PDF/EML và không gọi Cloud AI trả phí):
  - `GET /api/health` → HTTP `200`, `status="healthy"`, `runtime="onnxruntime"`, `prediction_available=true`, `weights_loaded=true`, `multilabel_weights_loaded=true`, `cdr_engine="pikepdf-inplace"`.
  - `GET /` → HTTP `200`, khớp byte và SHA-256 (`e5d0c00795c3e83ae06d0af75ea7d08c6c9bc6ed228474f487dd425a95b7b3fe`) với commit `69ecdac`, chứa `vis-stage-wrap`, `graph-floating-toolbar` và `HELD_FOR_REVIEW`.
  - `GET /assets/dashboard.css` → HTTP `200`, khớp byte và SHA-256 (`356d567015af1644a73fe66ab501d4bff0d4cd241f1852616b62620781edf2c6`).
  - `GET /api/scans` → HTTP `200`, header `Cache-Control: no-store`.

## Nâng cấp Pop-up HUD thu gọn / mở rộng (`dce6d3b`)

- **Space & Commit**: [`DrStone113/malpdfdetection`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/dce6d3b09e36de4db58d8a03a510e56d5b4e2377) (`dce6d3b09e36de4db58d8a03a510e56d5b4e2377`, cập nhật fast-forward từ `69ecdac`, `stage=RUNNING`, `hw=zero-a10g`).
- **Thiết kế mới**:
  - Thu gọn mặc định thành nút nổi gọn `#btn-graph-controls-toggle` (`Tùy chỉnh` + pill trạng thái `#graph-toolbar-status-pill` + chevron) ở góc trên trái và nút thao tác nhanh 1 chạm `#btn-graph-fit-quick` (`Căn giữa`) ở góc trên phải.
  - Khi mở ra, hiển thị bảng nổi kính mờ `#graph-controls-popover` (`width: min(316px, calc(100vw - 74px))`, `max-height: 376px`), gồm công tắc phân đoạn `Mạng lưới` / `Phân tầng`, 3 hàng công tắc gạt (`Tự gộp trang dài`, `Chỉ nhánh nguy hiểm`, `Độ nảy vật lý`) và chân trang (`Căn giữa`, `Mặc định` qua `resetGraphViewControls()`).
  - Tự thu gọn khi bấm ra ngoài, nhấn `Escape` (trả focus về nút mở) hoặc chuyển sang tab khác; hỗ trợ `prefers-reduced-motion: reduce`.
- **Xác minh DEV & Live read-only**:
  - DEV: `.\.venv-windows-dev\Scripts\python.exe -m pytest tests/test_web_app.py tests/test_onnx_production.py -q` đạt `18 passed`; Playwright trên `tests/fixtures/real_threat_document.pdf` ở `390x844` và `1440x900` đạt `0` console/page/request errors, `scrollWidth == innerWidth`, popover nằm trọn trong `#vis-stage-wrap` (`316x360`).
  - Live Space `https://drstone113-malpdfdetection.hf.space`: `GET /api/health` → `200` (`healthy`, `onnxruntime`, weights loaded); `GET /` → `200` (`313,946` bytes, SHA-256 `31bf2be471e2e495587e563c1e48f8070a91e3ac954554b00c9c16831b74f228`); `GET /assets/dashboard.css` → `200` (`35,606` bytes, SHA-256 `33e403b886237d0e1dbd08e3ca6a4337207b247aa443557eee3987d7c5e5e22c`); `GET /api/scans` → `200` (`no-store`).
