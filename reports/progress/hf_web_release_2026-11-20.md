# Phát hành bản web lên Hugging Face — 2026-11-20

[Space MalPDF](https://huggingface.co/spaces/DrStone113/malpdfdetection) đã ở trạng thái `RUNNING`, domain `READY`. Git main và runtime đều ở [`7035b78`](https://huggingface.co/spaces/DrStone113/malpdfdetection/commit/7035b7849cd9fc5a3515da8d9c5944517f9ac828). Commit trước là `87b44aa3f3105a3aba3b2c07ff971dbc687c0e7f`.

- Ghép 11 tệp web/CDR lên đầu nhánh Space hiện có. Bảo toàn ONNX, cấu hình, hardware và các mô-đun phiên và Cloud AI trên Space. Template tiếp tục gọi Cloud AI qua endpoint cùng origin với SSE phía máy chủ. Không dùng kịch bản đóng gói toàn bộ để thay thế các tệp riêng của Space.
- Bản ghép ONNX chạy cục bộ qua kịch bản Chromium với fixture đã rà soát, gồm phục hồi khi mất phản hồi CDR, retry preview, đổi trang, tải tên Unicode và tuỳ chọn trình duyệt. Hai phiên khác nhau gọi đúng cùng ID cho kết quả truy cập 404 từ phiên không sở hữu. POST từ origin khác bị từ chối 403.
- Kiểm tra live `/api/health` trả HTTP 200, `healthy`, mô hình ONNX đã tải. HTML, CSS và thư viện sơ đồ trả HTTP 200 và khớp SHA-256 với gói phát hành. `/api/scans` trả 200 và `Cache-Control: no-store`. Smoke live chỉ đọc; không tải fixture hoặc tài liệu người dùng lên Space.
- Kiểm tra 11 tệp trước khi đẩy, giới hạn phạm vi thư mục web/CDR. Phát hiện khóa Cloud AI cũ trong HTML DEV và xác nhận bản phát hành không chứa khóa. Xác minh model ONNX cục bộ với hash Git LFS của phiên bản trước; không thay LFS pointer trên Space.

Bản ghép được giữ trong `artifacts/hf-web-release-20261120`. Nếu cần hoàn tác, tạo commit revert `7035b78` trên checkout sạch từ Space và đợi runtime chuyển sang commit hoàn tác. Giữ nhánh chính fast-forward.
