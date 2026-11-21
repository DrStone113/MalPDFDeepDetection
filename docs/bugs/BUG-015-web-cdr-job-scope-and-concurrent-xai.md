# BUG-015 — Phản hồi CDR lệch lượt quét và tranh chấp XAI

Ngày ghi nhận 2026-11-20. Phân loại `WEB_JOB_LIFECYCLE / CONCURRENCY`. Hai lỗi thuộc luồng làm sạch trên web.

## Triệu chứng và nguyên nhân

1. Nút làm sạch nhận được lần bấm khác trong khi yêu cầu trước đang chạy. Phản hồi của A có thể cập nhật thẻ của B nếu người dùng chọn tệp mới.
2. Giao diện lấy kết quả bằng trạng thái toàn cục thay đổi theo thời gian và không đối chiếu ID nhận về. Preview cũng có thể hoàn tất sai thứ tự khi đổi trang nhanh.
3. Ca kiểm thử giữ phản hồi CDR A và quét B đồng thời còn ghi nhận HTTP 500 từ `MalPDFScannerEngine._compute_xai_signals` với `float() argument must be a string or a real number, not 'list'`.
4. Đường suy luận DEV dùng chung một mô hình. Các encoder giữ bộ nhớ chú ý từ lượt forward cuối. Forward theo lô của một yêu cầu có thể ghi đè tensor trước khi yêu cầu khác đọc để giải thích.
5. Kiểm thử API tuần tự chưa đi qua hai request này cùng lúc. Việc lưu trạng thái DISARMED trước quét lại cũng có thể khiến lần đọc trạng thái thấy một kết quả chưa hoàn tất.

## Giải pháp và bất biến

- Gắn CDR và bản tải xuống với ID đã xác nhận, chống bấm lặp trong phiên. Đối soát trạng thái khi mất phản hồi. Khi đổi tệp, bỏ phản hồi preview cũ và chỉ cập nhật ảnh từ đúng lượt quét, trang và phiên bản bản sạch.
- Giữ bộ nhớ chú ý của PyTorch trong vùng được khoá trong lúc tính XAI. Mọi đường forward từ scanner dùng cùng khoá. Đọc PDF và nghiệp vụ CDR vẫn nằm ngoài vùng khoá.
- Chỉ công bố bản sạch khi tẩy độc và quét lại đã trả kết quả. Lưu tiêu chí hậu kiểm cùng audit để lần mở lại hoặc đối soát trả đúng bằng chứng.
- Chế độ audit gọn giữ số liệu preview và bỏ ảnh base64 trùng. API mặc định giữ schema và dữ liệu cũ cho caller hiện có. Trả tên tệp tải xuống tiếng Việt bằng `filename*` UTF-8.
- Lỗi preview có thao tác tải lại riêng. Trạng thái đã làm sạch không bị đổi chỉ vì mất ảnh.

## Kiểm thử hồi quy

`scripts/verify_web_job_state.cjs` dùng cùng một fixture PDF có nội dung đã rà soát, gán tên A/B riêng và gọi API thật. Playwright điều khiển thứ tự nhận phản hồi, gây mất xác nhận sau khi backend hoàn tất, gây lỗi preview và tạo lượt quét hết hiệu lực. Script kiểm tra ID của tệp tải xuống, tên Unicode, phím điều hướng slider và tuỳ chọn cục bộ khi trình duyệt chặn storage. Baseline ban đầu thất bại ở điều kiện nút phải bị vô hiệu hoá. Sau khi sửa UI, lần kiểm tra trước khóa mô hình còn ghi nhận lỗi HTTP 500. Phiên bản cuối đã qua kịch bản trên DEV và entrypoint ONNX cục bộ.
