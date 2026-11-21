# Tiến trình trợ lý AI trên web — 2026-11-20

Thay dòng chờ chung bằng nhật ký có thể mở lại trong từng câu trả lời. Dòng hoàn thành xuất hiện dựa trên hồ sơ đã nhận, bản tóm tắt bằng chứng, báo cáo làm sạch nếu có, các kiểm tra thiết bị và sự kiện thực tế của luồng Cloud AI. Khi đang nhận nội dung, số ký tự được cập nhật cùng lần vẽ phần trả lời. Dòng hoàn tất ghi rõ Cloud AI, mô hình trên máy hoặc câu trả lời từ hồ sơ.

Luồng bị ngắt giữ phần đã hiển thị, báo nguyên nhân phù hợp và cho phép gửi lại. Nếu Cloud AI chưa gửi nội dung, trợ lý có thể chuyển sang câu trả lời lấy từ hồ sơ. Đổi lượt quét hủy yêu cầu trước. Cuộn theo tiến trình chỉ khi người dùng đang theo dõi cuối khung. Hiệu ứng nhẹ tự tắt khi hệ thống bật giảm chuyển động.

Client dùng endpoint Cloud cùng origin, bỏ khóa nhúng trong HTML DEV. Backend DEV có thể trả theo hồ sơ khi chưa có luồng Cloud. Bản ONNX trên Space giữ backend SSE hiện hữu.

Kịch bản [Playwright](../../scripts/verify_web_chat_activity.cjs) dùng PDF đã rà soát và hồ sơ/CDR thật. Sự kiện luồng Cloud được điều khiển riêng trong bài kiểm thử để kiểm chứng kết nối, nhận nội dung từng phần, hoàn tất, mất luồng, dự phòng, đổi lượt quét và reduced motion ở 1365 px và 390 px. Bằng chứng hình ảnh cục bộ ở `artifacts/chat-activity-proof/`. Không gọi nhà cung cấp Cloud trong bài kiểm thử.

Kiểm tra trình duyệt đạt trên DEV và bản ONNX cục bộ. Pytest toàn bộ Windows đạt 2140, lỗi 183, bỏ qua 33. So với baseline của đợt trước, cùng 183 tên ca lỗi và không có ca mới. REMnux SSH timeout.

[Hugging Face Space](https://drstone113-malpdfdetection.hf.space) đã ở trạng thái `RUNNING` với commit `c64d3a3aed8963c420a693276ca1a8357490277d`, cập nhật fast-forward từ `7035b78`. Kiểm tra live xác nhận `/api/health` trả 200 và ONNX đã tải, HTML và CSS khớp byte với commit. Chưa gửi câu hỏi thật qua Cloud AI trong lượt xác minh phát hành.
