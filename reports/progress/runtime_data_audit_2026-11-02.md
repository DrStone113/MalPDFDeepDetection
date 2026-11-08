# Rà soát dữ liệu và bằng chứng chạy thực tế — 2026-11-02

## Kết quả đã xác minh

- Gỡ endpoint fixture/demo và email mô phỏng khỏi runtime; bộ nạp fixture không tự tạo PDF. CLI gateway chỉ đọc EML được cung cấp.
- Xóa 57 PDF thuộc các kịch bản email/fixture đã xác định và 2 hình XAI được tạo bằng đầu vào ngẫu nhiên. `data/quarantine/` không còn tệp từ các kịch bản này.
- Bỏ địa chỉ byte, hex, attention, ma trận ghép cặp và kết luận khai thác/an toàn viết sẵn. Giao diện thể hiện unavailable khi chưa đo; lịch sử email lấy từ email thực sự tải lên.
- Chặn checkpoint/scaler thiếu hoặc hỏng. Đặc trưng scanner chưa khớp với hợp đồng huấn luyện nên xác suất và OOD là null; gateway giữ tài liệu để xem xét, không cho qua như clean.
- Cache hiện có 1.452 SHA nhưng chỉ có 1.314 đồ thị thật. 138 đồ thị thiếu: 85 train, 27 validation, 26 test. Ba loader huấn luyện/đánh giá đã bỏ node toàn zero dùng để lấp thiếu. Gọi loader với dữ liệu hiện tại bị chặn trước huấn luyện.
- CDR dùng byte gốc, xử lý cả hành động trực tiếp lồng trong `/A/Next`, đối chiếu trang, Contents, Resources và văn bản chính xác. Mẫu active-action đã duyệt giữ 99,84% dung lượng, 2/2 trang và 9.839 ký tự khớp; đây là kiểm thử fixture, không phải hiệu quả trên malware thực tế.
- Xóa 298 comment Python trong 104 tệp để tuân thủ AGENTS; AST thực thi trước/sau giống nhau. Các thay đổi sẵn có của người dùng được giữ lại.

## Bằng chứng và giới hạn kiểm chứng

| Phạm vi | Kết quả |
| --- | --- |
| Kiểm thử scanner/CDR/gateway/API và hồi quy mới, Python DEV chuyên dụng | 57 passed |
| Bộ kiểm thử đầy đủ Windows, Python DEV chuyên dụng | 1.830 passed, 200 failed, 21 skipped |
| Bộ kiểm thử đầy đủ REMnux, bản sao kiểm thử riêng từ snapshot đã xác minh | 2.022 passed, 26 failed, 3 skipped |
| Trình duyệt Chromium thực, tải fixture qua API và chạy CDR, mail history rỗng, SIEM | Không có page error hoặc console error trong lượt đã ghi nhận |
| Guard nội dung Git index | Passed, 2.239 tệp |
| Guard toàn worktree | Bị chặn bởi 3 PNG tham khảo đã tồn tại trong `UI_Example/`; chúng không được đưa vào gói triển khai |
| `git diff --check` | Passed |
| Phán quyết ML và hiệu năng phát hiện trên malware thật | Chưa được xác minh; không có số liệu accuracy/F1 mới |

Không được xem 26 kiểm thử LAB còn lỗi là đã xử lý; chưa phân loại đầy đủ nguyên nhân. Thành công của các kiểm thử tập trung và của CDR trên fixture không đồng nghĩa toàn dự án đã đạt mọi kiểm tra.

Các chỉ số PDF-TransGraph và hình XAI trong báo cáo cũ không được tái sử dụng như bằng chứng hiệu năng hiện hành. Đồ thị giả đã bị chặn; cần hoàn thiện dữ liệu và hợp đồng đặc trưng rồi huấn luyện/đánh giá lại trong lần chạy mới. Các bản ghi lịch sử được giữ nguyên và điều chỉnh phương pháp được ghi bổ sung.

## Gói và job REMnux

- Base commit: `c6b920385d966eaba9f0e1eec0ac2dcb789a4664`; Windows worktree chưa commit.
- Snapshot: `edfcfeb51ab51fc716999acfb28c03c4d0ec14bafac006a125e9e17c290855a6`, 397 tệp text được kiểm tra nội dung; không có PDF malware hay bí mật trong gói mã.
- Manifest SHA-256: `e4a9a1ce4f34f1aabc1dced5dcd027295ee6a73469f7f10c749079c7ff8f14fb`.
- Archive SHA-256: `bffb3ef0a3f5ffa12776bba3fc5594ae62a20a86541f803b120ece9015e2b253`.
- Release: `/home/remnux/malpdf-releases/c6b920385d966eaba9f0e1eec0ac2dcb789a4664`.
- Helper `lab_side.py` đã được đồng bộ từ bản Windows đã kiểm tra hash, có backup, không đổi SSHD hay chính sách runtime.
- Job: `4cec6c2794967311bc5c55a924933a0b0cbda0529ff31fe1f19de8b4cdcd7b75`.
- Loại: `pdf-static-cic-full`, 1.452 mẫu, seed 42, 870 train / 291 validation / 291 test, 10 worker; tối đa 35 giây/file, 30 giây CPU/file, 1 GiB/file, 7.200 giây/job, 2 GiB output.
- Agent đã xác minh trạng thái `queued`. Người dùng sau đó tự thao tác cô lập và kích hoạt `lab run`; ảnh console người dùng gửi cho thấy job bắt đầu và đã hoàn tất 10/1.452 mẫu.
- Agent không ngắt NIC hoặc sửa shared folders. Không thực hiện kết nối lại hoặc thay đổi release đang chạy sau khi người dùng chuyển sang console offline.

`bounded_complete`, `partial`, `unsupported` là trạng thái trích xuất. Chúng không phải nhãn malware/benign, và không được biến dữ liệu thiếu thành số zero hoặc lược bỏ khỏi mẫu số.

## Chứng cứ trên Windows

- Lần đo bất biến: `reports/experiments/runtime_data_audit/run_20261102T125104715255Z_c6b920385d96/locked_methodology.json` và `metrics.json`.
- Receipt, checksum triển khai, kết quả kiểm thử, danh sách tệp demo đã xóa, ảnh/DOM trình duyệt: `artifacts/tmp/runtime_audit/`.
- Hồ sơ lỗi và bất biến: `docs/bugs/BUG-005-fabricated-runtime-evidence.md`.

## Việc tiếp theo sau khi job kết thúc

Thu thập trạng thái và chỉ số có cấu trúc theo quy tắc xuất dữ liệu của LAB; không chuyển PDF, script trích xuất hoặc bundle thô về Windows. Đối chiếu đủ 1.452 mẫu, lý do missing/unsupported/timeout và hash từng nguồn trước khi tạo cache đồ thị mới. Chỉ tiếp tục huấn luyện khi có dữ liệu đo thật đầy đủ và hợp đồng train/inference đã được xác minh; không cam kết rằng chạy lại sẽ tự khắc phục toàn bộ 138 đồ thị thiếu.
