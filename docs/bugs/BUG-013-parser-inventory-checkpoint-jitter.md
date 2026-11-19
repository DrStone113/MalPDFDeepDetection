# BUG-013 — Parser inventory rollback phụ thuộc nhịp IPC

| Mục | Chi tiết |
| --- | --- |
| Ngày ghi nhận | 2026-11-19 |
| Trạng thái | Đã sửa mã, chờ đối chiếu pilot offline |
| Mức độ | HIGH |
| Thành phần | `parser_views.py`, `bulk_recovery.py`, `lab_runner.py` |

## Triệu chứng và nguyên nhân

Pilot `9297f95` đối chiếu 128 mẫu. Ba mẫu `bounded_complete` tại index 5, 509, 3486 lệch đúng −6 ở `excluded_feature_count`. Feature xuất ra, graph, metadata và Markov khớp ở cả ba mẫu. Pilot chặn bulk và giữ nguyên tám chunk. [Báo cáo phiên đầu](../../reports/progress/bulk_extractor_recovery_2026-11-19.md)

Parser inventory trước đây kiểm tra cap kích thước JSON và lưu bản rollback sau khi scheduler cho phép gửi IPC. Khi hai đồng hồ đi qua các thời điểm khác nhau, cùng giới hạn có thể giữ lại tập backend khác nhau. Mỗi view đóng góp sáu feature inventory ngoài allowlist. Regression test tái hiện chênh lệch đó trên PDF lành tính với hai đồng hồ và cùng cap.

## Bất biến hồi quy

- Kiểm tra giới hạn trước khi nhận từng thay đổi. Tính kích thước JSON compact theo phần tử mảng mới và header thay đổi. Giữ prefix vừa với cap và phần dự phòng 512 byte cho metadata kết thúc. Đồng hồ chỉ điều khiển nhịp gửi checkpoint IPC.
- Trong pilot, báo riêng `bounded_inventory_excluded_count` cùng hai giá trị trước/sau. Chỉ chấp nhận ±6 hoặc ±12 ở mẫu `bounded_complete` với tín hiệu `inventory_metadata_limit`, cleanup và kết quả đã xác minh. Mọi trường tabular còn lại và mọi artifact khác phải khớp chính xác. Giữ chặn bulk khi còn sai khác chưa giải thích được.
- `test_extraction_performance.py` kiểm inventory, feature và nhịp IPC ở hai đồng hồ. `test_bulk_recovery.py` kiểm bốn delta hợp lệ cùng các sai khác feature, status, artifact, delta và bằng chứng.

## Phạm vi còn lại

`raw_forensic.py` và `carving.py` cũng có đường coalesce checkpoint cần đánh giá riêng dưới cap. Đợt này giữ nguyên cadence của hai stage. Hồi quy tương lai cần đối chiếu cả `verified_physical_span_bytes` và provenance với các chunk đã chốt.
