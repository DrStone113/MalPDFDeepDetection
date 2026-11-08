# BUG-006 — Shard dừng sớm nhưng console vẫn báo hoàn tất thành công

## Thông tin chung

| Mục | Chi tiết |
| --- | --- |
| Ngày | 2026-11-02 |
| Trạng thái | MITIGATED; nguyên nhân kernel làm chậm cleanup chưa được xác minh |
| Mức độ | HIGH |
| Phân loại | EVIDENCE_INTEGRITY / WORKER_LIFECYCLE |
| Thành phần | `scripts/lab/lab_jobs.py`, `scripts/lab/lab_runner.py`, xuất dữ liệu sau chạy |
| Job bằng chứng | `4cec6c2794967311bc5c55a924933a0b0cbda0529ff31fe1f19de8b4cdcd7b75` |

## Triệu chứng và tái hiện

Job thực chạy tại REMnux lưu 1.380/1.452 bundle. Shard 4 dừng ở index 724 với `worker_cleanup_complete=false`; 72 index từ 734 đến 1444, bước 10, chưa có bundle. Kết quả JSON gốc ghi `partial`, nhưng banner console cũ được in trước khi đọc mã thoát và gộp summary, luôn dùng `COMPLETED SUCCESSFULLY`. File JSON lỗi hoặc thiếu status cũng có thể bị hiển thị bằng dấu hoàn tất.

Tái hiện an toàn: cấp các checkpoint JSON đã qua hợp đồng cho 72 index trước 724, sau đó cho boundary extractor trả bundle có cleanup false. Kiểm thử khẳng định worker giữ cờ false, dừng trước 734 và ghi nguyên nhân có cấu trúc. Không đọc PDF trong kiểm thử này.

## Nguyên nhân gốc

1. Console dùng việc kết thúc vòng theo dõi làm tín hiệu thành công.
2. Summary và mã thoát được kiểm tra sau khi banner đã in.
3. Nhánh dừng an toàn không lưu nguyên nhân riêng theo shard.
4. Luồng resume chỉ kiểm tra status của checkpoint, thiếu đối chiếu SHA, hợp đồng bundle và cờ cleanup.
5. Thiếu regression nối vòng đời worker, trạng thái lưu trên đĩa và thông báo cho người vận hành.

Điểm dừng cleanup được xác minh từ metadata lưu sẵn và đường chạy nguồn. Chưa có bằng chứng đủ để kết luận lỗi kernel, OOM hoặc loại PDF cụ thể. Không tăng timeout tùy tiện và không bỏ điều kiện dừng.

## Thay đổi

- Chỉ in banner sau khi kiểm tra mã thoát và summary. Hiển thị mẫu đã xử lý, mẫu còn thiếu và shard đã dừng; các bundle partial/unsupported không được chứng nhận thành công.
- Lưu `pdf_halt.<shard>.json` bất biến với job, shard, index và một reason thuộc enum. Halt vẫn ngăn trạng thái `passed` kể cả khi các bộ đếm trông đầy đủ.
- Chỉ tái sử dụng bundle đúng SHA-256, qua `validate_bundle`, cleanup bằng đúng boolean true. Bundle gốc và kết quả lịch sử không bị sửa.
- Xuất số liệu bằng danh sách hữu hạn tên feature được duyệt; chặn tên chứa văn bản nguồn. Giá trị thiếu là null; không dựng node 0. Đồ thị có thuộc tính chưa biết không được đưa thẳng vào mô hình.
- Chỉ đọc JSON đã lưu tại LAB. Windows nhận schema số đóng, SHA, split và nhãn đã đối chiếu; không nhận nội dung PDF, script, evidence ID hoặc exception text.

## Bất biến chống hồi quy

1. Số mẫu đã xử lý không đồng nghĩa số mẫu trích xuất đầy đủ, càng không phải số mẫu được phân loại đúng.
2. Không xác nhận thành công khi thiếu mẫu, shard đã halt hoặc summary chưa hợp lệ.
3. Không đổi `worker_cleanup_complete=false` thành true để cho phép tiếp tục.
4. Không dùng lại bundle khác SHA hoặc sai schema; không điền 0 vào dữ liệu chưa đo.
5. Lần chạy tiếp theo cần job mới, ghi rõ nguồn bundle tái sử dụng và giữ human gate `lab run`.
6. Kết quả export phải giữ đủ mẫu số, kể cả missing/invalid, và giữ nguyên split gốc.

## Kiểm chứng

`tests/test_lab_halt_reporting.py`, `tests/test_numeric_postrun_export.py` và `tests/test_numeric_export_job.py` bảo vệ các ranh giới trên bằng JSON và fixture cấu trúc. Chạy rộng hơn với `tests/test_cic_full_cohort.py` và `tests/test_runtime_evidence.py`: 107 passed trên Windows DEV. Kết quả kiểm thử LAB và export thật được ghi riêng trong báo cáo sau chạy; không suy diễn thành độ chính xác phân loại malware.


## Đối chiếu sau lần chạy tiếp tục — 2026-11-02

Job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` do operator kích hoạt đã lưu 1.452/1.452 bundle, không halt và không còn job pending. Đối chiếu xác nhận 1.379 bundle giữ đúng hash, 73 bundle được xử lý mới; index 724 có cleanup true. Toàn bộ 1.452 worker metadata đều cleanup true. Trạng thái job vẫn partial theo kết quả trích xuất, không bị nâng thành passed. Nguyên nhân kernel lần dừng trước vẫn chưa được kết luận. [Báo cáo sau chạy](../../reports/progress/runtime_data_recovery_postrun_2026-11-02.md).
