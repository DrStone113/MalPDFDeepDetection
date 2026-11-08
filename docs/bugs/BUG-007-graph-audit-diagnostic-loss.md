# BUG-007 — Lỗi profile bị gộp và projection rỗng thiếu ngữ cảnh

| Mục | Chi tiết |
| --- | --- |
| Ngày | 2026-11-02 |
| Trạng thái | UNDER_INVESTIGATION; hoàn thành audit, chưa sửa Extractor |
| Mức độ | HIGH |
| Phân loại | EVIDENCE_DIAGNOSTICS / GRAPH_PROVENANCE |
| Baseline | `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` |
| Audit | `reports/experiments/pdf_graph_audit/run_20261102T163322794619Z_dfafd888f7a9` |

## Triệu chứng đã xác minh

Projection mô hình có 75 mẫu không còn node, nhưng không thể suy ra rằng cả 75 PDF đều hỏng hoặc không thể tạo graph.

- 70 mẫu có `worker_admission_failed`, worker status worker_error, thiếu primary checkpoint và không còn originating stage. Nguyên nhân gốc chưa xác minh.
- 4 mẫu ghi nhận timeout; chưa đủ bằng chứng để xác định nguyên nhân gây chậm hoặc cần thay ngân sách nào.
- Index 141 có 13 native object observed với projection của MuPDF, nhưng kind parser_object nằm ngoài projection 9 loại node hiện tại. Audit xác nhận cơ chế lọc của view này; không tự chuyển inventory sang semantic graph mô hình.
- Index 749 có 433 candidate object nhưng không object nào có projection đọc thành công. Không được xem 433 candidate là 433 node hợp lệ.

Toàn bộ 1.452 bundle vẫn đúng schema và SHA/nhãn/split khóa. Không phát hiện duplicate node ID, duplicate edge ID, dangling edge hoặc kiểu thuộc tính sai trong phạm vi audit. Điều này không chứng nhận tính đúng ngữ nghĩa của PDF hay toàn bộ graph.

## Nguyên nhân và giới hạn kết luận

`extract_pdf` bắt `OSError`/`ValueError` quanh toàn bộ `profile_pdf` và thay kết quả bằng worker_admission_failed. Vì lời gọi bao gồm cả admission, vòng đời worker, IPC và phục hồi checkpoint, mã này không giữ được sự phân biệt nguyên nhân. Không có dữ liệu đủ để khẳng định 70 lỗi cụ thể phát sinh ở đâu.

Normalization giữ các native inventory/parser/forensic record riêng. Projection số chỉ giữ 9 loại node, các trạng thái đủ điều kiện và tối đa 200 node. Do đó projection rỗng không đồng nhất với evidence graph rỗng. 465 mẫu có thêm node đủ điều kiện bị loại bởi cap; tổng 274.506 node bị loại theo cap. Đây là phạm vi representation hiện hữu, chưa được kết luận là lỗi parser.

Builder legacy đọc details.size_bytes rồi mặc định 0 khi thiếu, trong khi bản xuất số hiện tại giữ null. Audit tìm được 8.619 span raw-forensic declaration đủ provenance trong evidence đầy đủ. Các span này không phải producer thay thế cho 171.055 kích thước node semantic projection còn thiếu.

## Các giai đoạn tiếp theo

Triển khai được tách thành [BUG-007A: Worker Diagnostic Preservation](BUG-007A-worker-diagnostic-preservation.md) và [BUG-007B: Extraction Recovery & Graph Truncation Analysis](BUG-007B-recovery-and-truncation-analysis.md). Phần dưới ghi lại đề xuất tại thời điểm audit; trạng thái triển khai và kiểm chứng mới được ghi trong từng hồ sơ con. 74 nguyên nhân gốc lịch sử vẫn chưa được xác minh.

## Đề xuất tại thời điểm audit

1. Giữ mã lỗi bounded theo tầng và originating stage/checkpoint khi lỗi đi qua profile boundary. Không xuất exception text tự do và không làm yếu isolation/cleanup.
2. Xác minh representation mong muốn trước khi mở rộng node kind hoặc fallback; giữ backend/revision riêng và phân biệt observed với candidate.
3. Tái sử dụng span đã lưu cho đúng physical declaration; xác định producer cho thuộc tính mô hình khác. Không gán kích thước JSON hoặc span object cha cho node khác.
4. Sau khi có diagnostic đủ thông tin, đề xuất chẩn đoán chọn lọc 74 index; index 141 ưu tiên kiểm tra evidence lưu sẵn. Audit này không queue hay chạy lại chúng.

## Bất biến và regression

- Generic worker failure và parser_error không đủ để chứng nhận corrupt PDF hoặc graph rỗng hợp lệ.
- Candidate, failed read, partial projection và observed object là các trạng thái khác nhau.
- Không gộp backend hoặc phiên bản đối tượng chỉ bằng object number. Cycle, shared reference và parallel edge hợp lệ không tự động bị xóa.
- Null không thành 0; kích thước byte nguồn không thành kích thước serialize hoặc ngược lại.
- Span phải có boundary/identity nhất quán giữa record và producer. `present` trong audit phải có hash và schema hợp lệ.

`tests/test_graph_audit.py` và `tests/test_graph_audit_job.py` bảo vệ công cụ audit trước các kết luận sai trên; chúng chưa chứng minh đã sửa nhánh lỗi của Extractor. Kiểm thử tập trung: Windows 77 passed/1 skipped do quyền symlink; REMnux 78 passed/0 skipped. Full suite Windows còn đúng 200 failed case của baseline, không phát sinh failed case mới trong lần đối chiếu.
