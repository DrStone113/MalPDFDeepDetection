# Audit PDF Extractor và graph — 2026-11-02

Đã thực hiện audit nguồn và **1.452 bundle JSON lưu sẵn** của job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f`. Công cụ mới chỉ bổ sung phân tích; tất cả file nguồn đã tồn tại trong release Extractor baseline giữ nguyên hash. Không đọc/chạy lại PDF, sửa Extractor, thay API ứng dụng, queue job hay huấn luyện mô hình.

## Phân loại 75 projection rỗng

| Nhóm bằng chứng | Số mẫu | Kết luận có thể đưa ra |
| --- | ---: | --- |
| worker_admission_failed bị gộp | 70 | Chưa biết tầng phát sinh; không kết luận PDF hỏng |
| Timeout đã ghi nhận | 4 | Biết cơ chế timeout; chưa xác minh nguyên nhân gốc |
| Object observed nằm ngoài projection | 1 | Index 141: 13 object MuPDF observed, bị loại bởi view hiện tại |

Tổng **74 nguyên nhân gốc còn unresolved** và **1 cơ chế lọc projection đã xác minh**. Cơ chế lọc của một view không chứng nhận toàn bộ PDF hoặc mọi graph khác đều hợp lệ. Không có trường hợp nào được tự gắn nhãn corrupt hoặc valid-empty chỉ vì parser lỗi.

Index 749 có 433 candidate nhưng không có projection object đọc thành công. Candidate count không được biến thành node thành công. Các backend inventory và graph được báo riêng; QPDF inventory không được trình bày thành graph QPDF.

## Độ phủ và cấu trúc

| Phép đo | Kết quả |
| --- | ---: |
| Bundle đúng schema/checksum/nhãn/split | 1.452 |
| Projection có node | 1.377 |
| Projection rỗng | 75 (5,17%) |
| Evidence record đầy đủ | 1.187.743 |
| Evidence edge đầy đủ | 1.426.870 |
| Node giữ trong projection | 171.055 |
| Edge giữ trong projection | 95.162 |
| Mẫu có node bị cắt bởi cap 200 | 465 |
| Node đủ điều kiện bị loại theo cap | 274.506 |
| Node bị loại theo kind | 741.942 |
| Node bị loại theo observation status | 240 |
| Duplicate node/edge ID, dangling edge, invalid attribute | 0 trong mỗi nhóm |

1.331.708 edge không nằm trong projection vì endpoint không được giữ. Đây là chênh lệch giữa representation evidence và representation mô hình, không phải bằng chứng từng cạnh đều bị mất do parser. Không tự động xóa cycle, shared reference, đa cạnh hoặc gộp các backend để thay đổi số liệu.

## Hai phép đo kích thước

**Byte đối tượng gốc:** có **8.619 declaration** đủ provenance để đo interval từ header đối tượng gián tiếp đến hết token endobj. Min 16 byte; median 136; p95 25513; max 1147740. Tổng span 40477710 byte không được gọi là độ phủ tệp vì phạm vi có thể chồng nhau.

Các record khác được phân loại rõ: 1.177.888 không áp dụng phép đo physical declaration; 832 ở không gian decoded/object stream; 404 chưa xác minh boundary/provenance. Không có span được gán 0 để thay null. Các span đo được thuộc đúng raw-forensic declaration; **171.055 node của projection vẫn thiếu legacy size_bytes**, không được tự backfill qua object number hay backend khác.

**Dung lượng serialize:** đo byte JSON UTF-8 canonical của mỗi node và graph (nodes+edges), tách khỏi byte nguồn, RSS và kích thước tệp gzip. Chiều feature thực giữ null vì chưa materialize tensor; 19 chỉ là target metadata của builder cũ. Không chọn storage cost làm predictor.

## Ưu tiên sửa cho đợt sau

1. Bảo toàn error enum, originating stage và checkpoint tại profile boundary. Nhánh bắt OSError/ValueError hiện không đủ ngữ cảnh để giải thích 70 lỗi worker; chưa có cơ sở chọn parser mới hoặc tăng timeout.
2. Kiểm tra evidence của index 141 trước khi đụng PDF. Chốt view graph có version, semantics của node/edge, giới hạn 200 và provenance backend/revision trước khi mở rộng projection.
3. Tái sử dụng span đã lưu cho đúng declaration. Xác định producer cho kích thước node semantic; không thay nó bằng dung lượng JSON.
4. Sau khi diagnostic được cải thiện, đề xuất chẩn đoán offline cho **74 index**, giữ nguyên source SHA/nhãn/split. Danh sách nằm trong metrics.json; **chưa có job nào được queue**.
5. Validation toàn bộ 1.452 mẫu và chính sách unavailable rõ ràng phải đi trước một quyết định huấn luyện. `model_input_ready=false`; không có Accuracy/F1/MCC/AUC mới.

Một điểm cần làm rõ trong đợt resource/lifecycle tiếp theo: tổng bundle hiện có 2232473959 byte, trong khi manifest khai báo output_bytes=2147483648. Nhánh worker kiểm tra phần ghi mới theo shard và bỏ qua cache dùng lại khi cộng total. Cần chốt phạm vi budget của job và artifact tái sử dụng; audit không gán đây là nguyên nhân của 70 lỗi trước đó và không xóa dữ liệu để làm khớp cap.

## Kiểm chứng và bảo toàn

- Windows: **77 passed, 1 skipped** trong kiểm thử audit cuối; skip do quyền tạo symlink. REMnux: **78 passed, 0 skipped**.
- Full Windows: **1976 passed, 200 failed, 22 skipped** trên 2198 test. Tập 200 failed case khớp baseline hoàn toàn; 0 failed case mới. Các lỗi baseline không được tắt hoặc sửa ngoài phạm vi.
- Mỗi case đã qua validator đóng và đối chiếu index nguồn. Báo cáo Markdown được dựng lại tại Windows từ số liệu đã kiểm tra và khớp checksum của bản LAB; không tải raw report/log tùy ý.
- 369 tệp Python qua AST, 0 Python comments. Content guard kiểm tra 2.239 tệp index qua. HEAD repo chính giữ nguyên; snapshot audit có commit riêng chỉ để truy vết package.
- Job, result, selection và 1.452 bundle baseline giữ nguyên; không có job pending sau audit. PDF/payload/script/nội dung tài liệu ở lại LAB.

Công cụ: [`audit_graph_extraction.py`](../../scripts/lab/audit_graph_extraction.py). Hợp đồng và cách sử dụng: [`graph_extraction_audit.md`](../../docs/graph_extraction_audit.md). Hồ sơ lỗi: [BUG-007](../../docs/bugs/BUG-007-graph-audit-diagnostic-loss.md).

Báo cáo chi tiết: [`audit_report.md`](../experiments/pdf_graph_audit/run_20261102T163322794619Z_dfafd888f7a9/audit_report.md), [`cases.jsonl`](../experiments/pdf_graph_audit/run_20261102T163322794619Z_dfafd888f7a9/cases.jsonl), [`metrics.json`](../experiments/pdf_graph_audit/run_20261102T163322794619Z_dfafd888f7a9/metrics.json), [`locked_methodology.json`](../experiments/pdf_graph_audit/run_20261102T163322794619Z_dfafd888f7a9/locked_methodology.json).
