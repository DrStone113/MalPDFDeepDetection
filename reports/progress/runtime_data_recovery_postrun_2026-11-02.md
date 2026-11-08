# Kết quả job tiếp tục sau chạy thật — 2026-11-02

Job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` kết thúc lúc `2026-11-02T15:30:08Z`. Đã xử lý **1.452/1.452 mẫu**, không còn mẫu thiếu, không có halt marker và không còn job pending. Trạng thái của runner vẫn là **partial** vì các kết quả trích xuất bên dưới chưa phải đều hoàn chỉnh.

## Kết quả trích xuất đã xác minh

| Trạng thái bundle | Số mẫu |
| --- | ---: |
| bounded_complete | 326 |
| observed | 1 |
| partial | 143 |
| timeout | 589 |
| unsupported | 342 |
| decode_error | 51 |
| Tổng | 1452 |

Có **1.381 primary checkpoint**. Theo nhóm của runner: 327 observed/bounded_complete, 143 partial, 982 failed/unsupported. Các trạng thái này mô tả trích xuất theo phạm vi; không phải phán quyết benign/malicious và không phải độ chính xác mô hình.

## Đối chiếu job gốc và lần tiếp tục

- 1.379 bundle tái sử dụng khớp SHA-256 của nội dung gốc; không đổi nhãn, split hoặc SHA của mẫu.
- 72 vị trí thiếu đã có bundle mới; index 724 được thay bằng lần trích xuất mới. Đối chiếu xác nhận đúng 73 bundle mới, không có thay đổi bất ngờ ngoài tập này.
- Riêng 73 bundle mới: 43 bounded_complete, 4 partial, 2 timeout, 21 unsupported, 3 decode_error.
- Index 724 vẫn có trạng thái `unsupported` nhưng `worker_cleanup_complete=true`. Cả 1.452 bundle đều xác nhận cleanup bằng đúng boolean true. Vấn đề dừng sớm lần trước không tái diễn trong lần này; chưa kết luận nguyên nhân kernel đã được xử lý triệt để.
- Job gốc vẫn giữ nguyên 1.380 bundle và checksum kết quả. Source release và hash helper của job tiếp tục đã được kiểm tra.

Summary ghi elapsed **809.713 ms** (13 phút 29,713 giây), peak RSS **400.019.456 byte** cho lần tiếp tục. Do 1.379 bundle dùng lại từ lần trước, không được coi đây là thời gian trích xuất mới toàn bộ 1.452 PDF.

## Dữ liệu số thật đã lưu tại DEV

Dataset mới: `data/processed/runtime_postrun/dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f/a07a82e079974a0e9e7dff2a796d680a311967ff9fc41f3384daef4f704068cd`.

`numeric.jsonl.gz` chứa 1.452 record có dữ liệu; `manifest.json`, `coverage.json` và `record_index.json` lưu checksum, phạm vi và nguồn từng bundle. Toàn bộ record đã qua schema số đóng và đối chiếu manifest gốc có checksum. Split giữ nguyên **870 train / 291 validation / 291 test**, seed **42**. Không fit scaler, thay nhãn, chia lại tập hay đánh giá classifier.

Windows không nhận PDF, script, payload, shellcode hoặc nội dung tài liệu. Các giá trị chưa đo vẫn null. Cache, checkpoint và kết quả thí nghiệm cũ được giữ nguyên; dataset mới không ghi đè chúng.

## Điều kiện huấn luyện còn thiếu

Có **1.377 mẫu với đồ thị quan sát được**; **75 mẫu chưa có node đồ thị thuộc schema đang xuất**. 171.055 node được xuất đều có kích thước chưa biết: **0 kích thước node hợp lệ**, **171.055 null**. Vì vậy cả 1.377 đồ thị đều còn thiếu thuộc tính kích thước.

Đây là kết quả đo phạm vi hiện có, không được biến thành đồ thị giả hoặc node kích thước 0. Hợp đồng node feature 19 chiều của pipeline huấn luyện cũ chưa được xác minh trên dataset này; dữ liệu mới giữ `model_input_ready=false`. Chưa huấn luyện lại, chưa suy luận classifier và không phát sinh Accuracy/F1/MCC/AUC mới. Cần hoàn thiện hợp đồng đặc trưng và xử lý thiếu dữ liệu có phương pháp trước khi huấn luyện; chạy lại nguyên job với cùng mã nguồn không phải bằng chứng rằng các thuộc tính đã được bổ sung.

## Kiểm chứng và hồ sơ

- Kiểm tra trực tiếp trạng thái job, 1.452 bundle, 0 halt, 0 pending; hash release/helper đúng manifest.
- Trình xuất trên LAB chỉ đọc JSON đã lưu; trình nhận DEV kiểm tra mọi record, kích thước, checksum, giá trị hữu hạn, tên feature hữu hạn và SHA/nhãn/split.
- Đối chiếu đủ 1.379 bundle dùng lại và 73 bundle mới; xác minh checksum kết quả job gốc không đổi.
- 365 tệp Python qua AST, 0 Python comments; `git diff --check` qua. Không sửa mã sản phẩm trong lượt này nên không chạy lại pytest. Các kết quả 107/107 ban đầu và 79/79 sau sửa manifest thuộc lượt kiểm thử trước, không được trình bày thành kiểm thử mới.
- Không thay NIC/shared folders, không chạy parser trên PDF thật từ SSH và không queue thêm job. Restricted gateway có policy mismatch đã ghi ở lượt trước; lượt này chỉ kiểm tra source/helper của offline console runner, không công bố gateway hay full suite đã sẵn sàng.

Hồ sơ bất biến: [`locked_methodology.json`](../experiments/runtime_data_postrun/run_20261102T153739818896Z_dfafd888f7a9/locked_methodology.json), [`metrics.json`](../experiments/runtime_data_postrun/run_20261102T153739818896Z_dfafd888f7a9/metrics.json), [`recovery_comparison.json`](../experiments/runtime_data_postrun/run_20261102T153739818896Z_dfafd888f7a9/recovery_comparison.json), [`final_lab_verification.json`](../experiments/runtime_data_postrun/run_20261102T153739818896Z_dfafd888f7a9/final_lab_verification.json).
