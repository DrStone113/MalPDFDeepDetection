# BUG-007A — Worker Diagnostic Preservation — 2026-11-03

Đã triển khai diagnostic cho vòng đời PDF worker và kiểm chứng bằng tiến trình thật trên Windows/REMnux. Đây là cải thiện khả năng chẩn đoán; chưa chạy lại 74 PDF lịch sử hoặc xác định nguyên nhân gốc của chúng.

## Thay đổi

- `coverage_report.worker.diagnostic` giữ sample/run/entry point, exception type/errno, traceback có cấu trúc, stderr có giới hạn, elapsed, phase, checkpoint, timeout và tài nguyên đo được.
- Diagnostic được ghi nhận trước cleanup; exit code trước cleanup được giữ riêng với exit code sau cleanup. Fallback tại profile boundary không còn tự khẳng định cleanup thành công khi chưa đo được.
- Worker gửi diagnostic qua JSON byte channel riêng. Traceback không có exception message, source hoặc locals. Stderr giữ tối đa 16 KiB byte đầu trong private LAB bundle, có cờ giới hạn và độ hoàn tất capture. Numeric exporter không mang stderr/diagnostic sang Windows.
- Phân loại ưu tiên exception gốc trước lỗi EOF thứ cấp. `MemoryError`, allocation failure, crash, timeout và IPC/serialization được phân biệt khi evidence đủ; signal không tự chứng minh OOM. Trường chưa đo vẫn `null`.
- LAB runner truyền `job_id` làm `run_id` và entry point trực tiếp. Lời gọi độc lập có run ID mới.

## Kiểm chứng

13 test mới bảo vệ success, exception, crash, timeout, IPC lỗi, MemoryError, stderr quá giới hạn, checkpoint trước timeout, admission failure, process-start failure, boundary, normalization/export privacy và fixture benign thật. Windows chạy 11 case, bỏ qua 2 case yêu cầu Linux LAB; REMnux chạy đủ 13 case. Không tạo PDF trắng mới trong các test này.

| Nhóm | Trước sửa | Sau sửa | Đối chiếu |
| --- | --- | --- | --- |
| Full Windows | 1979 passed / 200 failed / 22 skipped | 1990 passed / 200 failed / 24 skipped | 0 failed case mới; giữ đúng 200 case |
| REMnux, nhóm worker/extraction/audit/export | 219 passed / 5 failed / 0 skipped | 232 passed / 5 failed / 0 skipped | 0 failed case mới; giữ đúng 5 case |

5 lỗi trong nhóm REMnux được giữ riêng: 4 lỗi/assertion của source baseline hiện tại trong `test_extraction.py`, và 1 lỗi provenance vì package kiểm thử độc lập không có Git metadata. Không trình bày nhóm tập trung này thành full suite REMnux. Full Windows trong lần audit cũ có 1976 passed; baseline trước sửa của lần này có 1979 passed do workspace đã có thêm test.

Đã đảo marker bảo toàn diagnostic trong kiểm tra mutation: test phát hiện lỗi, sau đó khôi phục byte mã nguồn chính xác. Toàn bộ 371 file Python parse AST thành công, không có Python comment. Content guard trên index và kiểm tra source của các file thay đổi đều qua. Không tắt hoặc sửa các test baseline để đạt kết quả.

## Bảo toàn dữ liệu và triển khai

Đối chiếu toàn bộ 1.452 bundle trong job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` với checksum từng bundle của audit: **0 bundle thay đổi**. Job/result giữ nguyên checksum; canonical selection rows giữ nguyên checksum và từng SHA-256/nhãn/split khớp audit. Checksum selection ở đây là hash canonical rows theo contract của producer, tách khỏi hash byte của file JSON chứa chúng.

Đã kiểm tra manifest 415 file của package trước/sau, 0 mismatch. Package cuối có SHA-256 `a53c1ceb1bffcc0e7cbcb21e403e2e1f30da431b29b7122a3a0f1d60ecd83e9c`, triển khai ở `/home/remnux/malpdf-diagnostic-validation/bug007a_20261102/after_v3`. Đường dẫn mang ngày bắt đầu trước nửa đêm; báo cáo dùng ngày 2026-11-03 theo Asia/Saigon. Đây là release kiểm thử riêng, không thay active runner/release của corpus và không chỉnh tracked source trên REMnux.

Không thay parser, projection, node cap 200, timeout, labels/splits hoặc baseline bundle. Không huấn luyện, queue job mới hoặc chạy PDF không tin cậy. Chỉ structured verification JSON do lượt kiểm thử này tạo được lấy về; stderr và bundle gốc ở lại LAB.

## Giai đoạn tiếp theo

[BUG-007A](../../docs/bugs/BUG-007A-worker-diagnostic-preservation.md) có kiểm chứng engineering; **74 nguyên nhân lịch sử vẫn unresolved**. [BUG-007B](../../docs/bugs/BUG-007B-recovery-and-truncation-analysis.md) giữ riêng lượt chẩn đoán lại 74 mẫu, báo cáo 465 graph bị cap và validation theo split/nhãn/định nghĩa kích thước node. Chưa queue lượt chạy này; real-sample extraction vẫn cần human gate `lab run` sau staging. Không backfill diagnostic hoặc số đo thiếu vào bundle gốc.

Bằng chứng khóa: [validation.json](../experiments/worker_diagnostics/run_20261103_bug007a/validation.json), [locked_methodology.json](../experiments/worker_diagnostics/run_20261103_bug007a/locked_methodology.json), [source_manifest.json](../experiments/worker_diagnostics/run_20261103_bug007a/source_manifest.json).
