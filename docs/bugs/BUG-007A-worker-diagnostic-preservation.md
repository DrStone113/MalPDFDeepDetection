# BUG-007A — Worker Diagnostic Preservation

| Mục | Chi tiết |
| --- | --- |
| Ngày | 2026-11-03 |
| Trạng thái | RESOLVED (cơ chế diagnostic đã kiểm chứng thực chiến trên 74 mẫu tại [BUG-007B1](BUG-007B-recovery-and-truncation-analysis.md)) |
| Mức độ | HIGH / P0 |
| Phân loại | EVIDENCE_DIAGNOSTICS |
| Hồ sơ gốc | [BUG-007](BUG-007-graph-audit-diagnostic-loss.md) |

## Triệu chứng và nguyên nhân

Audit baseline ghi nhận 70 lỗi worker bị gộp và 4 timeout. BUG-007A sửa khả năng quan sát; chưa xác định nguyên nhân của các mẫu lịch sử.

1. Projection rỗng không giải thích được lỗi vì thiếu primary checkpoint.
2. Boundary bắt `OSError`/`ValueError` quanh toàn bộ profiler và gán chung admission failure.
3. Profiler bao gồm admission, spawn, IPC, checkpoint và cleanup, nên một mã chung không định vị tầng lỗi.
4. Worker bỏ stderr vào devnull và không giữ traceback có cấu trúc.
5. Exit code được cập nhật sau cleanup, nên tín hiệu cleanup có thể bị nhầm là tín hiệu gây lỗi ban đầu.

## Giải pháp

`coverage_report.worker.diagnostic` có schema `pdf-worker-diagnostic-v1`. Giữ `sample_id` mặc định bằng SHA-256 đầu vào, `run_id`, `entry_point`, `exception_type`, `exception_errno`, `traceback`, `stderr`, `elapsed_ms`, `last_phase`, `exception_phase` khi đo được, `timeout_reason`, checkpoint status và tài nguyên đo được.

LAB runner truyền job ID và entry point trực tiếp. Lời gọi độc lập tạo run ID mới. Traceback gồm tối đa 32 frame: đường dẫn tương đối hoặc basename, function và dòng; không có message, source line, locals hoặc nội dung tài liệu. Diagnostic được chụp trong `finally` trước khi cleanup. `worker_exit_code` trong diagnostic là giá trị quan sát trước cleanup; `cleanup_exit_code` và `cleanup_complete` mô tả cleanup sau đó. Các field legacy của worker vẫn giữ ý nghĩa sau cleanup.

Stderr đi qua pipe riêng, chỉ giữ tối đa 16 KiB byte đầu, tiếp tục drain phần dư để worker không chờ stderr đầy. Có cờ truncation và `stderr_capture_complete`; khi crash ngắt capture thì trạng thái chưa biết giữ `null`. Không tạo log file không giới hạn và không thay RLIMIT_FSIZE. Stderr là text không tin cậy, chỉ lưu trong bundle riêng tại LAB. Kênh diagnostic dùng JSON `send_bytes`/`recv_bytes`, không dùng object serialization. Numeric exporter hiện hữu không xuất diagnostic/stderr; regression kiểm tra ranh giới này.

Phân loại cơ chế gồm admission, allocation failure, memory exception, crash, timeout, IPC/serialization, exception và unresolved. SIGKILL tự nó không chứng minh OOM. Phase của exception độc lập với phase serialize kết quả sau lỗi. Không sửa parser, projection, cap 200, timeout hoặc huấn luyện.

## Bất biến và kiểm thử

- Không suy ra corrupt PDF từ worker failure, timeout hoặc graph rỗng.
- Không ghi exception message hoặc traceback có locals/source vào diagnostic.
- Không thay `null` bằng 0 khi chưa đo tài nguyên, stderr hoặc exit code.
- Diagnostic phải tồn tại trước cleanup; không thay exit code quan sát bằng signal do cleanup.
- Không xuất stderr qua numeric projection; không đọc PDF không tin cậy trên Windows.
- `tests/test_worker_diagnostics.py` dùng tiến trình spawn thật cho success, exception, crash, timeout, IPC lỗi, MemoryError, stderr quá cap và checkpoint trước timeout. Kiểm tra boundary và fixture benign thật chỉ chạy trong Linux LAB.
- Danh sách 200 failed case Windows baseline được đối chiếu riêng với full suite sau sửa.

Kết quả kiểm chứng: xem [báo cáo triển khai](../../reports/progress/bug007a_worker_diagnostics_2026-11-03.md).

## Chuyển giai đoạn

74 mẫu lịch sử vẫn unresolved cho tới khi có lượt chạy mới qua human gate. Không ghi diagnostic mới vào bundle gốc. [BUG-007B](BUG-007B-recovery-and-truncation-analysis.md) giữ riêng extraction recovery và phân tích cap.
