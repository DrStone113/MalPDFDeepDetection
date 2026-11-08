# [BUG-008] Outer Shard Crash (`worker_failed`) Do Đối Chiếu Byte-Exact `locked_methodology.json` Với `/proc/meminfo` `MemTotal` Sau Khi Khởi Động Lại VM

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-008` |
| **Ngày ghi nhận** | `2026-11-06` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Toàn bộ 10 outer shard dừng ở giây thứ 14–16 trước khi mở bất kỳ PDF nào; `0/74` mẫu được chạy) |
| **Phân loại lỗi** | `EVIDENCE_DIAGNOSTICS` / `CROSS_BOOT_PROVENANCE` |
| **Thành phần ảnh hưởng** | `src/malpdf/extraction/diagnostic_replay_runner.py`, `src/malpdf/extraction/diagnostic_replay_results.py`, `scripts/lab/lab_jobs.py` |
| **Hồ sơ liên quan** | Failed job `5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0`; Re-staged job `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575` (commit `d1e10fd2c341e1f553ca47f4fe31db8c21a8307c`); [BUG-007B](BUG-007B-recovery-and-truncation-analysis.md); bằng chứng sau chạy `reports/experiments/diagnostic_replay/run_20261106_B1_failed_outer_5fb4b0967c68/`; bằng chứng staging mới `reports/experiments/diagnostic_replay/run_20261106_B1_restaging_6f9cc944ed98/` |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Khi operator ngắt NIC và chạy `unset SSH_AUTH_SOCK && lab run` tại console REMnux LAB cho job `pdf-diagnostic-replay` (`5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0`, 74 mẫu unresolved của `BUG-007B1`):

- Preflight cách ly vượt qua đầy đủ (`guest_network_checked: true`, `hypervisor_controls_attested: true`, `stdlib_dependencies_checked: true`).
- Tiến trình dừng ở giây `00:16`: `Tien trinh: 0/74 (0%) | Da chay: 00:16 | Con lai: --:-- | Workers: 0/10`.
- Kết quả trả về: `{"status": "failed", "reason": "worker_failed", "pdf_summary": null}`.
- Chưa có bất kỳ thư mục `private_cases/`, `private_bundles/` hay `private_attempts/` nào được tạo (chưa mở byte PDF nào trong 74 mẫu).
- Cơ chế bảo toàn lỗi tầng ngoài (`outer_diagnostics.json`) vừa bổ sung ở B1 tự động kích hoạt trong khối `finally` và ghi lại chính xác traceback của cả 10 shard.

### Log / Traceback chi tiết (từ `analysis/outer_diagnostics.json`)

```json
{
  "shard": 0,
  "scope": "outer_shard_not_per_pdf",
  "exit_before_cleanup": 2,
  "cleanup_exit_code": 2,
  "supervisor_reason": "observed_process_exit",
  "exception_type": "ValueError",
  "last_phase": "immutable",
  "elapsed_ms": 14425,
  "traceback": [
    {"file": "lab_runner.py", "function": "pdf_worker", "line": 247},
    {"file": "lab_runner.py", "function": "_pdf_worker", "line": 308},
    {"file": "diagnostic_replay_runner.py", "function": "run_shard", "line": 69},
    {"file": "diagnostic_replay_runner.py", "function": "prepare_replay", "line": 44},
    {"file": "lab_jobs.py", "function": "immutable", "line": 285}
  ]
}
```

Đối chiếu trực tiếp `locked_methodology.json` (lưu lúc staging `2026-11-02`) với môi trường thực thi REMnux lúc chạy (`2026-11-06`):

- Lúc staging (`pdf_prepare`): `environment.memory_bytes = 6222553088` (`MemTotal: 6076712 kB`).
- Lúc chạy offline (`lab run`): `environment.memory_bytes = 6222536704` (`MemTotal: 6076696 kB`).
- Sai lệch đúng **16,384 bytes (16 KiB = 4 trang 4 KiB)**, trong khi Python `3.11.17`, toàn bộ 8 gói thư viện parser/runtime, số vCPU (`12`), kiến trúc (`x86_64`) và biến môi trường thread (`1`) khớp tuyệt đối 100%.

### Điều kiện tái hiện (Reproduction Conditions)

1. Chuẩn bị và queue job `pdf-diagnostic-replay` qua `pdf_prepare` (tạo `locked_methodology.json`).
2. Thực hiện quy trình cách ly chuẩn của operator (snapshot/reboot/khôi phục máy ảo REMnux và ngắt NIC) khiến `MemTotal` trong `/proc/meminfo` dịch chuyển vài trang nhớ 4 KiB giữa hai lần khởi động kernel.
3. Chạy `lab run`: cả 10 tiến trình `pdf-worker` gọi lại `prepare_replay` và bị từ chối tại `lab_jobs.immutable`.

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

1. **Tại sao (Why 1)?** Job thất bại với `reason: "worker_failed"` sau ~16 giây mà không xử lý được mẫu PDF nào (`0/74`).
2. **Tại sao (Why 2)?** Cả 10 outer shard đều ném `ValueError('job_mismatch')` tại `lab_jobs.immutable(directory / 'locked_methodology.json', value)` và thoát với mã `2`.
3. **Tại sao (Why 3)?** `run_shard()` gọi lại `prepare_replay()`, hàm này sinh lại từ điển `locked_methodology.json` kèm `environment()` trực tiếp rồi gọi `immutable()` lên tệp đã được tạo từ bước `pdf_prepare`.
4. **Tại sao (Why 4)?** Trường `environment.memory_bytes` đọc từ dòng `MemTotal:` của `/proc/meminfo` thay đổi từ `6,222,553,088` xuống `6,222,536,704` (-16 KiB) sau khi khởi động lại/khôi phục snapshot máy ảo để ngắt mạng chạy offline.
5. **Tại sao (Why 5 - Root Cause)?** Thiết kế đồng nhất việc **khởi tạo hồ sơ phương pháp luận một lần lúc staging** (`prepare_replay`) với việc **xác minh điều kiện bất biến trong 10 tiến trình thực thi song song** (`run_shard`), đồng thời xếp thông số phần cứng biến thiên theo từng lần boot của kernel (`MemTotal`) chung vào phép so sánh byte-exact `immutable()` và dùng mock `monkeypatch.setattr(runner, 'prepare_replay', ...)` trong unit test nên che khuất tương tác qua hai lần boot.

### Cơ chế kỹ thuật tầng sâu (Deep Mechanics)

- Trên Linux, giá trị `MemTotal:` trong `/proc/meminfo` không phải dung lượng thanh RAM vật lý cố định từ hypervisor mà được tính từ `totalram_pages()` — tổng số trang nhớ khả dụng còn lại sau khi kernel trừ đi vùng đặt chỗ sớm (early memblock, bảng ACPI/UEFI, vùng căn chỉnh KASLR và cấp phát bảng trang khởi tạo). Giữa hai lần boot của cùng một máy ảo VMware với cùng cấu hình RAM, KASLR làm số trang khả dụng dao động tự nhiên từ 4 KiB đến 64 KiB.
- Ngoài lỗi dịch chuyển `MemTotal`, việc để cả 10 shard song song cùng gọi `immutable()` trên một tệp chung `locked_methodology.json` còn tiềm ẩn tranh chấp ghi (`FileExistsError` hoặc đọc tệp đang ghi dở) nếu tệp chưa tồn tại trước đó.
- Quá trình rà soát toàn tuyến thực thi của `diagnostic_replay_runner.py` cũng phát hiện thêm hai điểm hẹp liên quan cần khóa chặt cùng lúc:
  1. Khi `process.start()` thất bại trước khi sinh PID con (ví dụ `OSError(ENOMEM)` ở pha `worker_start`), `profile_worker.py` chưa có tiến trình con nên `cleanup_complete` giữ `None`; điều kiện `no_worker` cũ chỉ cho phép `last_phase == 'worker_admission'`, có nguy cơ dừng sớm cả shard (`worker_cleanup_incomplete`) dù không hề có tiến trình con rò rỉ.
  2. `safe_trace` yêu cầu `line >= 1` (có thể loại nhầm frame C-extension/frozen bootstrap có `tb_lineno == 0`) và `lab_jobs` giới hạn đọc `analysis/summary.json` ở `MAX_REPORT` (`16,384` bytes).

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh

- **Xóa bỏ kiểm tra môi trường hoặc cho phép ghi đè `locked_methodology.json`:** Phá vỡ tính bất biến của hồ sơ thực nghiệm và có thể che giấu việc đổi phiên bản thư viện parser (`pypdf`, `PyMuPDF`, `pikepdf`) giữa lúc staging và lúc chạy.
- **Bỏ lưu `memory_bytes` khỏi telemetry:** Làm mất thông tin cấu hình bộ nhớ thực tế của máy ảo tại thời điểm staging và thời điểm chạy.

### Giải pháp kỹ thuật chuẩn

1. **Tách biệt `prepare_replay` (ghi một lần lúc staging) và `verify_replay` (chỉ đọc và kiểm chứng ở từng shard lúc chạy):**
   - `prepare_replay` chỉ chạy trong `pdf_prepare` đơn luồng để khóa `locked_methodology.json`.
   - `run_shard` gọi `verify_replay(..., shard=shard)`: đọc `locked_methodology.json`, đối chiếu khớp tuyệt đối toàn bộ trường phương pháp luận, mã nguồn khóa, danh sách 74 mẫu, giới hạn tài nguyên và các bất biến phần mềm (`python`, `machine`, `packages`, `thread_environment`), đồng thời kiểm tra `memory_bytes >= file_memory_bytes` và lưu bản chụp môi trường thực thi thực tế của từng shard vào `private_outer/environment.<shard>.json` (tự động hậu tố UUID nếu resume qua lần boot thứ hai để không bao giờ xung đột `immutable`).
2. **Chuẩn hóa điều kiện `no_worker` trước khi spawn:** Ghi nhận đầy đủ các pha tiền-spawn (`validation`, `profile_boundary`, `worker_admission`, `worker_start`) khi cả `cleanup_complete`, `worker_exit_code` và `cleanup_exit_code` đều là `None` (chứng minh `process.pid is None`), giữ nguyên cơ chế dừng shard fail-closed khi `cleanup_complete is False` hoặc không xác định sau khi đã spawn.
3. **Mở rộng an toàn `safe_trace` (`0 <= line <= 10**7`) và trần đọc `analysis/summary.json` (`128 KiB`).**

### Minh họa Logic Thay thế

```diff
- def run_shard(job, directory, source, data_root, rows, limits, catalog, shard, count, operations):
-     lock = prepare_replay(job, directory, source, operations)
+ def run_shard(job, directory, source, data_root, rows, limits, catalog, shard, count, operations):
+     lock = verify_replay(job, directory, source, operations, shard=shard)
```

---

## 4. Nguyên tắc Bất biến để Không Lặp lại (Anti-Regression Invariants)

1. **Không Ghi Lại Hồ sơ Cấp Job Từ Các Worker Shard Song song:** Mọi tệp khóa cấp job (`locked_methodology.json`, `selection.json`, `job.json`) chỉ được ghi một lần ở pha chuẩn bị đơn tiến trình; các worker shard chỉ được phép đọc và xác thực.
2. **Tách Bất biến Phần mềm Khỏi Telemetry Khởi động Kernel:** Phiên bản Python, kiến trúc CPU, phiên bản gói parser và cấu hình thread phải khớp tuyệt đối (`==`); thông số phụ thuộc KASLR/boot của kernel như `/proc/meminfo` `MemTotal` được kiểm tra ngưỡng an toàn (`>= file_memory_bytes`) và ghi nhận riêng theo từng lượt chạy.
3. **Không Mock Toàn bộ Hàm Chuẩn bị Trong Kiểm thử Tích hợp Shard:** Phải có bài kiểm thử chạy thật chuỗi `prepare_replay` → thay đổi `MemTotal` sau reboot → `run_shard` → resume sau lần reboot tiếp theo.

---

## 5. Hợp đồng Kiểm thử Hồi quy (Regression Test Contract)

- **Tệp kiểm thử:** `tests/test_diagnostic_replay.py`
- **Hàm kiểm thử:**
  - `test_replay_shard_survives_boot_memtotal_shift_without_rewriting_methodology_and_rejects_package_drift`
  - `test_pre_spawn_worker_start_failure_continues_shard_while_post_spawn_uncertainty_halts`
  - `test_safe_trace_accepts_zero_line_extension_frames_and_rejects_negative_lines`
- **Cơ chế kiểm thử:** Mô phỏng đầy đủ chu kỳ `prepare_replay` lúc staging với `memory_bytes = 6222553088`, dịch chuyển sang `6222536704` và resume qua lần boot thứ hai, đồng thời khẳng định lệch phiên bản `pypdf`, sửa `node_cap`, hoặc thiếu `locked_methodology.json` đều bị từ chối fail-closed.
