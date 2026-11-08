# BUG-008 & BUG-007B1 — Phân tích lỗi `5fb4b0967c68`, sửa dứt điểm và staging lại Diagnostic Replay — 2026-11-06

**Đã truy xuất bằng chứng sau chạy của job `5fb4b0967c68...`, xác định nguyên nhân gốc `BUG-008`, sửa triệt để trên Windows DEV, kiểm chứng hồi quy trên cả Windows lẫn REMnux LAB và queue job replay mới `6f9cc944ed98...`.** Chưa mở hay chạy thực tế bất kỳ tệp PDF nào trong 74 mẫu (`0/74`); B2 (audit 465 graph bị cap), B3 (extraction quality gate) và huấn luyện mô hình chưa thực hiện.

## 1. Chẩn đoán sự cố job `5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0`

- Lượt chạy offline `lab run` tại console REMnux dừng ở giây `00:16` (`0/74 (0%)`) với `status="failed"`, `reason="worker_failed"`, `pdf_summary=null`.
- Xác minh trực tiếp tại `/var/lib/malpdf/jobs/5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0/`: chưa tạo `private_cases/`, `private_bundles/` hay `private_attempts/` — **0/74 PDF được mở**.
- Cơ chế bảo toàn lỗi outer worker (`analysis/outer_diagnostics.json`) đã tự động ghi lại chính xác cùng một traceback cho cả 10 shard (`shard 0..9`):
  - `lab_runner.py:247 (pdf_worker)` → `lab_runner.py:308 (_pdf_worker)` → `diagnostic_replay_runner.py:69 (run_shard)` → `diagnostic_replay_runner.py:44 (prepare_replay)` → `lab_jobs.py:285 (immutable)` (`exception_type="ValueError"`, `last_phase="immutable"`, `exit_before_cleanup=2`).
- **Nguyên nhân gốc (`BUG-008`):** Lúc staging (`2026-11-02`), `prepare_replay` ghi `locked_methodology.json` với `environment.memory_bytes = 6222553088` (`MemTotal: 6076712 kB`). Khi operator khởi động lại/khôi phục máy ảo REMnux và ngắt NIC để chạy offline (`2026-11-06`), kernel Linux tính lại `totalram_pages()` (`MemTotal` trong `/proc/meminfo`) thành `6222536704` (`6076696 kB`, lệch `-16,384` bytes = 4 trang 4 KiB do đặt chỗ sớm/KASLR tự nhiên giữa các lần boot). Do `run_shard` gọi lại `prepare_replay` kèm kiểm tra `immutable()` byte-exact trên `locked_methodology.json`, cả 10 shard đều bị từ chối ngay trước vòng lặp PDF.
- Hồ sơ chi tiết 5 Whys & bất biến chống hồi quy: [BUG-008-replay-methodology-boot-memtotal-mismatch.md](../../docs/bugs/BUG-008-replay-methodology-boot-memtotal-mismatch.md).
- Bản lưu bằng chứng sau chạy đã kiểm tra SHA-256: [run_20261106_B1_failed_outer_5fb4b0967c68](../experiments/diagnostic_replay/run_20261106_B1_failed_outer_5fb4b0967c68/manifest.json).

## 2. Các bản sửa mã nguồn đã áp dụng

1. **`src/malpdf/extraction/diagnostic_replay_runner.py`:**
   - Tách `prepare_replay` (chỉ ghi `locked_methodology.json` một lần duy nhất ở bước `pdf_prepare`) khỏi `verify_replay(..., shard=shard)` (chỉ đọc và kiểm chứng ở từng outer shard khi `lab run`).
   - `verify_replay` kiểm tra khớp tuyệt đối toàn bộ trường phương pháp luận, mã nguồn bảo vệ (`unchanged_code_sha256`), danh sách 74 bản ghi, giới hạn tài nguyên và bất biến phần mềm (`python`, `machine`, `packages`, `thread_environment`), đồng thời kiểm tra ngưỡng `memory_bytes >= file_memory_bytes` và lưu bản chụp môi trường thực tế của từng shard vào `private_outer/environment.<shard>.json` (hỗ trợ hậu tố UUID nếu resume qua lần boot tiếp theo).
   - Bổ sung đầy đủ các pha tiền-spawn (`validation`, `profile_boundary`, `worker_admission`, `worker_start` khi chưa sinh PID con) vào điều kiện `no_worker` để lỗi cấp phát trước khi spawn không dừng oan cả shard với `worker_cleanup_incomplete`, giữ nguyên dừng fail-closed khi `cleanup_complete` không chắc chắn sau spawn.
2. **`src/malpdf/extraction/diagnostic_replay_results.py`:** Cho phép `0 <= line <= 10**7` trong `safe_trace` để không loại nhầm frame C-extension/bootstrap có `tb_lineno == 0`.
3. **`scripts/lab/lab_jobs.py`:** Nâng trần đọc `analysis/summary.json` và stdout của `replay_analysis` từ `16 KiB` lên `128 KiB`.
4. **Giữ nguyên 100% 11 tệp parser/extractor/graph được khóa trong `configs/pdf_diagnostic_replay.json`.**

## 3. Kiểm chứng hồi quy

| Phạm vi | Trước sửa BUG-008 (B1 cũ) | Sau sửa BUG-008 | Đối chiếu |
| --- | --- | --- | --- |
| Windows tập trung (replay/worker/halt/audit/export/cohort) | 197 passed / 0 failed / 4 skipped | 200 passed / 0 failed / 4 skipped | +3 test hồi quy mới; 0 lỗi |
| REMnux LAB (worker/extraction/replay/audit/export) | 263 passed / 5 failed / 0 skipped | 266 passed / 5 failed / 0 skipped | +3 test hồi quy mới + toàn bộ Linux-only test pass; khớp đúng 5 failed ID baseline, 0 failed mới |

- Kiểm thử đột biến (mutation testing) trên bản sao cô lập tại Windows: cả 2 đột biến (`reintroduce_prepare_replay_in_run_shard` và `disable_pinned_environment_drift_check`) đều bị `tests/test_diagnostic_replay.py` bắt ngay (`exit_code = 1`), worktree không đổi.
- Toàn bộ 377 tệp Python qua kiểm tra AST với **0 Python comments**; index content guard qua 2,239 tệp; snapshot content guard qua toàn bộ 416 tệp.

## 4. Job mới chờ Operator tại Human Gate

- **Job ID:** `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575`
- **Kind / Mode / Status:** `pdf-diagnostic-replay` / `offline` / `queued` (pending duy nhất: `pending_jobs == 1`).
- **Source release commit:** `d1e10fd2c341e1f553ca47f4fe31db8c21a8307c`
  - Archive SHA-256: `c0230c6d08c3093377e9dcffc8a07deaf590262b31141755a973fb426b0095c7`
  - Manifest SHA-256: `cc82c65e69a329364e8b08111bb5dfe89c7399066560deda849b81fc54a488a7`
  - `locked_methodology.json` SHA-256: `bd66e91e68aa7afc81eb5462f7330636914aeef2e02b035fd0dc384ceb13e7d4`
  - `selection.json` rows SHA-256: `e9b3a7def820249d0d82e7e82a1da1927027f02b5cb65c6b0dbc806badac8791`
- **Phạm vi & giới hạn:** Đúng 74 mẫu unresolved (70 `worker_error_unspecified` + 4 `timeout`; 45 train / 17 val / 12 test; 41 nhãn `1` / 33 nhãn `0`); 35 s wall / 30 s CPU / 1 GiB / 10 MiB mỗi PDF, 10 worker, `node_cap = 200`.
- **Bảo toàn dữ liệu gốc:** Toàn bộ 1,452 bundle gốc của baseline `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` giữ nguyên 100% SHA-256 (`changed_bundle_indices = []`). Hồ sơ job lỗi `5fb4b0967c68...` được giữ nguyên tại LAB để truy vết. Helper `/usr/local/libexec/malpdf/lab_jobs.py` đã cập nhật nguyên tử kèm sao lưu tại `/var/lib/malpdf/bootstrap-backups/bug008_6f9cc944ed98`.

Theo [human gate của AGENTS.md](../../docs/agent_workflow_and_gates.md), sau khi ngắt NIC máy ảo REMnux trong VMware và kiểm tra điều kiện cách ly, operator chỉ cần chạy tại console REMnux:

```bash
unset SSH_AUTH_SOCK && lab run
```

Bằng chứng khóa: [validation.json](../experiments/diagnostic_replay/run_20261106_B1_restaging_6f9cc944ed98/validation.json), [staging_verification.json](../experiments/diagnostic_replay/run_20261106_B1_restaging_6f9cc944ed98/staging_verification.json), [locked_methodology.json](../experiments/diagnostic_replay/run_20261106_B1_restaging_6f9cc944ed98/locked_methodology.json), [manifest.json](../experiments/diagnostic_replay/run_20261106_B1_restaging_6f9cc944ed98/manifest.json).

