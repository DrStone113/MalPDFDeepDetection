# BUG-007B1 — Kết quả thực thi và phân tích Diagnostic Replay (74 mẫu) — 2026-11-06

**B1 đã hoàn tất thực thi offline tại REMnux LAB (`74/74` mẫu, `0` halted shard, `100%` phủ diagnostic `pdf-worker-diagnostic-v1`) và vượt qua kiểm định xuất bản đóng (`validate_export`).**
Trong điều kiện giữ nguyên 100% mã nguồn parser/extractor/graph (`unchanged_code_sha256`), `node_cap = 200` và giới hạn tài nguyên (`35 s` wall / `30 s` CPU / `1 GiB` / `10 MiB`), **71 / 74 mẫu (95.95%) đã khôi phục được đồ thị chiếu có node (`graphs_restored = 71`)**, không xuất hiện bất kỳ ca `worker_error` hay `worker_admission_failed` nào (`0/74`).

B2 (audit 465 graph bị cap `200`), B3 (extraction quality gate) và huấn luyện mô hình chưa thực hiện.

---

## 1. Thông tin lượt chạy và kiểm định toàn vẹn

- **Job ID:** `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575` (`pdf-diagnostic-replay`, `offline`)
- **Commit phát hành:** `d1e10fd2c341e1f553ca47f4fe31db8c21a8307c`
- **Thời gian chạy:** `222,757 ms` (`~03:57`), `peak_rss_bytes = 392,810,496` (`~374.6 MiB`), `10` outer workers, `0` halted shards.
- **Tài nguyên runtime ghi nhận tại 10 shard (`private_outer/environment.<shard>.json`):** `memory_bytes = 6,222,536,704`, khớp cơ chế kiểm chứng của [BUG-008](../../docs/bugs/BUG-008-replay-methodology-boot-memtotal-mismatch.md); cả 10 shard thoát sạch (`exit_before_cleanup = 0`, `cleanup_exit_code = 0`, `stderr_utf8_bytes = 0`).
- **Độ phủ mẫu & diagnostic:** `planned = 74`, `completed = 74`, `availability_counts = {"present": 74}`, `diagnostic_records = 74`, `diagnostic_coverage_complete = true`, `primary_available = 73/74`, `checkpoint_received = 74/74`.
- **Bảo toàn baseline:** Toàn bộ `1,452` bundle gốc của baseline `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` giữ nguyên 100% SHA-256 (`changed_bundle_indices = []`). Không xuất bất kỳ byte PDF thô, `private_bundles/`, `private_cases/` hay `stderr` thô nào sang Windows (`stderr_text_returned = false`).

---

## 2. Phân loại cơ chế quan sát được (`observed_mechanism`) & Đối chiếu Baseline

### 2.1. Ma trận chuyển trạng thái từ Baseline (`dfafd888f7a9...`) sang Replay (`6f9cc944ed98...`)

| Nhóm lỗi Baseline (74 mẫu) | Cơ chế quan sát khi Replay (`observed_mechanism`) | Trạng thái Bundle Replay | Số mẫu | Số mẫu khôi phục Graph (`projected_nodes > 0`) |
| --- | --- | --- | ---: | ---: |
| `worker_error_unspecified` (70) | `no_worker_failure_observed` | `bounded_complete` | 17 | 17 / 17 |
| `worker_error_unspecified` (70) | `no_worker_failure_observed` | `unsupported` | 19 | 19 / 19 |
| `worker_error_unspecified` (70) | `no_worker_failure_observed` | `partial` | 4 | 4 / 4 |
| `worker_error_unspecified` (70) | `no_worker_failure_observed` | `decode_error` | 3 | 3 / 3 |
| `worker_error_unspecified` (70) | `wall_timeout` (`35 s`) | `timeout` | 26 | 25 / 26 *(chỉ trừ index `407`)* |
| `worker_error_unspecified` (70) | `signal_exit_unresolved` (`-9` tại `byte_images`) | `bounded_complete` | 1 | 1 / 1 *(index `795`)* |
| `timeout` (4) | `wall_timeout` (`35 s`) | `timeout` | 4 | 2 / 4 *(`126`, `496` khôi phục; `292`, `749` còn `0`)* |
| **Tổng cộng** | — | — | **74** | **71 / 74 (95.95%)** |

### 2.2. Giải mã các phát hiện trọng tâm

1. **Giải thích 70 ca `worker_error_unspecified` lịch sử:**
   - Trong tập baseline `1,452` mẫu, toàn bộ 70 ca `worker_error_unspecified` nằm trọn trên **2 dải liên tiếp bước nhảy 10 của đúng 2 shard**:
     - **Shard 5 (`index % 10 == 5`):** `56` mẫu liên tiếp không đứt quãng từ `245` đến `795`.
     - **Shard 7 (`index % 10 == 7`):** `14` mẫu liên tiếp không đứt quãng từ `287` đến `417`.
   - Khi chạy lại trên cùng mã nguồn parser/worker không đổi, **0/70 mẫu gặp lỗi admission/spawn**, **70/70 gửi về primary checkpoint** và **69/70 tạo được đồ thị chiếu hợp lệ**. Điều này bác bỏ giả thuyết rằng 70 tệp PDF này hỏng nặng không thể trích xuất; tuy nhiên vì lượt chạy baseline cũ không có telemetry trước cleanup nên nguyên nhân hệ điều hành cụ thể tại thời điểm lịch sử vẫn giữ `historical_root_causes_confirmed = null` đúng nguyên tắc bằng chứng.
2. **Tách biệt `worker_exit_code` trước cleanup và `cleanup_exit_code` sau cleanup:**
   - Ở `73/74` mẫu (`43` hoàn tất bình thường tại `result_serialization` + `30` chạm ngưỡng `wall_timeout`), `worker_exit_code` trước cleanup là `null`, còn `-9` (`SIGKILL`) chỉ xuất hiện ở `cleanup_exit_code` khi supervisor thu dọn tiến trình con sau khi đã nhận kết quả hoặc hết hạn wall-clock.
   - Chỉ duy nhất **1 mẫu (`index 795`)** có `worker_exit_code = -9` trước cleanup: tiến trình con thoát bởi signal `-9` ở pha thứ cấp `byte_images` tại `elapsed_ms = 33,923` (`peak_rss_bytes = 258.0 MiB`, pipe đóng gây `EOFError`), sau khi đã hoàn tất primary checkpoint (`checkpoint_status = complete`). Do đó bundle vẫn đạt `bounded_complete` và khôi phục `133` projected nodes / `117` edges; theo quy tắc `BUG-007A`, `SIGKILL` không tự động gán là OOM (`observed_mechanism = signal_exit_unresolved`, `root_cause = null`).
3. **Phân rã 30 ca `wall_timeout` theo pha cuối cùng (`last_phase`):**
   - `parser_analysis`: `12` mẫu (`10` khôi phục graph, `2` còn `0` node là `407`, `749`).
   - `raw_forensic`: `8` mẫu (`8/8` khôi phục graph, hầu hết đã đạt trần `200` node từ primary checkpoint).
   - `stream_decode`: `5` mẫu (`5/5` khôi phục graph, cả `5` đạt `200` node).
   - `parse_pdf`: `4` mẫu (`3/4` khôi phục graph là `126`, `365`, `445`; `1` còn `0` node là `292`).
   - `checkpoint_serialization`: `1` mẫu (`index 496`, khôi phục `79` node / `55` cạnh).

---

## 3. Phân tích 3 mẫu duy nhất còn `projected_nodes = 0` (`292`, `407`, `749`)

Cả 3 mẫu còn `0` node chiếu đều thuộc tập **`train`** và có nhãn **`0` (benign)**; toàn bộ tập `validation` (`17/17`), `test` (`12/12`) và toàn bộ mẫu độc hại `label = 1` (`41/41`) đều đạt `100%` khôi phục graph:

| Baseline index | Split | Label | Lỗi Baseline | Replay `last_phase` | `checkpoint_status` | `evidence_nodes` / `edges` | `projected_nodes` | Bản chất kỹ thuật đã xác minh |
| ---: | --- | ---: | --- | --- | --- | --- | ---: | --- |
| `292` | `train` | `0` | `timeout` | `parse_pdf` (`35,018 ms`) | `partial` | `3` / `0` | `0` | Hết hạn `35 s` ngay trong `parse_pdf` trước khi thu được object ngữ nghĩa (`document`, `raw_layout`, `arlington_analysis:not_run`). |
| `407` | `train` | `0` | `worker_error_unspecified` | `parser_analysis` (`35,006 ms`) | `parser_error` | `634` / `615` | `0` | Primary parser báo `parser_error`; pha thứ cấp `parser_analysis` ghi nhận `612` bản ghi `parser_object:partial` trước khi hết `35 s`, nhưng loại `parser_object` nằm ngoài 9 loại node của phép chiếu số hiện hữu (cùng cơ chế với `index 141`). |
| `749` | `train` | `0` | `timeout` | `parser_analysis` (`35,014 ms`) | `parser_error` | `660` / `641` | `0` | Primary parser báo `parser_error`; `parser_analysis` ghi nhận `638` bản ghi `parser_object:partial` trước khi hết `35 s`, không thuộc 9 loại node chiếu ngữ nghĩa. |

---

## 4. Thống kê đồ thị khôi phục và giới hạn kết luận trước B2 / B3

- **Tổng hợp theo Split:**
  - `train`: `42 / 45` khôi phục (`93.33%`), `3` mẫu `0` node.
  - `validation`: `17 / 17` khôi phục (`100%`).
  - `test`: `12 / 12` khôi phục (`100%`).
- **Tổng hợp kích thước & cap:**
  - Tổng cộng `8,744` projected nodes và `4,529` projected edges được khôi phục trên `71` mẫu.
  - Có **`24 / 71` mẫu chạm trần `node_cap = 200`** ngay trong nhóm replay này.
  - Toàn bộ `8,744` node chiếu hiện có `node_sizes_unknown = 8,744` (`node_sizes_known = 0`), `model_feature_dim = null`, `model_input_ready = false` — nhất quán với phát hiện tại [BUG-007](../../docs/bugs/BUG-007-graph-audit-diagnostic-loss.md) về việc thiếu producer kích thước semantic node.
- **Điều kiện tiếp theo:**
  1. **B2 (Graph Truncation Audit):** Phân tích định lượng `465` mẫu bị cắt tại `node_cap = 200` trên tập baseline (cộng đối chiếu `24` mẫu chạm trần trong B1) và chốt producer kích thước/thuộc tính node.
  2. **B3 (Extraction Quality Gate):** Thiết lập hợp đồng kiểm định chất lượng trích xuất & quyết định xử lý đối với nhóm timeout thứ cấp / `parser_object` trước khi mở khóa bất kỳ lượt xuất ma trận hoặc huấn luyện mô hình nào.

Bằng chứng khóa:
- [summary.json](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/summary.json)
- [report.md](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/report.md)
- [cases.jsonl](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/cases.jsonl)
- [outer_diagnostics.json](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/outer_diagnostics.json)
- [postrun_analysis.json](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/postrun_analysis.json)
- [local_manifest.json](../experiments/diagnostic_replay/run_20261106_B1_completed_6f9cc944ed98/local_manifest.json)

