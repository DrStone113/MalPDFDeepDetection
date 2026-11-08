# Graph Projection v2 (`pdf-graph-projection-v2`), Hardening `lab_runner.py` & Staging Canonical `pdf-static-cic-full` — 2026-11-06

**Đã hoàn tất trọn vẹn Pha 1 (Windows DEV), Pha 2A (kiểm định tự động trên REMnux LAB với dữ liệu bundle đã lưu, `raw_pdf_processing = false`) và Pha 2B (đồng bộ helper gateway/runner + đóng gói/queue job canonical `pdf-static-cic-full` `89bf66f04d93...`), dừng nghiêm ngặt tại Human Gate Pha 3 chờ lệnh `unset SSH_AUTH_SOCK && lab run` của operator.**

---

## 1. Biểu diễn Đồ thị & Hợp đồng Đặc trưng `v2` (`pdf-graph-projection-v2`)

- **Đặc tả & Mã nguồn mới (bổ sung song song, giữ nguyên 100% đường `v1` 19D và 11 tệp parser khóa trong [`configs/pdf_diagnostic_replay.json`](../../configs/pdf_diagnostic_replay.json)):**
  - [`docs/graph_projection_v2.md`](../../docs/graph_projection_v2.md) — đặc tả kỹ thuật `pdf-graph-projection-v2` (`NODE_FEATURE_DIM_V2 = 23`, `MAX_NODES = 200`, `MAX_CONTAINER_HOPS = 8`).
  - [`src/malpdf/extraction/graph_projection_v2.py`](../../src/malpdf/extraction/graph_projection_v2.py) — loại bỏ ngập lụt `pdf_object` nội tuyến (`object_number is None`) khỏi `node_cap = 200`, xếp hạng ưu tiên 3 tầng (Tầng 0: `catalog`, `pages`, `action`, `script`, `annotation`, `filespec`, `stream`; Tầng 1: `page`; Tầng 2: `pdf_object` gián tiếp), rút gọn cạnh có hướng xuyên container trung gian (`<= 8` bước qua `array`, `form`, `field`, `pdf_object`, `embedded_stream`, `xfa_packet`, dừng tại node giữ lại mà không nối tắt qua node đó), giữ `null` trong JSON cho kích thước chưa xác thực và mã hóa đặc trưng `23D` đơn ánh có mặt nạ provenance (`[log1p_phys, has_phys_mask, log1p_stream, has_stream_mask, is_indirect, is_repaired, is_orphan, rwse_1..16]`).
  - [`src/malpdf/data/graph_contract.py`](../../src/malpdf/data/graph_contract.py) — bổ sung `index_measured_graphs_v2` (`23D`), giữ nguyên `index_measured_graphs` (`19D`).
  - [`src/malpdf/extraction/quality_gate.py`](../../src/malpdf/extraction/quality_gate.py) & [`scripts/lab/evaluate_extraction_quality_gate.py`](../../scripts/lab/evaluate_extraction_quality_gate.py) — bổ sung `GATE_CONTRACT_VERSION_V2 = "pdf-extraction-quality-gate-v2"` (`--projection-version {v1,v2}`).
  - [`scripts/lab/export_graphs_v2.py`](../../scripts/lab/export_graphs_v2.py) — công cụ xuất đồ thị `v2` fail-closed (từ chối xuất nếu `cohort_gate_verdict != "ready_for_locked_export"`).
  - [`tests/test_graph_projection_v2.py`](../../tests/test_graph_projection_v2.py) — `6` bài kiểm thử đơn vị & tích hợp (bao gồm lượt lan truyền thuận `PDFTransGraph(node_in_dim=23)`).

---

## 2. Kết quả Kiểm định Thực nghiệm `v2` trên REMnux LAB (Pha 2A — Bundle Đã lưu)

- **Thư mục bằng chứng thực nghiệm:** [`run_20261106T105703774357Z_dfafd888f7a9`](../experiments/pdf_graph_projection_v2/run_20261106T105703774357Z_dfafd888f7a9/) (`raw_pdf_processing = false`, `1,452 / 1,452` bundle baseline + `74 / 74` bundle replay giữ nguyên 100% SHA-256).

| Hạng mục | `v1` Hậu-B1 (`BUG-007B3`) | `v2` Baseline (`dfafd888f7a9...`) | `v2` Hậu-B1 (`dfafd888f7a9...` + `6f9cc944ed98...`) |
| --- | --- | --- | --- |
| **Phán quyết Cổng Chất lượng (`cohort_gate_verdict`)** | `hold_pending_v2_projection_and_size_contract` (`6 / 8`) | `blocked_unresolved_extraction_failures` (`6 / 8`) | **`ready_for_locked_export` (`8 / 8` PASS)** |
| **Đồ thị hợp lệ đủ điều kiện GNN** | `1,448 / 1,452` (`19D` thiếu size) | `1,377 / 1,452` (`23D`) | **`1,448 / 1,452` (`23D` đầy đủ provenance)** |
| **Số mẫu chạm trần `node_cap = 200`** | `489 / 1,448` | `1 / 1,377` | **`1 / 1,448`** |
| **Số mẫu rớt node nhạy cảm bảo mật do cap** | `390 / 1,452` (`26.86%` — FAIL) | **`0 / 1,452` (`0.00%` — PASS)** | **`0 / 1,452` (`0.00%` — PASS)** |
| **Tổng số node / cạnh xuất (`hetero_graphs_v2`)** | `179,799` node | `40,575` node | **`42,306` node / `64,117` cạnh** (`40,258` trực tiếp + `23,859` rút gọn container) |
| **Provenance kích thước vật lý đã xác thực** | `0` known (`100%` `null`) | `6,486` span + `8,865` stream | **`6,879` span vật lý + `9,275` stream payload** (`0` suy diễn `null -> 0`) |
| **Tài liệu unavailable ghi sổ minh bạch** | `4` (`[141, 292, 407, 749]`) | `75` (`70` worker + `4` timeout + `1` `[141]`) | **`4` (`validation=[141]` `0.34% <= 1%`; `test=[]` `0.00%`)** |

- **Kiểm chứng cơ chế xuất fail-closed (`export_graphs_v2.py`):**
  - Chạy trực tiếp trên baseline `dfafd888f7a9...` (còn 70 lỗi worker cũ) bị chặn đúng thiết kế với `quality_gate_not_ready_for_export`.
  - Chạy dry-run chỉ đọc trên đối chiếu ảo Hậu-B1 xuất thành công `1,448` đồ thị `23D` qua kiểm tra `index_measured_graphs_v2`, `1,452` dòng đặc trưng tĩnh và sổ cái `4` mẫu unavailable (`export_20261106T111844432382Z_dfafd888f7a9`).

---

## 3. Gia cố `scripts/lab/lab_runner.py` chống Suy kiệt RAM khi Chạy 10 Shard

1. **Điều tiết áp lực bộ nhớ trước mỗi mẫu (`_wait_for_memory_headroom`):** Trước khi gọi `extract_pdf`, từng outer shard kiểm tra `MemAvailable` trong `/proc/meminfo` (ngưỡng an toàn `>= 900 MiB`), tạm chờ theo nhịp `0.25 s` (tối đa `30 s`, tôn trọng trần thời gian toàn cục của job) khi các shard đồng thời đang giữ đỉnh RSS.
2. **Thử lại có giới hạn cho lỗi cấp phát tiền-spawn (`_is_prespawn_admission_failure`):** Khi tiến trình con gặp lỗi cấp phát hệ điều hành trước khi mở PDF (`worker_admission`, `profile_boundary`, `worker_start` với `worker_cleanup_complete is None`), outer shard chờ bộ nhớ hồi phục và thử lại tối đa `3` lần (`1.0 s`, `2.0 s`, `4.0 s`) thay vì ghi ngay `worker_error` giả tạo.
3. **Đồng bộ phân loại `no_worker` & bảo toàn chẩn đoán outer shard:** Tránh dừng oan cả shard bởi `worker_cleanup_incomplete` đối với lỗi tiền-spawn chưa sinh worker con (vẫn dừng fail-closed tức thì nếu `worker_cleanup_complete is False`), giữ chốt chặn `sys.platform != 'linux'` ngay đầu `pdf_worker`, và lưu `private_outer/exception.<shard>.json` cho toàn bộ `PDF_KINDS`.

---

## 4. Kiểm thử Hồi quy & Toàn vẹn Mã nguồn

| Môi trường & Bộ kiểm thử | Kết quả |
| --- | --- |
| **Zero Python Comments (`src/malpdf/`, `scripts/`, `tests/`)** | **`0` comment** trên toàn bộ mã nguồn Python |
| **11 tệp khóa `configs/pdf_diagnostic_replay.json`** | **`11 / 11` khớp SHA-256 tuyệt đối** |
| **Windows DEV `pytest` (11 module tương thích Python 3.11)** | **`220 passed, 5 skipped`** (`0` failed) |
| **Windows DEV bảo mật tổng hợp (`scripts/lab/selftest.py`)** | **`237 passed, 0 failed, 0 skipped`** |
| **REMnux LAB `.venv` `pytest` (13 module đầy đủ kèm PyTorch)** | **`287 passed, 5 failed, 0 skipped`** (`+21` test mới đạt 100%, `0` lỗi mới so với baseline `BUG-008`) |
| **REMnux Gateway `doctor` & `readiness(negative=True)`** | **`status = "ready"` (`ready_idle`)**, khớp `policy_sha256 = d59b2e622dfb660f67df2e2fae482d941b42f2dfc4c3bdfec267be718cf94040` |

---

## 5. Job Canonical `pdf-static-cic-full` Chờ Operator tại Human Gate (Pha 3)

Do job baseline cũ `dfafd888f7a9...` vẫn lưu 70 bundle `worker_error` trên đĩa còn `6f9cc944ed98...` là job replay riêng cho 74 mẫu, một job **`pdf-static-cic-full` đơn nhất, sạch và chuẩn tắc** đã được đóng gói và xếp hàng tại REMnux LAB để tạo bộ dữ liệu khóa cuối cùng từ một nguồn duy nhất:

- **Biên nhận xác minh staging:** [`staged_cic_full_89bf66f04d93.json`](../experiments/pdf_graph_projection_v2/staged_cic_full_89bf66f04d93.json)
- **Job ID:** `89bf66f04d932dece2518500fbdfb3121fff8799df74b2f02accac03197e1900`
- **Kind / Mode / Status:** `pdf-static-cic-full` / `offline` / `queued` (`pending_jobs == 1`, `credentials == []`).
- **Snapshot Release Commit:** `766f2856bf735d51d2ab676f5264b46e454cdf0c` (`425` tệp nguồn đã qua `check_repo_content.py --revision`; Windows `HEAD` `c6b920385d966eaba9f0e1eec0ac2dcb789a4664` và `.git/index` giữ nguyên không đổi).
  - Archive SHA-256: `2d0a46c86bf676a427d95ccc1d3a3a519a2d930dd9aa6cdaf159b0db112ac422`
  - Manifest SHA-256: `1816a3855aa331d841a1f7e433571c1de195719ebab7278509df5f047bec839b`
  - Installed `lab_runner.py` SHA-256: `d9caa078ef76e60179ce0117db921b41da6471679cb530b467ba474843ff3a01`
- **Cohort & Phân vùng (`selection.json`):**
  - Tổng số mẫu: **`1,452`** (`train = 870`, `validation = 291`, `test = 291`; `label 0 = 652`, `label 1 = 800`).
  - `selection_sha256`: `2fc0b5ae5ab1dfd1006d4c17b8991d78edc9f32493a2de6dd2254f3b2b69ded9` (khớp bit-for-bit với `selection_rows_sha256` chuẩn Protocol G seed `42`).
  - Giới hạn thực thi: `workers = 10`, `wall_seconds = 7200`, `file_wall_seconds = 35`, `file_cpu_seconds = 30`, `file_memory_bytes = 1 GiB`, `file_max_bytes = 10 MiB`.
- **Trạng thái cách ly hiện tại:** `claim_present = false`, `private_bundles_present = false`, `raw_pdf_processing = false` (**`0 / 1,452` tệp PDF được mở**); toàn bộ 3 thư mục job lịch sử (`dfafd888f7a9...`, `6f9cc944ed98...`, `5fb4b0967c68...`) giữ nguyên 100%.

### Hướng dẫn Thực thi tại Console REMnux (Pha 4 — Operator Trigger)

1. Ngắt kết nối card mạng (NIC) của máy ảo REMnux trong VMware và xác nhận chế độ cô lập offline (tắt clipboard, drag-drop, shared folders).
2. Mở terminal trực tiếp trên console REMnux và chạy duy nhất lệnh:

```bash
unset SSH_AUTH_SOCK && lab run
```

3. Sau khi toàn bộ `1,452 / 1,452` mẫu hoàn tất, bật lại kết nối Host-only (`VMnet1`) và thông báo để agent tự động thực hiện Pha 5: kiểm định cổng chất lượng `v2` (`8 / 8`) và xuất bộ đồ thị khóa `hetero_graphs_v2.jsonl.gz` (`23D`) từ duy nhất job canonical `89bf66f04d93...`.

