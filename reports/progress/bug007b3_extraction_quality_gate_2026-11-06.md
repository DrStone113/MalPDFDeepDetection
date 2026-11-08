# BUG-007B3 — Cổng Chất lượng Trích xuất (`pdf-extraction-quality-gate-v1`) & Chính sách Mẫu Unavailable / Kích thước Node — 2026-11-06

**B3 (`pdf-extraction-quality-gate-v1`) đã hoàn tất thực thi tự động trên REMnux LAB bằng dữ liệu bundle JSON đã lưu (`raw_pdf_processing = false`, không cần `lab run` từ operator, không sửa `node_cap = 200`, không sửa parser, không chạy huấn luyện mô hình).**
Giai đoạn này khép lại trọn vẹn ba phần của [`BUG-007B`](../../docs/bugs/BUG-007B-recovery-and-truncation-analysis.md) (`B1 Diagnostic Replay` → `B2 Graph Truncation Audit` → `B3 Extraction Quality Gate`), thiết lập hợp đồng kiểm soát chất lượng fail-closed trước mọi lượt xuất ma trận số hoặc huấn luyện GNN.

---

## 1. Thông tin lượt đánh giá & Toàn vẹn bằng chứng

- **Thư mục thực nghiệm:** [`run_20261106T095240284120Z_dfafd888f7a9`](../experiments/pdf_extraction_quality_gate/run_20261106T095240284120Z_dfafd888f7a9/)
- **Đặc tả hợp đồng:** [`docs/extraction_quality_gate.md`](../../docs/extraction_quality_gate.md) (`pdf-extraction-quality-gate-v1`, chính sách `protocol-g-quality-policy-v1`).
- **Mã nguồn & Công cụ thực thi:** [`src/malpdf/extraction/quality_gate.py`](../../src/malpdf/extraction/quality_gate.py), [`scripts/lab/evaluate_extraction_quality_gate.py`](../../scripts/lab/evaluate_extraction_quality_gate.py).
- **Baseline Job ID:** `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` (`expected_index_sha256 = 01b3f248a9685890bc53fda5355052453672649215474a796c4aa56fb40483ff`).
- **Replay Overlay Job ID:** `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575` (đối chiếu ảo chỉ đọc; `baseline_bundles_modified = false`).
- **Kiểm chứng bất biến & Kiểm thử tự động:**
  - `1,452 / 1,452` bundle baseline và `74 / 74` bundle replay giữ nguyên 100% SHA-256 trước và sau khi chạy.
  - Windows DEV: **`208 passed, 4 skipped`** trên bộ hồi quy tập trung (bao gồm `8` test mới trong [`tests/test_extraction_quality_gate.py`](../../tests/test_extraction_quality_gate.py)).
  - REMnux LAB QA: **`281 passed, 5 failed, 0 skipped`** trên `12` module kiểm thử (`+15` test B2+B3 đạt 100%, `0` lỗi mới so với mốc `266 passed, 5 failed` của [`BUG-008`](../../docs/bugs/BUG-008-replay-methodology-boot-memtotal-mismatch.md)).
  - `11 / 11` tệp khóa trong `configs/pdf_diagnostic_replay.json` giữ nguyên SHA-256; `0` byte PDF thô hoặc chuỗi nhạy cảm lọt ra ngoài.

---

## 2. Kết luận Cổng Chất lượng (`Baseline` → `Virtual Post-B1`)

| Hạng mục | Tập Baseline thuần (`dfafd888f7a9...`) | Đối chiếu ảo Hậu-B1 (`dfafd888f7a9...` + `6f9cc944ed98...`) | Ý nghĩa kỹ thuật |
| --- | --- | --- | --- |
| **Phán quyết Cohort (`cohort_gate_verdict`)** | **`blocked_unresolved_extraction_failures`** | **`hold_pending_v2_projection_and_size_contract`** | B1 giải tỏa hoàn toàn rào cản lỗi worker & độ phủ tập đánh giá; cổng giữ chế độ khóa chờ đặc tả biểu diễn v2 |
| **Số tiêu chí đạt (`checks_passed_count`)** | **`4 / 8`** (đạt trọn Tầng 1 Integrity) | **`6 / 8`** (đạt trọn Tầng 1 Integrity + Tầng 2 Recovery) | Còn đúng `2` tiêu chí Tầng 3 Representation cần giải quyết ở run v2 riêng |
| **Mẫu số kế hoạch / bảo toàn đánh giá** | `1,452` / **`1,452`** | `1,452` / **`1,452`** | Bảo toàn tuyệt đối mẫu số `Protocol G` (seed `42`), không co mẫu số `validation`/`test` |
| **Đủ điều kiện truyền thông điệp GNN** | `1,377 / 1,452` (`94.83%`) | **`1,448 / 1,452` (`99.72%`)** | Không chèn node giả `0` (`placeholder_nodes_inserted = false`) |
| **Hợp lệ `feature_store` dạng bảng** | **`1,452 / 1,452` (`100.00%`)** | **`1,452 / 1,452` (`100.00%`)** | Toàn bộ tuân thủ hợp đồng `ObservationStatus` |
| **Mẫu bị từ chối (`rejected_*`)** | **`0`** | **`0`** | `100%` có `worker_cleanup_complete = true` và cấu trúc đồ thị hợp lệ |
| **`v2_provenance_graph_ready`** | `1,004 / 1,452` (`69.15%`) | **`1,058 / 1,452` (`72.87%`)** | Đồ thị `>0` node và không rớt node nhạy cảm bảo mật bởi cap |
| **`legacy_19d_model_input_ready` / `training_unlocked`** | `False` / `False` | `False` / `False` | Chặn xuất vector 19D điền `0` ngầm và chặn huấn luyện sớm (`training_executed = false`) |

---

## 3. Chi tiết 8 Tiêu chí Kiểm định Cohort (`protocol-g-quality-policy-v1`)

| # | Tiêu chí | Tầng | Baseline (`dfafd888f7a9...`) | Virtual Post-B1 (`+ 6f9cc944ed98...`) |
| --- | --- | --- | --- | --- |
| 1 | `cohort_denominator_complete` | Tầng 1 — Toàn vẹn | **PASS** (`1,452 / 1,452`, `rejected=0`) | **PASS** (`1,452 / 1,452`, `rejected=0`) |
| 2 | `worker_cleanup_verified` | Tầng 1 — Toàn vẹn | **PASS** (`unverified_cleanup=0`) | **PASS** (`unverified_cleanup=0`) |
| 3 | `graph_structural_validity` | Tầng 1 — Toàn vẹn | **PASS** (`structural_issues=0`) | **PASS** (`structural_issues=0`) |
| 4 | `tabular_static_feature_store_integrity` | Tầng 1 — Toàn vẹn | **PASS** (`invalid_tabular=0`) | **PASS** (`invalid_tabular=0`) |
| 5 | `unresolved_worker_failures_cleared` | Tầng 2 — Khôi phục | **FAIL** (`70` `unavailable_worker_failure`) | **PASS** (`0` `unavailable_worker_failure`) |
| 6 | `evaluation_partition_coverage` (`<= 1.0%`) | Tầng 2 — Khôi phục | **FAIL** (`validation`: `18/291 = 6.19%`; `test`: `12/291 = 4.12%`) | **PASS** (`validation`: `1/291 = 0.34%` [`141`]; `test`: `0/291 = 0.00%`) |
| 7 | `legacy_19d_semantic_size_populated` | Tầng 3 — Biểu diễn | **FAIL** (`0 / 171,055` known; `171,055` `null`) | **FAIL** (`0 / 179,799` known; `179,799` `null`) |
| 8 | `security_sensitive_truncation_bounded` (`<= 5.0%`) | Tầng 3 — Biểu diễn | **FAIL** (`373 / 1,452 = 25.69% > 5.0%`) | **FAIL** (`390 / 1,452 = 26.86% > 5.0%`) |

---

## 4. Phân rã 10 Trạng thái Mẫu (`Sample Dispositions`) theo Split & Nhãn

### 4.1. Hậu-B1 (`Virtual Post-B1`, `1,452` mẫu — trạng thái thực chứng hiện hành)

| Phân vùng | Planned | `usable_complete` | `usable_degraded_partial_or_timeout` | `usable_degraded_capped_benign_loss` | `usable_degraded_capped_security_loss` | `unavailable_projection_filtered` | `unavailable_timeout_no_graph` | `unavailable_worker_failure` | GNN Eligible |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`train`** | 870 | 209 | 312 | 32 | 314 | 0 | **3** (`292, 407, 749`) | 0 | **867** (99.66%) |
| **`validation`** | 291 | 40 | 159 | 35 | 56 | **1** (`141`) | 0 | 0 | **290** (99.66%) |
| **`test`** | 291 | 11 | 228 | 32 | 20 | 0 | 0 | 0 | **291** (100.00%) |
| **`label = 0`** | 652 | 124 | 303 | 46 | 175 | **1** (`141`) | **3** (`292, 407, 749`) | 0 | **648** (99.39%) |
| **`label = 1`** | 800 | 136 | 396 | 53 | 215 | 0 | 0 | 0 | **800** (100.00%) |
| **Toàn tập** | **1,452** | **260** | **699** | **99** | **390** | **1** | **3** | **0** | **1,448 (99.72%)** |

*(Trên tập Baseline thuần trước B1: `usable_complete = 248`, `usable_degraded_partial_or_timeout = 664`, `usable_degraded_capped_benign_loss = 92`, `usable_degraded_capped_security_loss = 373`, `unavailable_projection_filtered = 1` [`141`], `unavailable_timeout_no_graph = 4` [`126, 292, 496, 749`], `unavailable_worker_failure = 70`).*

---

## 5. Hai Chính sách Ràng buộc Đã Khóa trong Mã nguồn

### 5.1. Chính sách Tài liệu Không có Đồ thị Chiếu (`UNAVAILABLE_DOCUMENT_POLICY`)
1. **Bảo toàn tuyệt đối mẫu số `Protocol G` (`1,452` mẫu, seed `42`):** Cấm loại bỏ ngầm bất kỳ mẫu nào khỏi mẫu số đánh giá của `validation` (`291`) hoặc `test` (`291`).
2. **Cấm chèn node giả lập điền `0` (`placeholder_zero_nodes_allowed = false`):** Đồ thị rỗng giữ nguyên `0` node thay vì bịa node giả gây nhiễu lan truyền thông điệp GNN.
3. **Cơ chế xử lý tách biệt theo phân vùng:**
   - Tập `train`: `3` mẫu benign timeout (`excluded_train_gnn_batch_indices = [292, 407, 749]`) được loại tường minh khỏi minibatch GNN nhưng vẫn giữ trong manifest cohort và kiểm toán `feature_store` tĩnh.
   - Tập `validation` & `test`: Mẫu duy nhất không có node chiếu là `index 141` thuộc `validation` (`eval_abstention_or_tabular_fallback_indices = {"validation": [141], "test": []}`), được xử lý qua cơ chế **abstention tường minh hoặc nhánh đặc trưng tĩnh đã kiểm chứng** và tính trực tiếp trên mẫu số đủ `291`.
4. **Không áp đặt giả tạo 1,452 đồ thị khác rỗng:** Mọi lý do rỗng hợp lệ (`unavailable_projection_filtered` và `unavailable_timeout_no_graph`) được ghi sổ minh bạch trong `unavailable_document_ledger`.

### 5.2. Chính sách Kích thước Node & Nguồn gốc Đặc trưng (`NODE_SIZE_AND_FEATURE_PROVENANCE_POLICY`)
1. **Giữ nguyên `null` cho kích thước thiếu (`missing_size_representation = "null"`):** Nghiêm cấm điền `null -> 0` và nghiêm cấm dùng kích thước chuỗi JSON (`projected_json_storage_bytes`) làm độ dài đối tượng PDF.
2. **Khóa bảo vệ vector `legacy_19d`:** `legacy_19d_ready` bị khóa `false` khi `details.size_bytes` bị thiếu (`179,799 / 179,799` node hậu-B1 là `null`), ngăn chặn triệt để việc huấn luyện GNN trên cột kích thước rỗng.
3. **Định tuyến sang đặc tả v2 có mặt nạ provenance:** Ở run thiết kế biểu diễn v2 tiếp theo (tách biệt với `BUG-007B`), kích thước vật lý sẽ lấy từ 2 producer đã xác thực (`verified_physical_declaration_span_bytes = 6,245` node và `stream_raw_payload_bytes = 4,682` node = `100%` node `stream` giữ lại) kèm cờ mask cho đối tượng inline / MuPDF repaired / `/ObjStm`, đồng thời loại bỏ sự ngập lụt `direct_pypdf` + `direct_mupdf` nội tuyến khỏi `node_cap = 200` (vốn làm `390` mẫu mất node nhạy cảm dù `488 / 489` mẫu có `<= 200` đối tượng gián tiếp).

