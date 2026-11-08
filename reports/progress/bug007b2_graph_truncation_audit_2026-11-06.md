# BUG-007B2 — Kết quả Kiểm định Cắt cụt Đồ thị (`node_cap = 200`) & Nguồn gốc Kích thước Node — 2026-11-06

**B2 (`pdf-graph-truncation-audit-v1`) đã hoàn tất thực thi tự động trên REMnux LAB bằng dữ liệu bundle JSON đã lưu (`raw_pdf_processing = false`, không cần `lab run` từ operator, không sửa `node_cap = 200` hay mã parser).**
Kiểm định bao phủ toàn bộ **`1,452 / 1,452` mẫu baseline (`dfafd888f7a9...`)** và lớp phủ đối chiếu chỉ đọc (virtual read-only overlay) trên **`74 / 74` mẫu replay B1 (`6f9cc944ed98...`)**, đồng thời xác nhận 100% bất biến SHA-256 trên cả `1,452` bundle baseline và `74` bundle replay.

B3 (Extraction Quality Gate) và huấn luyện mô hình chưa thực hiện (`model_input_ready = false`, `training_executed = false`).

---

## 1. Thông tin lượt kiểm định & Toàn vẹn bằng chứng

- **Thư mục thực nghiệm:** [`run_20261106T092752131513Z_dfafd888f7a9`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/)
- **Baseline Job ID:** `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` (`expected_index_sha256 = 01b3f248a9685890bc53fda5355052453672649215474a796c4aa56fb40483ff`, khớp bit-for-bit với mốc kiểm toán ban đầu).
- **Replay Overlay Job ID:** `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575` (chỉ đọc để đối chiếu ảo hậu-B1; `baseline_bundles_modified = false`).
- **Kiểm thử tự động:**
  - Windows DEV: `200 passed, 4 skipped` trên bộ hồi quy tập trung (bao gồm `7` test mới trong [`test_graph_truncation_audit.py`](../../tests/test_graph_truncation_audit.py)).
  - REMnux LAB QA: `273 passed, 5 failed, 0 skipped` (`+7` test mới pass, `0` lỗi mới so với mốc `266 passed, 5 failed` của `BUG-008`).
- **Ràng buộc an toàn:** `0` byte PDF thô được đọc/truyền, `0` chuỗi đường dẫn nội bộ hay `stderr` xuất ra ngoài, `11/11` tệp khóa trong `configs/pdf_diagnostic_replay.json` giữ nguyên SHA-256.

---

## 2. Phân tầng Cohort theo Split & Nhãn (`Baseline` vs `Virtual Post-B1`)

### 2.1. Tập Baseline bất biến (`1,452` mẫu)

| Phân vùng | Planned | Đồ thị có node (`>0`) | Không chạm trần (`<=200`) | Chạm trần (`>200`) | Đồ thị rỗng (`0` node) | Hợp lệ theo contract v1 (`cleanup && nodes>0`) | Node đủ ĐK trước cap (median / p95 / max) | Node giữ sau cap (median / total) | Cạnh giữ sau cap (median / total) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| **`train`** | 870 | 825 (94.83%) | 496 | **329** (37.82%) | 45 | 825 | `122.0` / `1448` / `1625` | `122.0` / `105,812` | `60.0` / `58,505` |
| **`validation`** | 291 | 273 (93.81%) | 186 | **87** (29.90%) | 18 | 273 | `119.0` / `1157` / `1625` | `119.0` / `33,822` | `57.0` / `17,371` |
| **`test`** | 291 | 279 (95.88%) | 230 | **49** (16.84%) | 12 | 279 | `100.0` / `1015` / `1625` | `100.0` / `31,421` | `71.0` / `19,286` |
| **`label = 0`** | 652 | 618 (94.79%) | 406 | **212** (32.52%) | 34 | 618 | `100.0` / `1434` / `1625` | `100.0` / `76,359` | `69.0` / `41,972` |
| **`label = 1`** | 800 | 759 (94.88%) | 506 | **253** (31.63%) | 41 | 759 | `100.0` / `1394` / `1625` | `100.0` / `94,696` | `71.0` / `53,190` |
| **Toàn tập** | **1,452** | **1,377 (94.83%)** | **912** | **465 (32.02%)** | **75** | **1,377** | `100.0` / `1406` / `1625` | `100.0` / `171,055` | `71.0` / `95,162` |

- **Tách biệt minh bạch nhóm `0` node (`75` mẫu baseline):**
  - `projection_filter_confirmed_indices = [141]` (`1` mẫu thuộc `validation`, `label = 0`, có `13` bản ghi `parser_object:observed` nằm ngoài 9 loại node chiếu — **không nằm trong 74 ca unresolved**).
  - `other_empty_projection_indices`: đúng `74` mẫu lịch sử (`4` `empty_timeout` + `70` `empty_worker_error`).

### 2.2. Đối chiếu ảo Hậu-B1 (`Virtual Post-B1`, không ghi đè baseline)

Khi chiếu chỉ đọc kết quả replay B1 lên 74 index lịch sử:
- **Đồ thị có node tăng từ `1,377` lên `1,448 / 1,452` (`99.72%`)**: `uncapped = 959`, **`capped = 489`** (`+24` mẫu replay chạm trần `200`), và chỉ còn **`4` đồ thị rỗng**:
  - `validation`: `290 / 291` (`99.66%`) — chỉ còn duy nhất `index 141` (`empty_projection_filtered`).
  - `test`: **`291 / 291` (`100.00%`)** — không còn mẫu rỗng (`52` mẫu chạm trần `200`).
  - `train`: `867 / 870` (`99.66%`) — còn `3` mẫu benign chạm `wall_timeout` (`292`, `407`, `749`).
  - `label = 1` (độc hại): **`800 / 800` (`100.00%`)** có đồ thị chiếu (`268` chạm trần `200`).

---

## 3. Phân tích Chuyên sâu `465` Mẫu Bị Cắt tại `node_cap = 200` (`489` Hậu-B1)

### 3.1. Quy mô cắt bỏ Node & Phát hiện Gốc rễ về "Ngập lụt Inline `pdf_object`"

Trên **`465` mẫu baseline bị cap**:
- **Tổng node đủ điều kiện (9 loại + `observed`) trước cap:** `367,506` (min `201`, median **`695.0`**, p95 **`1,553`**, max **`1,625`**).
- **Node giữ lại:** `93,000` (`200` node/mẫu).
- **Node bị loại bởi `node_cap = 200`:** **`274,506` node (`74.69%`)**; tỷ lệ mất node trên từng mẫu có median **`71.22%`**, p95 **`87.12%`**, max **`87.69%`**.

**Phân rã theo loại node (`by_kind`) và nguồn gốc (`by_origin`) trên 465 mẫu bị cap:**

| Phân loại | Đủ điều kiện trước cap | Giữ lại (`<200`) | Bị loại bởi cap (`>=200`) | Tỷ lệ bị loại trong nhóm cap | Số mẫu bị mất ít nhất 1 node loại này |
| --- | ---: | ---: | ---: | ---: | ---: |
| `pdf_object` | `355,324` | `87,856` | **`267,468`** | `75.27%` | `465 / 465` (100.0%) |
| `stream` *(nhạy cảm)* | `6,652` | `2,232` | **`4,420`** | **`66.45%`** | `356 / 465` (76.6%) |
| `page` | `1,577` | `671` | **`906`** | `57.45%` | `244 / 465` (52.5%) |
| `action` *(nhạy cảm)* | `1,351` | `679` | **`672`** | **`49.74%`** | `240 / 465` (51.6%) |
| `annotation` *(nhạy cảm)* | `583` | `226` | **`357`** | **`61.23%`** | `82 / 465` (17.6%) |
| `pages` | `791` | `487` | **`304`** | `38.43%` | `175 / 465` (37.6%) |
| `catalog` | `708` | `538` | **`170`** | `24.01%` | `123 / 465` (26.5%) |
| `filespec` *(nhạy cảm)* | `214` | `100` | **`114`** | **`53.27%`** | `70 / 465` (15.1%) |
| `script` *(nhạy cảm)* | `306` | `211` | **`95`** | **`31.05%`** | `83 / 465` (17.8%) |

**Phân rã theo nguồn gốc đối tượng (`by_origin`) trên 465 mẫu bị cap:**
- `direct_pypdf` (từ điển con / giá trị vô hướng nội tuyến `object_number = None`): `280,875` đủ ĐK (`77,922` giữ, `202,953` bỏ).
- `direct_mupdf` (giá trị nội tuyến từ nhánh sửa lỗi MuPDF): `61,531` đủ ĐK (`7,333` giữ, `54,198` bỏ).
- `indirect_pypdf` (đối tượng gián tiếp `N G obj` thật): chỉ **`20,283`** đủ ĐK (`6,980` giữ, `13,303` bỏ).
- `indirect_mupdf` (đối tượng gián tiếp MuPDF): chỉ **`4,817`** đủ ĐK (`765` giữ, `4,052` bỏ).

> **Phát hiện kiến trúc cốt lõi của B2:**
> - Các node nội tuyến không định danh (`direct_pypdf + direct_mupdf`) chiếm tới **`342,406 / 367,506` (`93.17%`)** tổng node đủ điều kiện và chiếm **`85,255 / 93,000` (`91.67%`)** ngân sách 200 slot đầu tiên!
> - Thực tế, **`464 / 465` mẫu baseline bị cap (`99.78%`, và `488 / 489` tức `99.80%` hậu-B1) có tổng số đối tượng PDF gián tiếp `<= 200` (tối đa chỉ `218`)**; đồng thời **`465 / 465` mẫu (`100%`) có tổng số node thuộc 8 loại thực thể ngữ nghĩa chuyên biệt (`catalog`, `pages`, `page`, `stream`, `action`, `script`, `annotation`, `filespec`) `<= 166`**!
> - Việc duyệt cây theo chiều sâu (`_Graph.child` trong `evidence_v9.py`) sinh node `pdf_object` cho mọi từ điển/scalar nội tuyến khiến ngân sách 200 node bị bão hòa sớm, đẩy **`5,658` node nhạy cảm bảo mật** (`stream`, `action`, `annotation`, `filespec`, `script`) trên **`373 / 465` mẫu (`80.22%`)** ra ngoài phạm vi mô hình (`390 / 489` mẫu và `5,861` node hậu-B1).

### 3.2. Tách biệt Cạnh bị loại do Khác View với Cạnh bị loại do Cap & Biến dạng Cấu trúc

Trên `465` mẫu baseline bị cap (`776,296` cạnh trong `evidence_store`):
1. **Cạnh loại do đầu mút nằm ngoài phép chiếu 9 loại (`excluded_edges_non_eligible_endpoint = 647,885`):**
   - Bao gồm cạnh đi qua container `kind = "array"` (`/Kids`, `/Annots`), bản ghi kiểm kê `parser_object`, hoặc `forensic_object_declaration`. Đây là đặc tả của phép chiếu 9 loại, **không phải lỗi parser**.
2. **Cạnh đủ điều kiện giữa hai node thuộc 9 loại `observed` (`eligible_edges_before_cap = 128,411`):**
   - **Giữ lại sau cap:** `37,420` cạnh (median `87.0`, p95 `130`, max `243`; không mẫu nào chạm `MAX_EDGES = 4,096`, `excluded_edges_edge_cap_total = 0`).
   - **Bị cắt bởi `node_cap = 200`:** **`90,991` cạnh (`70.86%`)**, gồm:
     - `one_endpoint_capped = 9,352` cạnh (cắt đứt liên kết trực tiếp từ một node được giữ `<200` tới node `>=200`).
     - `both_endpoints_capped = 81,639` cạnh (nằm hoàn toàn trong vùng bị cắt `>=200`).
   - Tỷ lệ mất cạnh đủ điều kiện trên từng mẫu có median **`57.95%`**, p95 **`87.67%`**, max **`96.63%`**.
3. **Độ méo cấu trúc trên chính tập node được giữ lại (`<200`):**
   - **Mất kết nối có hướng từ `catalog` (`kept_disconnected_from_catalog_by_cap`):** **`377` node được giữ** (trên `9` mẫu) vốn đi tới được từ `catalog` trước cap (qua cầu nối ở `>=200`) bị đứt đường đi từ `catalog` sau cap.
   - **Phát sinh node mồ côi giả tạo (`newly_orphaned_kept_nodes`):** **`32` node không phải `catalog`** (trên `25` mẫu; `35` node / `26` mẫu hậu-B1) có `in_degree > 0` trước cap bị tụt về `in_degree == 0` sau cap, **làm lật sai đặc trưng `is_orphan` của mô hình từ `0` sang `1`**.
   - **Phát sinh node cô lập hoàn toàn (`newly_isolated_kept_nodes`):** **`16` node** (trên `16` mẫu; `20` node hậu-B1) rơi về bậc `0`.
   - **Phân mảnh thành phần liên thông yếu trên tập giữ lại (`kept_fragmentation_wcc_gain`):** tăng thêm **`+25` thành phần liên thông** trên `19` mẫu do mất node cầu nối ở `>=200` (trong khi `wcc_delta` toàn cục đạt tổng `-191,914`, median `-311.0`, do xóa các cụm node rời nằm trên `>=200`).

---

## 4. Chốt Định nghĩa Kích thước Node Mô hình & Producer / Provenance

Trên toàn bộ **`171,055` node chiếu được giữ lại của baseline** (`179,799` node hậu-B1), 4 khái niệm kích thước được tách bạch tuyệt đối, không điền `0` giả và không tráo chéo:

| Khái niệm kích thước | Producer trong mã nguồn | Được phép làm đặc trưng PDF? | Baseline Known / Null (`171,055` node) | Hậu-B1 Known / Null (`179,799` node) | Tổng Bytes (Baseline) |
| --- | --- | --- | --- | --- | ---: |
| `legacy_semantic_size_bytes` | `record.details.size_bytes` (đang được `numeric_export.py` đọc) | `True` *(nhưng hiện rỗng)* | **`0` / `171,055`** (0.00%) | `0` / `179,799` (0.00%) | `0` |
| `verified_physical_declaration_span_bytes` | Khoảng nửa mở `[byte_start, byte_end)` của `forensic_object_declaration` (`source_space="original"`, `top_level_confirmed=true`) nối khớp nghiêm ngặt `(pypdf non-repaired, object_number, generation, byte_offset_start)` | `True` | **`5,900` / `165,155`** (3.45%) | `6,245` / `173,554` (3.47%) | `24,607,946` |
| `stream_raw_payload_bytes` | `record.details.raw_bytes` trên `StreamObject` (`evidence_v9.py`, thân stream mã hóa, không gồm `obj/endobj` và dict header) | `True` *(riêng cho `stream`)* | **`4,445` / `166,610`** (2.60% — **100% node `stream`**) | `4,682` / `175,117` (100% node `stream`) | `73,584,157` |
| `projected_json_storage_bytes` | `len(canonical_bytes(record))` (chi phí lưu trữ/truyền tải JSON UTF-8) | **`False` (Cấm dùng)** | `171,055` / `0` (100.0%) | `179,799` / `0` (100.0%) | `160,703,249` |

** Sổ cái lý do đầy đủ cho `verified_physical_declaration_span_bytes` trên `171,055` node giữ lại (`ambiguous_declaration_match = 0`):**
1. `direct_inline_object` (`111,159` node — `64.98%`): từ điển/scalar nội tuyến không có khai báo `N G obj ... endobj` độc lập trong đặc tả PDF → bắt buộc giữ `null` đối với physical declaration span.
2. `synthetic_repaired_backend` (`44,398` node — `25.96%`): đối tượng từ nhánh sửa lỗi `MuPDF` (`is_synthetic_repaired = true`), không nối chéo sang span byte thô để tránh gán sai lệch.
3. `no_matching_confirmed_original_declaration` (`7,015` node — `4.10%`): đối tượng gián tiếp `pypdf` nằm trong `/ObjStm` nén (`decoded_stream`) hoặc thuộc mẫu bị hết hạn `35 s` trước khi hoàn tất `raw_forensic`.
4. `measured` (`5,900` node — `3.45%`): đối tượng gián tiếp `pypdf` đối chiếu khớp tuyệt đối với khai báo vật lý gốc đã xác nhận.
5. `missing_verified_header_offset` (`1,455` node — `0.85%`): đối tượng gián tiếp `pypdf` thiếu `byte_offset_start` đã xác minh trong `xref`.
6. `script_derived_node` (`1,128` node — `0.66%`): node `kind = "script"` sinh từ phân tích mã kịch bản (có `details.length` riêng cho độ dài chuỗi script giải mã, không phải khai báo đối tượng PDF cấp cao).

---

## 5. Hàm ý Kỹ thuật cho Bước tiếp theo (`BUG-007B3` — Extraction Quality Gate)

1. **Hợp đồng kích thước node đã rõ nguồn gốc:** Không được lấy `projected_json_storage_bytes` thay cho kích thước đối tượng PDF và không zero-fill mù quáng `details.size_bytes` đang `null` 100%; bất kỳ đặc trưng kích thước nào đưa vào mô hình ở giai đoạn sau phải tách rõ channel đo được (`verified_physical_declaration_span_bytes` cho indirect object, `stream_raw_payload_bytes` cho `stream`, `script_length` cho `script`) kèm cờ hiện diện (`is_present` mask), giữ nguyên `null` ở tầng xuất kiểm định.
2. **Nguyên nhân chạm trần `200` đã được định vị chính xác:** `99.78%` mẫu bị cap thực chất có `<= 200` đối tượng PDF gián tiếp và `100%` có `<= 166` thực thể ngữ nghĩa chuyên biệt; sự mất mát `80.22%` mẫu chứa node nhạy cảm (`stream`/`action`/`annotation`/`filespec`/`script`) xuất phát từ việc trộn chung inline `pdf_object` không định danh vào cùng hạn ngạch 200 slot duyệt DFS. (Mọi thay đổi biểu diễn đồ thị hoặc chính sách node sẽ chỉ được đề xuất/thử nghiệm ở run riêng sau khi chốt `B3`, tuyệt đối không trộn vào lần đo này).
3. **Trọng tâm của `BUG-007B3` (Extraction Quality Gate):** Thiết lập cổng kiểm định chất lượng trích xuất được version hóa (`pdf-extraction-quality-v1` / gate xuất dữ liệu) phân định rõ điều kiện chấp nhận/từ chối/cảnh báo đối với: (a) đồ thị hợp lệ đủ điều kiện, (b) đồ thị bị cắt cụt mất node nhạy cảm hoặc bị timeout pha thứ cấp, và (c) `4` mẫu projection rỗng (`141` lọc projection + `292`, `407`, `749` timeout ở `train`), trước khi mở khóa xuất tensor hoặc huấn luyện lại.

Bằng chứng khóa:
- [`locked_methodology.json`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/locked_methodology.json)
- [`summary.json`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/summary.json)
- [`report.md`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/report.md)
- [`cases.jsonl`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/cases.jsonl)
- [`replay_overlay_cases.jsonl`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/replay_overlay_cases.jsonl)
- [`verification.json`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/verification.json)
- [`local_manifest.json`](../experiments/pdf_graph_truncation_audit/run_20261106T092752131513Z_dfafd888f7a9/local_manifest.json)

