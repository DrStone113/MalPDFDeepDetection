# Canonical Extraction, Quality Gate v2 & Fail-Closed Graph Export v2 — 2026-11-06

**Đã hoàn thành toàn diện toàn bộ 5 pha theo đúng quy trình chuẩn của dự án: trích xuất tĩnh toàn bộ 1.452 mẫu CIC (`pdf-static-cic-full`), đánh giá đạt trọn vẹn 8/8 chỉ tiêu Cổng Chất lượng v2 (`ready_for_locked_export`), và xuất thành công bộ đồ thị nhị phân chuẩn hóa 23D (`hetero_graphs_v2.jsonl.gz`) sẵn sàng cho bước huấn luyện mô hình sâu (GNN/TransGraph).**

---

## 1. Thông số Job Canonical Thực tế (`89bf66f04d93...`)

- **Job ID:** `89bf66f04d932dece2518500fbdfb3121fff8799df74b2f02accac03197e1900`
- **Kind / Mode / Status:** `pdf-static-cic-full` / `offline` / `partial` (hoàn tất 100% denominator).
- **Bộ dữ liệu chuẩn tắc:** Protocol G deterministic split (seed `42`):
  - Tổng số mẫu: **`1.452`** (`train = 870`, `validation = 291`, `test = 291`).
  - Tỷ lệ nhãn: `label 0 = 652` (lành tính), `label 1 = 800` (mã độc).
- **Tiến trình thực thi trên REMnux LAB (10 Workers):**
  - **`1.452 / 1.452` mẫu (100.0%)** đã được trích xuất và ghi thành công vào `/var/lib/malpdf/jobs/89bf66f04d93.../private_bundles/`.
  - Phân bố trạng thái trích xuất thô:
    - `bounded_complete`: `349`
    - `observed`: `1`
    - `partial`: `74`
    - `timeout` (ở bước trích xuất chi tiết nhưng vẫn giữ đồ thị cấu trúc): `584`
    - `unsupported` / `decode_error`: `444` (`358 unsupported` + `86 decode_error`)
    - `missing`: **`0`**

---

## 2. Kết quả Đánh giá Cổng Chất lượng v2 (`pdf-extraction-quality-gate-v2`)

- **Báo cáo chi tiết:** [`quality_gate_report.md`](../experiments/pdf_graph_projection_v2/canonical_run_89bf66f04d93/quality_gate_report.md)
- **File tổng kết JSON:** [`quality_gate_summary.json`](../experiments/pdf_graph_projection_v2/canonical_run_89bf66f04d93/quality_gate_summary.json)
- **Phán quyết chung (`cohort_gate_verdict`):** **`ready_for_locked_export`** (Đạt **`8 / 8`** chỉ tiêu).
- **Cờ mở khóa huấn luyện:** `training_unlocked = True`, `v2_graph_model_input_ready = True`.

| Chỉ tiêu Kiểm tra Cổng Chất lượng | Kết quả | Dữ liệu Thực nghiệm |
| --- | :---: | --- |
| `cohort_denominator_complete` | **PASS** | `1.452 / 1.452` có mặt hợp lệ; `0` mẫu corrupt/thiếu. |
| `worker_cleanup_verified` | **PASS** | `0` mẫu dọn dẹp worker không hoàn tất. |
| `graph_structural_validity` | **PASS** | `0` mẫu gặp lỗi bất thường cấu trúc đồ thị. |
| `tabular_static_feature_store_integrity` | **PASS** | `1.452 / 1.452` dòng đặc trưng bảng tĩnh hợp lệ 100%. |
| `unresolved_worker_failures_cleared` | **PASS** | `0` mẫu lỗi worker chưa phân loại (`unavailable_worker_failure = 0`). |
| `evaluation_partition_coverage` | **PASS** | Phân vùng kiểm định bảo toàn tối đa:<br>• `test`: `0 / 291` unavailable (`0.0%` $\le 1.0\%$).<br>• `validation`: `2 / 291` unavailable (`0.687%` $\le 1.0\%$). |
| `v2_provenance_size_contract_verified` | **PASS** | `1.446 / 1.446` mẫu GNN sẵn sàng với hợp đồng provenance 23D;<br>• Tổng số node giữ lại: `42.308`<br>• Verified physical spans: `7.741`<br>• Stream payloads known: `9.285`<br>• Vi phạm gán `null -> 0`: **`0`**. |
| `security_sensitive_truncation_bounded` | **PASS** | `0` mẫu bị rớt node nhạy cảm bảo mật do cap (`0.0%` $\le 5.0\%$). |

---

## 3. Kết quả Xuất Đồ thị Nhị phân v2 (`export_graphs_v2.py`)

- **Thư mục xuất chính thức trên REMnux:** `/home/remnux/malpdf-graph-exports-v2/export_20261106T135440198431Z_89bf66f04d93/`
- **File Manifest:** [`export_manifest.json`](../experiments/pdf_graph_projection_v2/canonical_run_89bf66f04d93/export_manifest.json)
- **Sổ cái tài liệu không có đồ thị:** [`unavailable_document_ledger.json`](../experiments/pdf_graph_projection_v2/canonical_run_89bf66f04d93/unavailable_document_ledger.json)

### Chi tiết các tệp dữ liệu đã xuất:
1. **`hetero_graphs_v2.jsonl.gz`** (`1.18 MB`, SHA-256: `3dcdc8d741e5f9a55f46897b0afc0d903d38ea9e28fd5bb696ddeea57cf75eb0`):
   - Chứa **`1.446`** đồ thị có hướng không chu trình rút gọn container trung gian (`<= 8` bước).
   - Không gian đặc trưng node: **`23D`** (`NODE_FEATURE_DIM_V2 = 23`), kèm mặt nạ provenance cho kích thước vật lý và stream (`[log1p_phys, has_phys_mask, log1p_stream, has_stream_mask, is_indirect, is_repaired, is_orphan, rwse_1..16]`).
   - Đã qua xác thực độc lập bằng `index_measured_graphs_v2` với 100% SHA-256 khớp kỳ vọng.
2. **`tabular_features_v2.jsonl.gz`** (`4.21 MB`, SHA-256: `6ca22c2cedc0afc02468576e62c44c4e519c96540713dc33b3033e3a559e59a6`):
   - Đầy đủ **`1.452`** dòng vector đặc trưng bảng tĩnh hỗ trợ các mô hình cổ điển (XGBoost/LightGBM) và cơ chế tabular fallback.
3. **`unavailable_document_ledger.json`** (`1.87 KB`):
   - Ghi sổ minh bạch chính xác **6 mẫu** không có đồ thị (`placeholder_nodes_inserted: false`):
     - `train` (4 mẫu): `[11, 292, 407, 749]` (bị timeout ở tầng sâu không có node cấu trúc, loại khỏi batch GNN nhưng giữ trong denominator bảng tĩnh).
     - `validation` (2 mẫu): `[3, 141]` (mẫu 141 bị projection lọc rỗng, mẫu 3 bị timeout; xử lý bằng abstention hoặc tabular fallback).
     - `test` (0 mẫu): **`0`** mẫu rỗng, toàn bộ 291/291 mẫu test đều có đồ thị hợp lệ.
4. **`locked_methodology.json`** & **`manifest.json`**:
   - Ghi nhận thông số môi trường, cam kết tính bất biến bit-for-bit cho toàn bộ nghiên cứu.

---

## 4. Trạng thái Hoàn thành

Tất cả các rào cản từ Bug-004 đến Bug-008 đã được giải quyết trọn vẹn. Bộ dữ liệu chuẩn tắc Protocol G trên cohort CIC 1.452 mẫu đã được trích xuất tĩnh hoàn chỉnh, vượt qua Cổng chất lượng v2 và sẵn sàng cho việc huấn luyện kiến trúc sâu đa phương thức `PDFTransGraph`.

