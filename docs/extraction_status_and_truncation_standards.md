# Chuẩn hóa Phân tách: Trạng thái Hệ thống vs Tín hiệu Dị thường & Truncation Standards

## 1. Bối cảnh và Nguyên nhân Gốc (Root Cause)

Trong pipeline trích xuất tĩnh đa tầng (`deep-static`), trước đây khi một thành phần trích xuất chạm các ngưỡng phòng vệ an toàn (chẳng hạn như tỷ lệ nở stream, số lượng vi phạm Arlington lặp lại, độ sâu AST của JavaScript làm rối mã, hoặc số lượng object đồ thị trang), toàn bộ mẫu bị đánh nhãn `status: resource_limit`.

Hệ quả là:
- Mẫu trích xuất thực tế đã cứu vãn và bảo toàn 100% đặc trưng cốt lõi (`primary_available = 100%`), nhưng lại hiển thị như một mẫu bị lỗi trích xuất hoặc crash.
- Các hành vi dị thường mang tính chủ đích của mã độc (như decompression bomb, flood lỗi cú pháp nhằm làm tràn bộ đệm parser, obfuscated AST recursion) bị coi là "điểm yếu của bộ trích xuất" thay vì được chuyển đổi thành **tín hiệu đặc trưng đầu vào** cho mô hình phân loại ML.

## 2. Chuẩn hóa Phân tách: Schema Đầu ra

Hệ thống phân tách rạch ròi 2 trường độc lập trong schema đầu ra (`bundle` và `coverage_report`):

### 2.1 Trạng thái Trích xuất (`extraction_status`)

| Trạng thái | Định nghĩa Kỹ thuật |
| --- | --- |
| `COMPLETE` | Pipeline đi hết luồng phân tích mà không chạm bất kỳ ngưỡng phòng vệ nào. |
| `BOUNDED_COMPLETE` | Đã chạm một hoặc nhiều ngưỡng cắt an toàn (cắt prefix stream, dừng đệ quy AST, giới hạn số lượng mẫu vi phạm cú pháp), nhưng bảo toàn 100% đặc trưng cốt lõi (`primary_available`) và hoàn tất xuất dữ liệu đúng hạn. |
| `TIMEOUT_PARTIAL` | Chạm ngưỡng thời gian wall-clock nhưng vẫn cứu (salvage) được dữ liệu và checkpoint đã phân tích trước đó. |
| `FAILED` | Crash worker (SIGKILL / Out-of-Memory OS), lỗi I/O nghiêm trọng, không thu được đặc trưng cốt lõi (`primary_available = False`). |

### 2.2 Cờ Đặc trưng Phòng vệ (`evasion_or_quota_flags`)

Toàn bộ các lần chạm trần được chuyển đổi thành Boolean/numerical features đưa trực tiếp vào `feature_store` dưới nhóm `parser_coverage`:

| Tên cờ (Feature Name) | Thay thế Lỗi Cũ | Ý nghĩa Dị thường Đối với Mô hình ML |
| --- | --- | --- |
| `flag_decompression_ratio_exceeded` | `decoded_byte_or_expansion_limit` | Dấu hiệu mạnh của PDF chứa zip bomb hoặc kỹ thuật heap spray qua stream nén. |
| `flag_spec_violation_flood` | `arlington_metadata_limit` | Dấu hiệu file bị fuzzing hoặc cố tình làm hỏng cấu trúc để làm tràn bộ đệm parser. |
| `flag_ast_complexity_truncated` | `ast_node_limit` / `ast_depth_limit` | Dấu hiệu rõ ràng của kỹ thuật JavaScript obfuscation (vòng lặp rác, lồng chuỗi sâu). |
| `is_truncated_stream` | `decoded_byte_limit` | Đánh dấu stream bị cắt ngắn ở ngưỡng dung lượng trần. |
| `flag_excessive_object_graph` | `pdf_structure_limit` / `graph_object_limit` | Dấu hiệu của đồ thị tham chiếu vòng (cyclic references) hoặc hàng chục nghìn object rác. |

## 3. Tiêu chuẩn Thu thập Đại diện (Representative Sampling & Truncation)

| Thành phần | Nguyên nhân Chạm trần Trước đây | Tiêu chuẩn Xử lý Mới |
| --- | --- | --- |
| **Arlington Validator** | Lưu lặp lại từng lỗi của hàng nghìn object giống nhau làm tràn bộ đệm metadata 512 KB. | **Deduplicate theo Rule ID (`model_table:model_line:category`)**: Mỗi quy tắc vi phạm chỉ lưu tối đa 5 mẫu bằng chứng đầu tiên (`first-5 exemplars`) kèm theo biến đếm `total_violation_count`. Xuất `arlington_total_violations` và `flag_spec_violation_flood` vào `feature_store`. |
| **Stream Decompression** | Cố giải nén toàn bộ stream cho đến khi chạm trần byte / expansion ratio. | **Windowed Prefix + Entropy**: Giải nén tối đa 64 KB đầu tiên (đủ nhận diện magic bytes, shellcode stub, hoặc JS). Nếu tỷ lệ nén vượt 100:1 hoặc dung lượng stream vượt 2 MB, lập tức dừng giải nén, tính Shannon entropy trên luồng nén, bật `flag_decompression_ratio_exceeded = True`, `is_truncated_stream = True`. |
| **JavaScript AST** | Duyệt toàn bộ cây cú pháp của mảng chuỗi nối dài hoặc vòng lặp rác. | **Depth & Breadth Bounding**: Cắt tỉa nhánh vượt quá `max_depth = 64` hoặc `max_nodes = 20,000` với chế độ `bounded=True`. Trích xuất thống kê bề mặt: `literal_strings_count`, `mean_string_length`, `string_literal_ratio` và bật `flag_ast_complexity_truncated = True`. |
| **Page Tree / Xref** | Tham chiếu vòng hoặc hàng chục nghìn object rác làm tiêu hao quota duyệt. | **Visited-Set & Object Budget**: Đặt `max_visited_objects = 10,000` và kiểm tra chu trình bằng Hash Set của `(obj_id, gen_id)`. Vượt quá số lượng object này thì dừng duyệt nhánh phụ, bật `flag_excessive_object_graph = True`. |

## 4. Khóa Cấu hình Tiêu chuẩn (Frozen Baseline Profile)

```json
{
  "wall_seconds": 60,
  "file_cpu_seconds": 45,
  "file_memory_bytes": 1073741824,
  "max_stream_bytes": 2097152,
  "total_stream_bytes": 16777216,
  "max_expansion_ratio": 100,
  "max_ast_nodes": 20000,
  "max_ast_depth": 64,
  "arlington_exemplars_per_rule": 5,
  "arlington_metadata_buffer_bytes": 524288,
  "max_visited_objects": 10000
}
```

### Tiêu chuẩn Nghiệm thu (Acceptance Criteria)
1. Tỷ lệ SIGKILL (tiến trình chết do crash OS): 0%.
2. Tỷ lệ `primary_available`: 100% đối với mọi file đọc được header.
3. Mọi trường hợp chạm các ngưỡng phòng vệ an toàn đều được phân loại là `BOUNDED_COMPLETE`, bảo toàn thông tin dị thường cho mô hình học máy.

---

## 5. Kiểm soát và Phòng ngừa 5 Rủi ro Kỹ thuật Thực chiến

Khi triển khai bộ tiêu chuẩn Bounded Static Extraction trên tập dữ liệu lớn và huấn luyện mô hình ML/DL, hệ thống thiết lập cơ chế kiểm soát cho 5 rủi ro kỹ thuật:

### 5.1 Rủi ro Lệch Phân phối Đặc trưng (Feature Distribution Shift) giữa các Batch
- **Thách thức:** Các đợt trích xuất cũ thiếu 5 cờ phòng vệ, thiếu các chỉ số AST mới và quy tắc Arlington bị cắt cụt không theo Rule ID.
- **Giải pháp:**
  - `normalize.py` hỗ trợ cơ chế backfill an toàn: tự động suy luận các cờ phòng vệ từ lý do lỗi cũ trong `coverage_report.limitations` nếu xử lý dữ liệu lịch sử.
  - Khuyến nghị chuẩn: Đồng bộ phiên bản code mới sang môi trường lab cách ly (REMnux) và thực hiện trích xuất lại theo một chuẩn Baseline Profile duy nhất để loại bỏ hoàn toàn hiện tượng lệch đặc trưng.

### 5.2 Rủi ro Điểm mù Cuối luồng (Tail-Payload Blind Spot) khi Cắt Stream
- **Thách thức:** Kỹ thuật chèn đệm rác/khoảng trắng (Zero/NOP padding) nhằm đẩy mã độc (`eval`, shellcode) xuống cuối stream sau mốc 64 KB.
- **Giải pháp:**
  - `filters.py` quét toàn bộ vùng đệm đã giải nén trong RAM trước khi cắt bằng danh sách từ khóa nguy hiểm: `eval`, `unescape`, `fromCharCode`, `exportDataObject`, `launchURL`. Kết quả được lưu vào `suspicious_keywords_found` trong metadata và tổng hợp tại `stream_analysis`.
  - Thay vì chỉ giữ 64 KB đầu, hệ thống lấy mẫu lưỡng cực: **Head (32 KB đầu) + Tail (32 KB cuối)**, phân cách bởi marker `\n/* ...MALPDF_STREAM_TRUNCATED... */\n`. Giới hạn dung lượng bundle bằng chứng vẫn đảm bảo tối đa 64 KB, nhưng bảo toàn payload ở đuôi luồng.

### 5.3 Rủi ro Che khuất Lỗi Thật khi Giám sát Telemetry
- **Thách thức:** Gộp hoàn toàn `bounded_complete` vào `observed` làm mất khả năng phát hiện độ trôi (drift) của bộ parser nếu xuất hiện lỗi vòng lặp hoặc quá tải bất thường.
- **Giải pháp:**
  - `lab_jobs.py` và `lab_runner.py` tách riêng một trường đếm `bounded_complete` độc lập trong telemetry (`pdf_summary.json` và shard summaries).
  - Về mặt bucket tổng thể, `bounded_complete` vẫn thuộc nhóm thành công (`observed`), nhưng trường đếm riêng cho phép giám sát trực tiếp tỷ lệ mẫu chạm trần trong từng batch.

### 5.4 Rủi ro Phụ thuộc Thứ tự Duyệt (Traversal-Order Bias) ở Giới hạn Object
- **Thách thức:** Tấn công bơm 15,000 indirect objects rác ở đầu file để làm cạn kiệt ngân sách duyệt trước khi chạm tới `/OpenAction` hay `/JavaScript`.
- **Giải pháp:**
  - `evidence_v9.py` thiết lập thứ tự duyệt **Priority-First**: luôn ưu tiên duyệt các nhánh kích hoạt nguy hiểm từ Catalog trước: `/Names` (`/JavaScript`) -> `/AcroForm` (`/XFA`) -> sau đó mới duyệt rộng ra `/Pages` và các tài nguyên tĩnh.
  - Đảm bảo 100% nhánh chứa mã thực thi được phân tích đầy đủ ngay cả khi đồ thị trang chạm mốc 10,000 objects.

### 5.5 Rủi ro Học vẹt (Shortcut Learning / Overfitting) trên Cờ Boolean
- **Thách thức:** Mô hình học máy coi cờ Boolean (`True`/`False`) là quy tắc cứng, dẫn đến báo động giả (False Positive) trên các tài liệu kỹ thuật hoặc bản vẽ CAD lớn.
- **Giải pháp:**
  - Xuất song song 3 đặc trưng liên tục (continuous ratios) vào `feature_store` dưới nhóm `parser_coverage`:
    - `arlington_violation_rate`: Tỷ lệ số vi phạm trên tổng số kiểm tra cú pháp đã thực hiện.
    - `stream_truncation_ratio`: Tỷ lệ số stream bị cắt ngắn trên tổng số stream phát hiện.
    - `object_graph_visited_ratio`: Tỷ lệ số object đã duyệt trên ngân sách tối đa 10,000 objects.
  - Phục vụ đánh giá FPR trên tập kiểm thử benign phức tạp (hard benign samples).

