# Kế Hoạch Chi Tiết Phát Triển 3 Trụ Cột Extractor (JBIG2, Visual Text Semantics, Arlington Conformance)

Tài liệu này xác định kiến trúc, tiêu chuẩn kỹ thuật, các trường đặc trưng sinh ra và kế hoạch kiểm thử theo phương pháp Test-Driven Development (TDD) cho ba trụ cột mở rộng của bộ trích xuất tĩnh `malpdf.extraction`.

---

## Trụ Cột 1: Bộ Phân Tích Cấu Trúc JBIG2 (`jbig2_structure`)

### 1. Bối cảnh & Mục tiêu bảo mật
- **Chuẩn kỹ thuật:** ITU-T T.88 / ISO/IEC 14492 và PDF 1.4-2.0 (`/Filter /JBIG2Decode`, `/JBIG2Globals`).
- **Rủi ro khai thác thực tế:** Kỹ thuật khai thác zero-click (điển hình như FORCEDENTRY của NSO Group) lợi dụng bộ giải nén JBIG2 để xây dựng các cổng logic (logic gates) bằng cách xâu chuỗi phân đoạn generic region và refinement region, gây tràn số nguyên (integer overflow) và ghi đè bộ nhớ heap mà không cần JavaScript.
- **Mục tiêu mô-đun:** Bóc tách toàn bộ khung phân đoạn (segment framing), cờ điều khiển, đồ thị phụ thuộc phân đoạn (referred-to segment graph) và kích thước trang tĩnh mà không thực thi mã giải nén pixel không an toàn.

### 2. Thiết kế kỹ thuật
- **Vị trí tệp:** `src/malpdf/extraction/media.py` (hàm `jbig2_structure`), `src/malpdf/extraction/carving.py` (`artifact_kind`), `src/malpdf/extraction/image_codecs.py` (`decode_image`), `src/malpdf/extraction/filters.py` (`decode_filters`).
- **Cấu trúc dữ liệu trả về:**
  ```python
  {
      "format": "jbig2",
      "complete": bool,
      "reason_codes": list[str],
      "has_file_header": bool,
      "file_organization": str,  # "sequential" | "random_access"
      "number_of_pages_known": bool,
      "declared_pages": int | None,
      "segment_count": int,
      "segment_types_present": dict[str, int],
      "segments": list[dict],    # metadata từng segment
      "width": int | None,       # từ Page Information segment (type 48)
      "height": int | None,      # từ Page Information segment (type 48)
      "components": 1,
      "bits_per_component": 1,
      "has_end_of_file": bool,
      "scope": "JBIG2 segment framing, headers and referred-to segment graph only; no image rendering or decompression"
  }
  ```
- **Các dấu hiệu bất thường (Anomaly & Exploit Reason Codes):**
  - `jbig2_forward_segment_reference`: Phân đoạn tham chiếu tới phân đoạn có số hiệu lớn hơn hoặc bằng chính nó.
  - `jbig2_duplicate_segment_number`: Trùng lặp số hiệu phân đoạn.
  - `jbig2_unknown_segment_type`: Loại phân đoạn nằm ngoài dải chuẩn 0..62.
  - `jbig2_segment_header_truncated`: Dữ liệu header bị cắt cụt.
  - `jbig2_segment_truncated`: Độ dài thân phân đoạn thực tế nhỏ hơn `size_bytes` khai báo.
  - `jbig2_excessive_reference_count`: Số lượng tham chiếu vượt quá ngưỡng an toàn.
  - `image_trailing_data`: Dữ liệu byte thừa sau phân đoạn End of File (type 51).

### 3. Kế hoạch kiểm thử (TDD)
- **Tệp kiểm thử:** `tests/test_extraction_media.py`.
- **Bộ fixture tổng hợp:**
  - File JBIG2 chuẩn có header 8-byte `\x97JB2\r\n\x1a\n` và 3 segment (Page Information, Immediate Generic Region, End of File).
  - Luồng JBIG2 nhúng (không header 8-byte) theo chuẩn PDF.
  - Luồng chứa tham chiếu tiến trái phép (forward reference).
  - Luồng chứa số hiệu segment trùng lặp hoặc loại segment lạ.
  - Luồng bị cắt cụt và luồng có dữ liệu rác sau EOF.

---

## Trụ Cột 2: Phân Tích Content Stream & Văn Bản Ẩn (`content_stream.py`)

### 1. Bối cảnh & Mục tiêu bảo mật
- **Chuẩn kỹ thuật:** ISO 32000-1 Mục 9 ("Text") và Mục 8 ("Graphics").
- **Kỹ thuật tấn công:**
  - Chèn từ khóa độc hại hoặc spam SEO/phishing bằng chữ vô hình (`Tr 3` - Neither fill nor stroke).
  - Thu nhỏ chữ về kích thước bằng 0 (`Tf /F1 0`).
  - Đặt màu chữ trùng màu nền (trắng trên nền trắng `#FFFFFF`).
  - Đặt tọa độ chữ nằm ngoài khung trang (`/MediaBox` / `/CropBox`).
  - Đặt Anchor Text hiển thị là tên miền ngân hàng uy tín nhưng toán tử liên kết trỏ tới URL lừa đảo.
- **Mục tiêu mô-đun:** Quét cú pháp luồng nội dung trang tĩnh (Content Stream), nhận diện trạng thái hiển thị của từng ký tự và định lượng tỷ lệ văn bản ẩn bất thường.

### 2. Thiết kế kỹ thuật
- **Vị trí tệp:** `src/malpdf/extraction/content_stream.py`.
- **Cấu trúc dữ liệu trả về:**
  ```python
  {
      "format": "content_stream",
      "complete": bool,
      "reason_codes": list[str],
      "operator_counts": dict[str, int],
      "total_characters": int,
      "invisible_characters": int,
      "invisible_ratio": float,
      "has_text_rendering_mode_3": bool,
      "has_zero_font_size": bool,
      "has_off_page_text": bool,
      "has_white_on_white_text": bool,
      "text_blocks": list[dict],
      "scope": "static page content stream inspection without rendering engine execution"
  }
  ```
- **Toán tử được nhận diện:**
  - Văn bản: `BT`, `ET`, `Tf`, `Tr`, `Ts`, `Tl`, `Tc`, `Tw`, `Tz`.
  - Vị trí: `Tm`, `Td`, `TD`, `T*`.
  - Hiển thị: `Tj`, `'`, `"`, `TJ`.
  - Màu sắc: `g`, `G`, `rg`, `RG`, `k`, `K`, `cs`, `CS`, `sc`, `SC`, `scn`, `SCN`.
  - Đối tượng ngoài: `Do` (XObject Form/Image).

### 3. Kế hoạch kiểm thử (TDD)
- **Tệp kiểm thử:** `tests/test_content_stream.py`.
- **Bộ fixture tổng hợp:**
  - Stream văn bản hiển thị bình thường.
  - Stream sử dụng `3 Tr` trước khối văn bản ẩn.
  - Stream sử dụng font size 0 hoặc ma trận scale 0.
  - Stream đặt màu trắng `1 1 1 rg` trên nền mặc định.
  - Stream đặt tọa độ `99999 99999 Td` ngoài trang.

---

## Trụ Cột 3: Mở Rộng Arlington Predicates & Conformance Engine

### 1. Bối cảnh & Mục tiêu kỹ thuật
- **Chuẩn kỹ thuật:** Bộ danh mục Arlington PDF Model đã khóa tại commit `b7d880b` (610 TSV, 3976 quy tắc).
- **Mục tiêu mô-đun:** Bổ sung các hàm vị từ (predicates) còn thiếu trong `arlington_expression.py` để giảm tỷ lệ `Unknown`, nâng cao độ bao phủ kiểm chứng hợp chuẩn trên các từ điển then chốt (`/Catalog`, `/Pages`, `/Encrypt`, `/Action`, `/Annot`).

### 2. Danh mục Predicate cần bổ sung
- `fn:ArrayLength(arg)`: Trả về độ dài mảng (kiểu `Decimal`), bảo đảm an toàn với Unknown và giới hạn bước tính toán.
- `fn:IsNumber(arg)`: Kiểm tra một đối số có phải là số hay không.
- `fn:DefaultValue(default, expr)`: Trả về `expr` nếu khác null/vắng mặt; ngược lại trả về `default`.
- `fn:PageCount()` / `fn:PageNumber()`: Trả về số trang từ ngữ cảnh nếu có.
- `fn:RequiredValue(val, required_val)`: So sánh giá trị bắt buộc với giá trị thực tế.

### 3. Kế hoạch kiểm thử (TDD)
- **Tệp kiểm thử:** `tests/test_arlington.py`.
- **Bộ fixture tổng hợp:**
  - Kiểm thử từng hàm với kiểu dữ liệu hợp lệ, mảng rỗng, giá trị Unknown, vượt ngân sách bước tính toán.
  - Kiểm chứng tính bất biến ba giá trị (Three-valued logic: True, False, Unknown).
  - Smoke test với danh mục TSV thực tế của Arlington.

---

## Lộ Trình Triển Khai Tuần Tự (Implementation Milestones)

| Bước | Mô-đun | Nhiệm vụ chính | Tệp tác động |
| :--- | :--- | :--- | :--- |
| **B1** | **Trụ cột 1 (JBIG2)** | Xây dựng `jbig2_structure` trong `media.py` kèm fixture kiểm thử TDD | `src/malpdf/extraction/media.py`<br>`tests/test_extraction_media.py` |
| **B2** | **Trụ cột 1 (Tích hợp)** | Đấu nối JBIG2 vào `carving.py`, `image_codecs.py` và `filters.py` | `src/malpdf/extraction/carving.py`<br>`src/malpdf/extraction/image_codecs.py`<br>`src/malpdf/extraction/filters.py` |
| **B3** | **Trụ cột 2 (Content Stream)** | Xây dựng `content_stream.py` bóc tách toán tử text, phát hiện text ẩn/tr3/font 0 | `src/malpdf/extraction/content_stream.py`<br>`tests/test_content_stream.py` |
| **B4** | **Trụ cột 3 (Arlington)** | Cài đặt `ArrayLength`, `IsNumber`, `DefaultValue` trong `arlington_expression.py` | `src/malpdf/extraction/arlington_expression.py`<br>`tests/test_arlington.py` |
| **B5** | **Xác minh & Nghiệm thu** | Chạy toàn bộ test suite trên Windows DEV, đối chiếu an toàn và cập nhật research log | `reports/research_log.md` |
