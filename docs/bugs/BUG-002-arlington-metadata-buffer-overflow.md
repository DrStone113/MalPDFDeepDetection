# [BUG-002] Tràn Bộ Đệm Metadata Arlington (512 KB) Do Bão Vi Phạm Cú Pháp Lặp Lại

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-002` |
| **Ngày ghi nhận** | `2026-10-28` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Biến mẫu thành công thành lỗi trích xuất `resource_limit`, làm mất nhãn và đặc trưng) |
| **Phân loại lỗi** | `PARSER_SYNTAX` |
| **Thành phần ảnh hưởng** | `src/malpdf/extract/arlington_validator.py`, `tests/test_arlington.py` |
| **Hồ sơ liên quan** | [Chuẩn hóa Phân tách Trạng thái vs Tín hiệu Dị thường](../extraction_status_and_truncation_standards.md) |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Khi chạy pipeline bóc tách tĩnh đa tầng (`deep-static`) trên các mẫu PDF độc hại thực tế hoặc mẫu bị fuzzing cú pháp:
- Quá trình trích xuất Arlington Validator bị hủy ngang do chạm ngưỡng giới hạn bộ nhớ đệm `arlington_metadata_buffer_bytes = 524288` (512 KB).
- Toàn bộ kết quả mẫu bị gán nhãn trạng thái thất bại: `status: resource_limit` kèm lý do `arlington_metadata_limit`.
- Mặc dù 100% đặc trưng cấu trúc cốt lõi (`primary_available = True`) đã được bóc tách hoàn chỉnh, mẫu vẫn bị coi là lỗi bộ trích xuất (parser fault) thay vì một mẫu hoàn thành có phát hiện hành vi né tránh (evasion).

### Log / Traceback chi tiết
```text
ExtractionResourceLimitExceeded: Arlington validator metadata buffer exceeded quota (524288 bytes).
Pipeline halted for sample 4a7c8b...
Status marked as resource_limit (reason: arlington_metadata_limit).
```

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

1. **Tại sao bộ đệm 512 KB bị tràn?**
   Vì bộ validator cố gắng serialize và ghi lại hàng nghìn chuỗi thông báo lỗi vi phạm cấu trúc PDF vào một mảng JSON metadata duy nhất.
2. **Tại sao lại có hàng nghìn thông báo vi phạm?**
   Vì file PDF độc hại chứa hàng nghìn object (vd: các `/FontDescriptor` hoặc `/ColorSpace` giả mạo) cùng vi phạm một quy tắc ngữ nghĩa trong bộ đặc tả Arlington.
3. **Tại sao mã độc lại chứa nhiều object vi phạm giống nhau như vậy?**
   Kẻ tấn công sử dụng kỹ thuật **Spec Violation Flood** (chủ đích chèn cú pháp rác hoặc dùng fuzzer) nhằm gây cạn kiệt bộ nhớ và từ chối dịch vụ (DoS) đối với các engine phân tích PDF của các phần mềm bảo mật.
4. **Tại sao pipeline phân tích lại lưu trữ từng chuỗi lỗi riêng rẽ?**
   Thiết kế ban đầu lưu trữ mộc (un-deduplicated error strings): mỗi khi phát hiện một vi phạm, hệ thống lại nối một chuỗi mô tả dài hàng trăm ký tự vào danh sách, dẫn đến độ phức tạp không gian bộ nhớ tăng tuyến tính $O(N)$ theo số lượng object vi phạm.
5. **Tại sao việc chạm ngưỡng lại làm hỏng trạng thái trích xuất của mẫu (Root Cause)?**
   Kiến trúc cũ đã đồng nhất hóa (conflate) giữa **"Lỗi của công cụ trích xuất"** và **"Hành vi dị thường của mã độc"**. Thay vì coi việc flood vi phạm là một *đặc trưng tấn công (attack feature)*, hệ thống lại tự phạt chính mình bằng cách đánh nhãn crash/resource_limit.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh
- Tăng mù quáng dung lượng bộ đệm từ 512 KB lên 10 MB, 50 MB (chỉ dời điểm chết ra xa hơn, khiến worker dễ bị OOM OS và SIGKILL).
- Bỏ qua hoàn toàn (silent ignore) lỗi vi phạm của Arlington sau khi chạm giới hạn.

### Giải pháp kỹ thuật chuẩn
Hệ thống áp dụng chuẩn **Representative Sampling & Rule Deduplication**:

1. **Deduplicate theo Rule ID (`model_table:model_line:category`):**
   - Không lưu chuỗi văn bản tự do lặp lại.
   - Nhóm các vi phạm theo mã định danh duy nhất của quy tắc Arlington.
2. **First-5 Exemplars:**
   - Mỗi Rule ID chỉ lưu trữ tối đa 5 mẫu bằng chứng cấu trúc đầu tiên (`first-5 exemplars`).
   - Kèm theo một bộ đếm số nguyên gọn nhẹ: `total_violation_count`.
3. **Chuyển đổi thành Đặc trưng Phân loại (Feature Engineering):**
   - Đưa biến đếm tổng `arlington_total_violations` vào `feature_store`.
   - Nếu số lượng vượt ngưỡng, bật cờ đặc trưng:
     ```python
     feature_store["flag_spec_violation_flood"] = True
     ```
   - Chuyển trạng thái xuất xưởng của mẫu thành `BOUNDED_COMPLETE` (bảo toàn 100% dữ liệu chính mà không bị tính là lỗi).

---

## 4. Nguyên tắc Bất biến để Không Lặp lại (Anti-Regression Invariants)

1. **Nguyên tắc "Không Lưu Chuỗi Không Giới Hạn":** Mọi thành phần validator/linter cú pháp không bao giờ được phép lưu trữ danh sách unbounded string logs từ đầu vào không tin cậy. Bắt buộc phải nhóm theo Rule Key và áp dụng trần kích thước mẫu (Exemplar Cap $\le 5$).
2. **Biến Cố Gắng DoS Thành Tín Hiệu Nhận Dạng:** Khi một mẫu PDF cố tình làm quá tải parser (bão cú pháp, recursion, chuỗi rác), hệ thống trích xuất phải ngắt an toàn và đóng gói hành vi đó thành một cờ Boolean dị thường phục vụ mô hình học máy.
3. **Phân tách Rạch ròi Status vs Feature:** Trạng thái `FAILED` chỉ dành cho worker crash hoặc mất dữ liệu cốt lõi; mọi trường hợp cắt tỉa có kiểm soát mà bảo toàn được đặc trưng đều phải trả về `BOUNDED_COMPLETE`.

---

## 5. Hợp đồng Kiểm thử Hồi quy (Regression Test Contract)

- **Tệp kiểm thử:** `tests/test_arlington.py`
- **Hàm kiểm thử:** `test_arlington_violation_flood_bounded`
- **Yêu cầu kiểm thử:** Tạo một synthetic PDF chứa 2.000 object cùng vi phạm một Arlington rule. Bộ validator phải hoàn tất dưới 50 ms, dung lượng metadata $\le 32 \text{ KB}$, và cờ `flag_spec_violation_flood` được bật `True`.
