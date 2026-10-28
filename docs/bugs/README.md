# Bug Knowledge Base & Root Cause Registry

Hệ thống lưu trữ, phân tích chuyên sâu nguyên nhân gốc rễ và cơ chế phòng ngừa lỗi hồi quy (Anti-Regression) cho dự án `MalPDFDeepDetection`.

> **Triết lý Cốt lõi: "Không Phạm Một Lỗi Hai Lần"**
> 1. **Dừng quy trình khi gặp sự cố (Stop-the-Line):** Khi phát hiện lỗi bất thường hoặc test fail, dừng phát triển tính năng mới, tập trung khoanh vùng và cô lập bằng chứng.
> 2. **Chữa bệnh, không chữa triệu chứng (Root Cause > Symptom Patch):** Không "nuốt lỗi" bằng `except: pass`, không tăng timeout mù quáng. Bắt buộc tìm hiểu sâu cơ chế tầng dưới qua kỹ thuật 5 Whys.
> 3. **Ràng buộc bất biến (Anti-Regression Invariant):** Mọi bug đều phải được đúc kết thành quy tắc bất biến và chốt chặn bằng ít nhất một unit test tự động trước khi đóng task.

---

## 1. Bảng Tra cứu Nhanh Danh mục Lỗi (Bug Registry)

| Mã | Tiêu đề Lỗi | Phân loại | Mức độ | Trạng thái | Tệp Kiểm thử Hồi quy | Tài liệu Chi tiết |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `BUG-001` | Lỗi `os.pidfd_open` POSIX syscall không tương thích trên Windows DEV | `CROSS_PLATFORM` | `HIGH` | `RESOLVED` | `tests/test_local_agent.py` | [Chi tiết](BUG-001-linux-pidfd-on-windows.md) |
| `BUG-002` | Tràn bộ đệm metadata Arlington (512 KB) do bão vi phạm cú pháp lặp lại | `PARSER_SYNTAX` | `CRITICAL` | `RESOLVED` | `tests/test_arlington.py` | [Chi tiết](BUG-002-arlington-metadata-buffer-overflow.md) |
| `BUG-003` | Worker crash (SIGKILL / OOM) do Decompression Bomb và stream đệ quy | `RESOURCE_OOM` | `CRITICAL` | `RESOLVED` | `tests/test_stream_filters.py` | [Chi tiết](BUG-003-stream-decompression-bomb-sigkill.md) |

---

## 2. Quy trình Ghi nhận & Xử lý Lỗi Chuẩn

Khi phát hiện một bug mới hoặc một parser edge case lạ:

```
[1. Phát hiện & Tái hiện]
  ↳ Ghi nhận traceback, cô lập input gây lỗi bằng synthetic fixture (không dùng malware thật trên Windows)
        │
[2. Phân tích 5 Whys & Deep Mechanics]
  ↳ Đào sâu nguyên nhân gốc rễ: syscall, byte structure, memory allocation, recursion
        │
[3. Sửa mã nguồn & Thiết lập Invariant]
  ↳ Áp dụng giải pháp bền vững (Clean Fix), không vá chắp vá; đúc kết nguyên tắc bất biến
        │
[4. Viết Test Hồi quy (Regression Test)]
  ↳ Thêm test case tự động kiểm tra trường hợp biên vừa sửa
        │
[5. Lập Hồ sơ Lỗi]
  ↳ Tạo file mới `docs/bugs/BUG-XXX-<ten-ngan-gon>.md` dựa trên `docs/bugs/TEMPLATE.md`
        │
[6. Cập nhật Chỉ mục]
  ↳ Điền dòng mới vào Bảng Tra cứu Nhanh tại file README này
```

---

## 3. Tiêu chuẩn Biểu mẫu

Khi tạo tài liệu lỗi mới, luôn sao chép từ mẫu chuẩn:
👉 **[Mẫu Hồ sơ Phân tích Lỗi (TEMPLATE.md)](TEMPLATE.md)**
