# [BUG-XXX] Tiêu đề ngắn gọn mô tả bản chất kỹ thuật của lỗi

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-XXX` |
| **Ngày ghi nhận** | `YYYY-MM-DD` |
| **Trạng thái** | `RESOLVED` \| `MITIGATED` \| `UNDER_INVESTIGATION` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Dừng pipeline/crash) \| `HIGH` (Sai lệch feature/data leakage) \| `MEDIUM` (Cảnh báo/chậm hiệu năng) \| `LOW` (Thứ yếu) |
| **Phân loại lỗi** | `PARSER_SYNTAX` \| `CROSS_PLATFORM` \| `RESOURCE_OOM` \| `SECURITY_DESERIALIZATION` \| `ML_LEAKAGE` |
| **Thành phần ảnh hưởng** | Đường dẫn file hoặc module bị ảnh hưởng (vd: `src/malpdf/extract/stream.py`) |
| **Hồ sơ liên quan** | Commit hash, PR hoặc tài liệu liên quan |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Mô tả chính xác hoàn cảnh xuất hiện lỗi, câu lệnh thực thi, môi trường (Windows DEV hoặc REMnux LAB), và dấu hiệu nhận biết ban đầu.

### Log / Traceback chi tiết
```text
[Dán log lỗi, traceback hoặc tín hiệu crash tại đây]
```

### Điều kiện tái hiện (Reproduction Conditions)
- Đầu vào kích hoạt lỗi: (vd: stream nén với tỷ lệ nở > 100x, file PDF có cross-reference đệ quy, chạy test POSIX trên Windows)
- Môi trường kiểm thử: Windows 11 / Python 3.11 hoặc REMnux Ubuntu 24.04.

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

Không dừng lại ở việc mô tả bề mặt (như "lỗi tại dòng 45"). Hãy phân tích sâu bản chất kỹ thuật, kiến trúc và nguyên lý tầng sâu:

1. **Tại sao (Why 1)?** ...
2. **Tại sao (Why 2)?** ...
3. **Tại sao (Why 3)?** ...
4. **Tại sao (Why 4)?** ...
5. **Tại sao (Why 5 - Root Cause)?** ...

### Cơ chế kỹ thuật tầng sâu (Deep Mechanics)
- Giải thích cấu trúc dữ liệu, hành vi syscall, byte sequence của PDF spec, hoặc cơ chế quản lý bộ nhớ của OS/runtime dẫn đến lỗi này.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh
- Nêu rõ cách sửa "chữa cháy" bề mặt mà lập trình viên dễ mắc phải (như nuốt lỗi `except: pass`, tăng timeout vô tội vạ, hoặc bypass check).

### Giải pháp kỹ thuật chuẩn
- Trình bày kiến trúc hoặc thuật toán sửa triệt để.

### Minh họa Code Diff / Logic Thay thế
```diff
- // Đoạn code cũ có nguy cơ lỗi
+ // Đoạn code mới an toàn, có defensive check
```

---

## 4. Nguyên tắc Bất biến để Không Lặp lại (Anti-Regression Invariants)

Đặt ra các quy tắc bất biến (Invariants) mà bất kỳ kỹ sư hoặc AI Agent nào khi đọc cũng phải tuân thủ để không bao giờ tái phạm lỗi này:

1. **Quy tắc 1:** ...
2. **Quy tắc 2:** ...

---

## 5. Hợp đồng Kiểm thử Hồi quy (Regression Test Contract)

Mọi lỗi sau khi fix BẮT BUỘC phải đi kèm ít nhất một test case tự động để bảo vệ kho mã nguồn:

- **Tệp kiểm thử:** `tests/test_...py`
- **Hàm kiểm thử:** `test_...`
- **Cơ chế kiểm thử:** Sử dụng dữ liệu giả lập tổng hợp (synthetic fixture), không phụ thuộc malware thật, đảm bảo chạy an toàn và độc lập trên Windows DEV hoặc REMnux LAB.
