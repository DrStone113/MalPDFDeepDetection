# [BUG-001] Lỗi `os.pidfd_open` POSIX Syscall Không Tương Thích Trên Windows DEV

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-001` |
| **Ngày ghi nhận** | `2026-10-28` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `HIGH` (Làm gián đoạn toàn bộ test suite cục bộ trên môi trường DEV) |
| **Phân loại lỗi** | `CROSS_PLATFORM` |
| **Thành phần ảnh hưởng** | `tests/test_local_agent.py`, `scripts/lab/local_agent.py` |
| **Hồ sơ liên quan** | Kiến trúc 2 môi trường (Windows DEV ↔ REMnux LAB) |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Khi chạy bộ kiểm thử đơn vị hoặc regression tests trên môi trường Windows 11 DEV bằng lệnh:
```powershell
pytest tests/test_local_agent.py
```
Toàn bộ các test case liên quan đến quản lý tiến trình SSH Agent (`test_invalid_pid_never_opens_or_signals`, `test_stale_cleanup_...`) đồng loạt gặp lỗi crash với cùng một thông báo ngoại lệ:

```text
E   AttributeError: <module 'os' (frozen)> has no attribute 'pidfd_open'
tests\test_local_agent.py:79: AttributeError
```

### Điều kiện tái hiện (Reproduction Conditions)
- Thực thi `pytest` trực tiếp trên hệ điều hành Windows (`sys.platform == 'win32'`).
- Tệp kiểm thử cố gắng thực hiện monkeypatching:
  ```python
  monkeypatch.setattr(local_agent.os, "pidfd_open", lambda *a: pytest.fail("Invalid PID"))
  ```

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

1. **Tại sao `pytest` bị lỗi `AttributeError`?**
   Vì đối tượng module `os` trên môi trường runtime hiện tại không có thuộc tính `pidfd_open`.
2. **Tại sao module `os` lại không có thuộc tính `pidfd_open`?**
   Vì Python runtime được biên dịch cho Windows không export hàm `pidfd_open`.
3. **Tại sao hàm này chỉ có trên Linux mà không có trên Windows?**
   Vì `pidfd_open` là một syscall đặc thù của Linux kernel (được giới thiệu từ Linux 5.3 và đưa vào CPython 3.9+ trong `posixmodule.c`). Hệ điều hành Windows sử dụng Win32 API với cơ chế `HANDLE` tiến trình (`OpenProcess`) chứ không có khái niệm file descriptor cho tiến trình (`pidfd`).
4. **Tại sao test suite trên Windows lại cố tình monkeypatch một syscall của Linux?**
   Vì người viết test suite giả định môi trường kiểm thử là Linux (môi trường của REMnux LAB), mà quên rằng **Windows DEV là Source of Truth** – nơi thực thi `pytest` chính trước khi đẩy code sang máy ảo.
5. **Tại sao lỗi này vi phạm nguyên tắc kiến trúc (Root Cause)?**
   Mã nguồn kiểm thử không có lớp trừu tượng hóa nền tảng (Platform Abstraction) và thiếu điều kiện lọc nền tảng (`sys.platform`), dẫn đến việc mã nguồn thiết kế cho Linux bị ép chạy trực tiếp trên Windows NT kernel.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh
- **Sai lầm 1:** Xóa bỏ hoàn toàn test case kiểm tra `pidfd` (làm mất kiểm soát chất lượng an toàn tiến trình trên môi trường LAB).
- **Sai lầm 2:** Tạo dummy attribute `os.pidfd_open = None` một cách bừa bãi trong mã nguồn production.

### Giải pháp kỹ thuật chuẩn
1. Trong file test (`test_local_agent.py`), bọc các bài test đòi hỏi `pidfd_open` bằng marker bỏ qua có điều kiện của `pytest`:
   ```python
   import sys
   import pytest

   requires_pidfd = pytest.mark.skipif(
       sys.platform == "win32" or not hasattr(os, "pidfd_open"),
       reason="Linux pidfd syscall required; not supported on Windows NT"
   )
   ```
2. Nếu hàm test bắt buộc phải monkeypatch `os.pidfd_open` trên cả môi trường không có Linux kernel để kiểm tra logic nhánh fallback, cần sử dụng cờ `raising=False` trong `monkeypatch.setattr`:
   ```python
   # Cho phép gán mock ngay cả khi attribute gốc chưa tồn tại trên Windows
   monkeypatch.setattr(local_agent.os, "pidfd_open", mock_handler, raising=False)
   ```
3. Trong mã nguồn production (`local_agent.py`), kiểm tra hỗ trợ tính năng (Feature Detection) thay vì kiểm tra phiên bản:
   ```python
   def is_pidfd_supported() -> bool:
       return hasattr(os, "pidfd_open")
   ```

---

## 4. Nguyên tắc Bất biến để Không Lặp lại (Anti-Regression Invariants)

1. **Nguyên tắc "Windows DEV là Source of Truth":** Toàn bộ file test nằm trong `tests/` phải luôn luôn vượt qua (Pass hoặc Skip hợp lệ) trên Windows 11 mà không được phép ném ra bất kỳ lỗi `AttributeError` hay `OSError` nào do khác biệt hệ điều hành.
2. **Feature Detection > Platform Assumption:** Không bao giờ gọi hoặc monkeypatch trực tiếp các hàm POSIX-only (`pidfd_open`, `fork`, `fcntl`, `symlink dangling`) mà không có `hasattr` guard hoặc `raising=False`.
3. **Phân định ranh giới Test Suite:** Các bài test can thiệp sâu vào kernel Linux phải được gắn `@pytest.mark.linux_only` hoặc cấu hình thực thi tự động qua SSH trên REMnux LAB.

---

## 5. Hợp đồng Kiểm thử Hồi quy (Regression Test Contract)

- **Tệp kiểm thử:** `tests/test_local_agent.py`
- **Cách xác nhận:** Chạy lệnh sau trên Windows DEV và kết quả phải trả về `PASSED` hoặc `SKIPPED`, tuyệt đối không có `FAILED`:
  ```powershell
  pytest tests/test_local_agent.py -k "pidfd"
  ```
