# [BUG-003] Worker Crash (SIGKILL / OOM) Do Decompression Bomb Và Stream Đệ Quy

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-003` |
| **Ngày ghi nhận** | `2026-10-28` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Tiến trình worker bị hệ điều hành tiêu diệt đột ngột, làm hỏng IPC và rò rỉ tiến trình con) |
| **Phân loại lỗi** | `RESOURCE_OOM` |
| **Thành phần ảnh hưởng** | `src/malpdf/extract/stream.py`, `src/malpdf/extract/filters.py` |
| **Hồ sơ liên quan** | Quản lý tài nguyên VM và Worker Pool đa tiến trình |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Trong các đợt chạy bóc tách hàng loạt (batch extraction) trên máy ảo REMnux LAB:
- Một hoặc nhiều tiến trình con (worker process) biến mất đột ngột mà không ghi lại traceback Python thông thường.
- Tiến trình cha nhận được tín hiệu thoát `Exit Code: -9` (SIGKILL / Signal 9).
- Đường ống giao tiếp giữa các tiến trình (multiprocessing Queue / Pipe) bị nghẽn (broken pipe), dẫn đến toàn bộ worker pool bị deadlock hoặc treo vô thời hạn.

### Log / Traceback chi tiết
```text
Process WorkerProcess-3 died unexpectedly with exit code -9 (SIGKILL).
BrokenPipeError: [Errno 32] Broken pipe
Kernel dmesg: Out of memory: Killed process 41829 (python3) total-vm:4289124kB, anon-rss:3145728kB
```

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys & Deep Mechanics)

1. **Tại sao worker process bị SIGKILL?**
   Vì Linux Kernel Out-Of-Memory (OOM) Killer đã can thiệp và tiêu diệt tiến trình tiêu thụ RAM vượt quá giới hạn cgroups hoặc dung lượng RAM vật lý của máy ảo.
2. **Tại sao worker lại tiêu thụ hàng gigabyte RAM trong tích tắc?**
   Vì worker đang thực thi giải nén một đối tượng stream PDF (`/FlateDecode`) và nạp toàn bộ dữ liệu đã giải nén vào một biến `bytes` trong RAM.
3. **Tại sao một stream PDF lại có thể nở ra hàng gigabyte RAM?**
   Kẻ tấn công chủ đích chế tạo một **Decompression Bomb (PDF Zip Bomb)**: Dữ liệu nén chỉ có kích thước khoảng vài chục kilobyte (gồm các chuỗi byte lặp lại được nén tối ưu bằng thuật toán DEFLATE), nhưng khi giải nén bung ra hàng gigabyte byte `0x00`. Tỷ lệ nén (Expansion Ratio) đạt hơn 10.000 : 1.
4. **Tại sao bộ giải nén của parser lại không phát hiện điều này trước khi giải nén?**
   Mã nguồn sử dụng trực tiếp các hàm giải nén toàn phần như `zlib.decompress(data)` hoặc `stream.get_data()`. Thuật toán DEFLATE không lưu trước kích thước giải nén trong header, nên hàm giải nén sẽ tiếp tục cấp phát mảng byte mở rộng cho đến khi cạn kiệt RAM hệ thống.
5. **Tại sao điều này làm sụp đổ toàn bộ batch job (Root Cause)?**
   Thiếu cơ chế **Windowed Chunk Streaming** và thiếu ngưỡng an toàn chặn sớm (Early Bailout). Khi giải nén dữ liệu từ nguồn không tin cậy, hệ thống đã giả định dữ liệu luôn có kích thước hợp lý, biến worker thành nạn nhân của kỹ thuật tấn công cạn kiệt tài nguyên.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm / Anti-Pattern cần tránh
- Gọi `zlib.decompress(raw_bytes)` trực tiếp không có đối số giới hạn.
- Tăng RAM của máy ảo từ 8 GB lên 32 GB (không giải quyết được gốc rễ vì decompression bomb có thể nở ra hàng trăm GB).

### Giải pháp kỹ thuật chuẩn
Áp dụng cơ chế **Windowed Prefix + Expansion Ratio Guard**:

1. **Windowed Prefix Decompression (Trần 64 KB):**
   - Chỉ giải nén tối đa 64 KB đầu tiên của stream (`max_prefix_bytes = 65536`).
   - Dung lượng 64 KB là hoàn toàn đủ để nhận diện magic bytes, header file nhúng, shellcode stub NOP sled, hoặc JavaScript code.
2. **Expansion Ratio Guard (Tỷ lệ 100:1):**
   - Sử dụng đối tượng streaming `zlib.decompressobj()`.
   - Vừa đọc vừa đếm số byte nở ra so với số byte nén đầu vào.
   - Nếu tỷ lệ nở vượt quá `100:1` hoặc stream giải nén vượt quá 2 MB, lập tức ngắt giải nén (`abort`).
3. **Chuyển đổi thành Đặc trưng Phân loại:**
   - Khi kích hoạt ngắt giải nén sớm:
     - Tính Shannon Entropy trực tiếp trên luồng byte nén thô.
     - Đặt cờ đặc trưng:
       ```python
       feature_store["flag_decompression_ratio_exceeded"] = True
       feature_store["is_truncated_stream"] = True
       ```
     - Chuyển trạng thái mẫu thành `BOUNDED_COMPLETE` thay vì để worker bị SIGKILL.

---

## 4. Nguyên tắc Bất biến để Không Lặp lại (Anti-Regression Invariants)

1. **Tuyệt đối Cấm Gọi `zlib.decompress` Không Giới Hạn:** Không bao giờ gọi `zlib.decompress`, `bz2.decompress` hoặc các hàm tương đương trên stream không tin cậy mà không truyền tham số giới hạn bộ đệm tối đa (`max_length`).
2. **Hard Ceiling về Tỷ lệ Nở (Expansion Ratio Cap = 100):** Mọi bộ giải mã stream trong `src/malpdf/extract/` phải có cơ chế đếm byte đầu vào/đầu ra và ngắt ngay lập tức khi tỷ lệ nở vượt quá 100 lần.
3. **Bảo vệ Vòng Đời Worker:** Mọi thao tác I/O hoặc bóc tách nặng phải được bọc trong context manager có timeout cục bộ và bắt ngoại lệ bộ nhớ mềm trước khi OS OOM Killer can thiệp.

---

## 5. Hợp đồng Kiểm thử Hồi quy (Regression Test Contract)

- **Tệp kiểm thử:** `tests/test_stream_filters.py`
- **Hàm kiểm thử:** `test_stream_decompression_bomb_truncated_safely`
- **Yêu cầu kiểm thử:** Tạo một synthetic stream bằng `zlib.compress(b"\x00" * 10_000_000)`. Bộ trích xuất phải dừng giải nén ở $\le 64 \text{ KB}$, tiêu tốn dưới 5 MB RAM, thực thi dưới 20 ms, và bật cờ `flag_decompression_ratio_exceeded = True`.
