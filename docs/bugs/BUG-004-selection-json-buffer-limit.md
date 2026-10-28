# [BUG-004] Worker Crash (worker_failed) Do Giới Hạn Đọc selection.json (512 KB) Khi Chạy Full Batch 1,452 Mẫu

## Thông tin Chung

| Mục | Chi tiết |
| --- | --- |
| **Mã định danh** | `BUG-004` |
| **Ngày ghi nhận** | `2026-10-28` |
| **Trạng thái** | `RESOLVED` |
| **Mức độ nghiêm trọng** | `CRITICAL` (Toàn bộ 5 worker crash ngay tại giây thứ 7 khi bắt đầu job) |
| **Phân loại lỗi** | `RESOURCE_OOM` / `BUFFER_OVERFLOW` (Cứng giới hạn buffer đọc metadata) |
| **Thành phần ảnh hưởng** | `scripts/lab/lab_runner.py` (`pdf_worker`, `selection_id`) |
| **Hồ sơ liên quan** | Job `e2560cc122de487a20429eba7ac9a954cdc30601dbf02b5f4dbc6dda530e8fcf` |

---

## 1. Triệu chứng & Bối cảnh (Symptoms & Context)

Khi vận hành job `pdf-static-cic-full` (1,452 mẫu PDF) trên REMnux LAB thông qua lệnh `lab run`:
* Quá trình preflight thành công (`guest_network_checked: true`, `hypervisor_controls_attested: true`).
* Cửa sổ hiển thị `Bat dau chay job e2560cc122de...`
* Tiến trình dừng ngay ở giây 00:07: `Tien trinh: 0/1452 (0%) | Da chay: 00:07 | Con lai: --:-- | Workers: 0/5`
* Kết quả trả về: `{"status": "failed", "reason": "worker_failed"}`.

### Log / Traceback chi tiết
Khi chạy trực tiếp hàm worker trên REMnux để phân tích traceback nội bộ:
```text
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/local/libexec/malpdf/lab_runner.py", line 242, in pdf_worker
    stored = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
  File "/usr/local/libexec/malpdf/lab_side.py", line 36, in bounded_read
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("Unexpected input type/size")
ValueError: Unexpected input type/size
```

### Điều kiện tái hiện (Reproduction Conditions)
* Chạy bất kỳ batch nào có quy mô lớn (> 800 mẫu PDF).
* Đối với tập 1,452 mẫu, file `selection.json` có kích thước **962,561 bytes (~940 KB)**.
* Lệnh đọc an toàn `side.bounded_read` kiểm tra cứng `info.st_size > limit` với `limit = 512 * 1024` (512 KB), dẫn tới ném `ValueError("Unexpected input type/size")`.

---

## 2. Phân tích Nguyên nhân Gốc (Root Cause Analysis - 5 Whys)

1. **Tại sao (Why 1)?** Toàn bộ 5 tiến trình worker đều kết thúc với mã lỗi non-zero và job thất bại với lý do `worker_failed`.
2. **Tại sao (Why 2)?** Mỗi worker khi khởi động đều xác thực tính toàn vẹn của tập mẫu được giao bằng cách so sánh `stored` đọc từ `selection.json` với `selection` dự kiến.
3. **Tại sao (Why 3)?** Lệnh đọc `stored = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))` bị ném ngoại lệ `ValueError("Unexpected input type/size")`.
4. **Tại sao (Why 4)?** Hàm `bounded_read` từ chối đọc bất kỳ file nào có `info.st_size > limit`. File `selection.json` của 1,452 mẫu có kích thước 962 KB, vượt quá ngưỡng 512 KB.
5. **Tại sao (Why 5 - Root Cause)?** Ngưỡng đọc 512 KB được thiết lập cứng từ các đợt chạy diagnostic nhỏ (32 hoặc 64 mẫu, file chỉ chiếm ~42 KB). Khi mở rộng sang `pdf-static-cic-full` với 1,452 mẫu, dung lượng manifest lưu trữ metadata của từng dòng tăng tỷ lệ thuận với số lượng mẫu nhưng giới hạn `bounded_read` chưa được điều chỉnh tương ứng.

---

## 3. Giải pháp & Cách sửa (Resolution & Code Changes)

### Cách tiếp cận sai lầm cần tránh
* Tắt bỏ hoàn toàn `bounded_read` và dùng `read_bytes()` thông thường: vi phạm nguyên tắc phòng vệ hạn chế tài nguyên và chống tấn công từ chối dịch vụ I/O.
* Hardcode tăng riêng cho trường hợp 1,452 mẫu: không hỗ trợ các tập dữ liệu lớn hơn trong tương lai.

### Giải pháp kỹ thuật chuẩn
* Nâng giới hạn trần an toàn của `selection.json` trong cả `pdf_worker` và `selection_id` từ `512 * 1024` (512 KB) lên `4 * 1024**2` (4 MiB).
* 4 MiB hoàn toàn an toàn cho bộ nhớ worker (được cấp tới 2 GiB AS), đồng thời đủ sức chứa metadata cho tập dữ liệu lên đến hơn 6,000 mẫu PDF.

### Minh họa Code Diff
```diff
--- a/scripts/lab/lab_runner.py
+++ b/scripts/lab/lab_runner.py
@@ -239,3 +239,3 @@
     if prepare:
         jobs.immutable(directory / 'selection.json', selection)
         return
-    stored = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
+    stored = parse_json(side.bounded_read(directory / 'selection.json', 4 * 1024**2))
@@ -318,3 +318,3 @@
 def selection_id(directory):
     try:
-        value = parse_json(side.bounded_read(directory / 'selection.json', 512 * 1024))
+        value = parse_json(side.bounded_read(directory / 'selection.json', 4 * 1024**2))
```

---

## 4. Ràng buộc Bất biến (Anti-Regression Invariants)

1. **Giới hạn kích thước Manifest Tỷ lệ thuận:** Mọi API đọc metadata danh sách mẫu (`selection.json`) qua `bounded_read` phải có buffer trần tối thiểu 4 MiB.
2. **Xác thực trước khi nhận Job:** Unit test kiểm tra cohort lớn phải xác nhận kích thước tuần tự hóa JSON của danh sách mẫu luôn nhỏ hơn giới hạn đọc của worker.
