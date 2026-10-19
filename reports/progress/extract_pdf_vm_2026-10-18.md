# Phát triển extractor theo quy tắc VM 2026-10-18

Đã bổ sung đường chạy VM cho extractor tĩnh theo nền tảng trong
[kế hoạch extract-pdf](../../plans/extract-pdf/plan.md). API `extract_pdf()` và
CLI `malpdf extract` mặc định dùng VM; lệnh batch là:

```bash
.venv/bin/python scripts/22_extract_pdf.py vm
```

Mã không áp trần CPU/RAM/thời gian từng file hay ép BLAS về một luồng. Sức chứa
byte/decoder/IR/graph/IPC dùng giới hạn biểu diễn `sys.maxsize - 1`; kiểm tra
vòng lặp, độ sâu và tỷ lệ giải nén vẫn hoạt động. Mỗi mẫu có worker riêng,
checkpoint, danh tính lần xuất và trạng thái lỗi; hủy iterator sẽ dọn worker.
Arlington được xác minh và tái sử dụng trong batch. Luồng cũ vẫn có thể chạy
theo policy bounded khi được chọn rõ.

Cấu hình [extraction_vm.yaml](../../configs/extraction_vm.yaml) dùng mọi CPU
khả dụng và toàn bộ partition Train/Validation đã lưu. Kiểm tra metadata chọn
1.161 mẫu CIC: 870 Train, 291 Validation; không tái chia, cân bằng hoặc lấy Test.
Kiểm tra rò rỉ nhóm vẫn xét cả các partition không được chọn. Không yêu cầu
commit sạch, launcher offline hay thay đổi claim cũ để chạy đường VM mới.
HEAD, dirty worktree, hash mã, manifest, seed và phiên bản/phần cứng được ghi
trong mỗi run. Ba store và nhánh kế hoạch sự kiện giữ hợp đồng hiện có.

## Bằng chứng kiểm tra

Run kiểm chứng:
[`run_20261018T135548982703Z_9f5d9357bf0c`](../experiments/extraction_vm_validation/run_20261018T135548982703Z_9f5d9357bf0c/run_summary.json).
HEAD là `9f5d9357bf0c83a3b3237fd9e433b78ed7ca61ac`, worktree dirty. Các chỉnh
sửa cục bộ có sẵn trong AGENTS/Arlington/raw syntax được giữ; comment trong
những file mã đã sửa được loại bỏ theo quy tắc mới. Không stage hoặc commit.

| Kiểm tra | Kết quả đo từ đầu ra đã lưu |
| --- | --- |
| Toàn bộ `pytest tests/` sau thay đổi cuối | 1.839 passed, 2 warning sklearn đã có, 230,93 giây |
| Kiểm thử VM riêng | 29 passed, 10,89 giây |
| Schema độc lập Draft 2020-12, chặn reference ngoài | 9 store từ 3 bundle tổng hợp hợp lệ |
| Dependency | `No broken requirements found.` |
| Whitespace | `git diff --check` đạt |
| Tokenizer trên 26 file mã đã sửa | 0 comment |

Các ca VM kiểm file lớn hơn 10 MB, giải mã 9 MiB vượt các quota cũ, raw IR vượt
8.192 node, dictionary 1.100 key, cửa sổ entropy/marker/name ở cuối file,
worker song song, mẫu lặp/lỗi, hủy worker, cache Arlington, giữ split và chạy
xuyên suốt từ manifest tổng hợp tới output thật. Các run lặp tạo thư mục mới;
test không cần dataset hay mạng.

Chi tiết checks và hash log tại
[validation_checks.json](../experiments/extraction_vm_validation/run_20261018T135548982703Z_9f5d9357bf0c/validation_checks.json).
Log cục bộ được giữ dưới `artifacts/tmp/maintenance/extraction_vm/`; các thư mục
scratch của hai lượt kiểm thử toàn bộ được dọn sau khi lưu kết quả kiểm tra.

## Môi trường và phạm vi kết luận

Python 3.11.17; NumPy 2.4.6; pandas 2.3.3; scikit-learn 1.9.1; pypdf 6.18.1;
PyMuPDF 1.26.7/MuPDF 1.26.12; pikepdf 10.17.0/QPDF 12.4.2; Esprima 4.0.1;
PyTorch 2.11.0+cpu và torchvision 0.26.0+cpu. VM có 4 CPU khả dụng,
8.271.798.272 byte RAM; không có GPU/CUDA. Không thay dependency hoặc cài wheel.

Lượt này không chạy lại corpus PDF thật, benchmark mô hình hoặc tính chỉ số
phát hiện. F1 malicious, MCC, ECE và Brier là N/A; `Label=1` vẫn là malicious
trong schema nghiên cứu. Bộ đếm mẫu từ manifest không phải kết quả trích xuất
corpus. Các kết quả cũ, gồm cohort 64 và audit 21 partial, giữ phạm vi lịch sử.

Native media decoder, đầy đủ Arlington conformance, JS liên thủ tục/heap,
render/OCR/QR, emulator, Reader/CAPE và tái nhập hiện vật động chưa hoàn tất.
Quy tắc hiện tại chỉ cho phân tích byte tĩnh, không mở/render/thực thi PDF.
Xem [hướng dẫn VM](../../docs/extraction_vm.md) và
[kiểm kê nghiệm thu](../../plans/extract-pdf/acceptance.md) cho phần còn lại.
