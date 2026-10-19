# Tăng tốc extractor trên VMware 2026-10-18

Đã giảm chi phí checkpoint của extractor tĩnh, giữ worker liên tục nhận mẫu
mới và bổ sung resume có xác minh. VM hiện có 4 CPU khả dụng, khoảng 7,7 GiB
RAM và PyTorch CPU; lượt tối ưu này sử dụng CPU song song.

```bash
.venv/bin/python scripts/22_extract_pdf.py vm
```

Cấu hình mặc định chọn mọi CPU khả dụng và 1.161 mẫu Train/Validation CIC từ
manifest Protocol G seed 42 đã lưu. Lượt này chưa chạy lại toàn bộ cohort.
Không thay split, fit mô hình hoặc phân tích PDF Test.

## Thay đổi đã triển khai

- Native inventory, raw forensic, Arlington, stream và carving giảm số lần
  deepcopy/serialize toàn bộ trạng thái giữa các bước nhỏ. VM bỏ kiểm tra kích
  thước JSON dành riêng cho ngân sách metadata hữu hạn. Các biên backend/giai
  đoạn và kết quả cuối vẫn flush đầy đủ. Bounded giữ cadence cũ.
- Scheduler điều chỉnh khoảng checkpoint theo chi phí snapshot, tối thiểu
  0,5 giây giữa các snapshot thông thường. Đây là giảm việc ghi tiến độ; không
  đặt timeout hoặc bỏ đặc trưng. Khi worker lỗi giữa giai đoạn, checkpoint là
  prefix gần nhất đã flush và vẫn mang trạng thái gián đoạn/partial.
- Batch giữ các tiến trình parser riêng cho từng mẫu, nạp mẫu tiếp theo trước
  khi giao JSON hoàn tất cho bộ ghi và báo heartbeat khi worker đang chạy.
  Tham số `--workers` hỗ trợ so sánh số worker; mặc định là `auto`.
- Mỗi JSON mẫu ghi compact cùng completion journal chứa SHA-256. Resume chỉ
  tái sử dụng bản ghi khớp mã/môi trường, manifest, PDF gốc, hợp đồng bundle,
  worker hoàn tất và hash blob. Bản ghi lỗi/hỏng được trích lại; fingerprint
  cũ không tương thích dẫn đến chạy mới. Mỗi invocation có thư mục mới.
- Bổ sung provenance dự phòng từ repository mã đang nạp khi thư mục Arlington
  nằm ngoài Git, để lỗi lấy Git HEAD không làm mất kết quả phân tích chính.

## Số đo đã lưu

Run hiệu năng:
[`run_20261018T150156599523Z_9f5d9357bf0c`](../experiments/extraction_vm_performance/run_20261018T150156599523Z_9f5d9357bf0c/run_summary.json).
HEAD `9f5d9357bf0c83a3b3237fd9e433b78ed7ca61ac`, worktree dirty; hash mã và
môi trường được ghi cùng run. Các thay đổi cục bộ có trước được giữ nguyên.

Đo toàn bộ deep-static với Arlington đã khóa trên 8 PDF tổng hợp lành tính,
cùng mã đã tối ưu, so sánh tuần tự và song song:

| Worker | Số PDF | Wall time | PDF/giây |
| --- | --- | --- | --- |
| 1 | 8 | 44,2914 giây | 0,1806 |
| 4 | 8 | 21,4817 giây | 0,3724 |

Throughput tăng khoảng **2,06 lần**. Evidence store, feature store và trạng thái
của cả 8 mẫu khớp chính xác giữa hai chế độ. Mỗi cấu hình được đo một lượt,
không phải benchmark throughput của toàn bộ corpus. Xem
[synthetic_batch_timings.json](../experiments/extraction_vm_performance/run_20261018T150156599523Z_9f5d9357bf0c/synthetic_batch_timings.json).

Đo riêng các giai đoạn trên một PDF tổng hợp có thêm 192 object cho thấy chi
phí sao chép/serialize checkpoint là nút thắt lớn:

| Giai đoạn | Trước | Sau | Số snapshot trước → sau |
| --- | --- | --- | --- |
| Native inventory | 39,4786 giây | 0,2028 giây | 1.181 → 5 |
| Raw forensic | 31,9898 giây | 0,1632 giây | 982 → 4 |

JSON kết quả cuối khớp hoàn toàn với bản trước tối ưu cho cả fixture 64 và
192 object. Các thời gian trên chỉ đo từng giai đoạn, không phải mức tăng tốc
của toàn pipeline. Xem
[isolated_stage_timings.json](../experiments/extraction_vm_performance/run_20261018T150156599523Z_9f5d9357bf0c/isolated_stage_timings.json).

Ba mẫu Train/Validation đã hoàn tất trong lượt VM trước cũng được trích lại
qua đọc byte tĩnh, kiểm SHA-256 từ manifest và đối chiếu JSON đã lưu:

| Input index | Worker trước | Worker sau | Trạng thái giữ nguyên | Evidence/feature |
| --- | --- | --- | --- | --- |
| 0 | 9,3071 giây | 4,2348 giây | observed | Khớp |
| 1 | 37,7811 giây | 5,3476 giây | unsupported | Khớp |
| 4 | 4,7759 giây | 4,6802 giây | observed | Khớp |

Đây là 3 mẫu đã hoàn tất của run
`run_20261018T142549597067Z_9f5d9357bf0c`; VM session và cache ở lần đo sau
khác lần trước. Không suy rộng mức tăng của từng mẫu ra 1.161 PDF hoặc quy
toàn bộ chênh lệch cho thay đổi mã. Bằng chứng tại
[paired_sample_timings.json](../experiments/extraction_vm_performance/run_20261018T150156599523Z_9f5d9357bf0c/paired_sample_timings.json).
Bundle/blob riêng giữ dưới `data/processed/pdf_extraction_performance/`, không
đưa PDF hoặc payload vào Git.

## Kiểm chứng và sử dụng resume

Run kiểm chứng:
[`run_20261018T151011107264Z_9f5d9357bf0c`](../experiments/extraction_vm_performance_validation/run_20261018T151011107264Z_9f5d9357bf0c/validation_checks.json).

| Kiểm tra | Kết quả |
| --- | --- |
| Toàn bộ `pytest tests/` | 1.860 passed, 2 warning sklearn về single-label ở vision smoke test, 236,00 giây |
| Nhóm kiểm thử sau sửa cuối | 51 passed, 12,57 giây |
| Schema Draft 2020-12 độc lập, cấm reference ngoài | 36 store từ 12 bundle hợp lệ |
| Deep-static qua worker thật trên 3 PDF tổng hợp | Chạy mới đủ 3; hai lần resume tiếp theo đều tái sử dụng 3/3 |
| Tokenizer trên 30 file mã đã sửa | 0 comment |
| Dependency | `No broken requirements found.` |
| Whitespace | `git diff --check` đạt |

Kiểm thử mới bao phủ cadence/force flush, parity kết quả cuối, refill worker,
chỉ số mẫu khi resume, record/PDF/blob bị đổi hoặc mất, blob path/symlink,
worker chưa hoàn tất, journal trùng/hỏng đuôi, fingerprint đổi và resume nối
tiếp. Fixture và lượt resume thật đều dùng PDF tổng hợp lành tính.

```bash
.venv/bin/python scripts/22_extract_pdf.py vm --workers 4
.venv/bin/python scripts/22_extract_pdf.py vm --resume-from run_REPLACE_WITH_SOURCE_RUN_ID
```

Thay placeholder bằng run ID `pdf_extraction_vm` do lệnh VM in ra. Resume hoạt
động giữa các PDF; giữ thư mục nguồn chứa blob được tái sử dụng. Các run cũ
trước khi có completion journal/worker marker phải trích lại. Không sửa hoặc
ghi đè run cũ. Hướng dẫn chi tiết tại
[docs/extraction_vm.md](../../docs/extraction_vm.md).

Python 3.11.17; NumPy 2.4.6; pandas 2.3.3; scikit-learn 1.9.1; pypdf 6.18.1;
PyMuPDF 1.26.7/MuPDF 1.26.12; pikepdf 10.17.0/QPDF 12.4.2; Esprima 4.0.1;
PyTorch 2.11.0+cpu, torchvision 0.26.0+cpu. Chi tiết tại
[runtime_environment.json](../experiments/extraction_vm_performance/run_20261018T150156599523Z_9f5d9357bf0c/runtime_environment.json).
Không cài dependency mới. F1 malicious, MCC, ECE và Brier là N/A vì không có
đánh giá mô hình; `Label=1` vẫn là malicious trong schema nghiên cứu.
