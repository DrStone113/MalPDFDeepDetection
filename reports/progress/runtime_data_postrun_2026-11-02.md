# Kết quả chạy thật và chuẩn bị tiếp tục — 2026-11-02

Job gốc `4cec6c2794967311bc5c55a924933a0b0cbda0529ff31fe1f19de8b4cdcd7b75` kết thúc lúc `2026-11-02T14:07:07Z` với trạng thái **partial**, lưu **1.380/1.452 bundle**. Thời gian của job gốc 3.980.880 ms, peak RSS 412.389.376 byte. Đây là số liệu trích xuất; không có phép đo mới về độ chính xác phân loại malware.

## Kết quả đã xác minh

| Trạng thái bundle | Số mẫu |
| --- | ---: |
| bounded_complete | 283 |
| observed | 1 |
| partial | 139 |
| timeout | 587 |
| unsupported | 322 |
| decode_error | 48 |
| Chưa có bundle | 72 |

Có 1.309 bundle chứa primary checkpoint. Theo bộ đếm của runner, 284 mẫu observed/bounded_complete, 139 partial, 957 failed/unsupported; ba nhóm này cộng thành 1.380, không phải số mẫu được phân loại đúng.

Shard 4 dừng sau index 724 vì metadata ghi `worker_cleanup_complete=false`. Các index chưa chạy là 734, 744, …, 1444. Chưa xác minh được nguyên nhân kernel khiến cleanup chưa hoàn tất. Giữ điều kiện dừng an toàn; không sửa cờ này thành true và không tăng timeout tùy tiện.

## Dữ liệu thật đã đưa về DEV

- Dataset mới: `data/processed/runtime_postrun/4cec6c2794967311bc5c55a924933a0b0cbda0529ff31fe1f19de8b4cdcd7b75/a07a82e079974a0e9e7dff2a796d680a311967ff9fc41f3384daef4f704068cd`. Gồm `numeric.jsonl.gz`, manifest hash, coverage và index nguồn.
- Giữ đủ 1.452 vị trí: 1.380 present, 72 missing, 0 invalid. Mỗi bundle được kiểm tra schema và đúng SHA. Nhãn và split được đối chiếu với ba manifest gốc có checksum khóa; seed 42 không đổi.
- Coverage theo split: train 834 present / 36 missing; validation 273 / 18; test 273 / 18.
- Có 1.305 đồ thị với node quan sát được. Cả 1.305 còn ít nhất một kích thước node chưa biết. Giá trị này giữ null; không tạo node giả hoặc thay null bằng 0. Dataset được đánh dấu `model_input_ready=false`.
- Tên feature lấy từ catalog hữu hạn 510 tên; không xuất tên tự do, nội dung tài liệu, script, evidence ID hoặc exception text. Chỉ xuất số hữu hạn, boolean, null và metadata thuộc schema đóng.
- Windows không nhận PDF, payload hay shellcode. Chỉ nhận dữ liệu số đã kiểm tra và CSV metadata đúng checksum. 1.380 bundle gốc tại LAB và cache thí nghiệm cũ được giữ nguyên.

## Mã nguồn và kiểm thử

Sửa banner để chỉ xuất sau khi kiểm tra mã thoát/summary; báo rõ incomplete/partial và shard halt. Lưu nguyên nhân dừng có cấu trúc. Trạng thái persisted cũng không được passed nếu còn halt marker. Resume chỉ dùng bundle đúng SHA, đúng schema và cleanup bằng đúng boolean true. [BUG-006](../../docs/bugs/BUG-006-incomplete-job-success-banner.md) ghi bất biến và regression.

Khi xếp hàng tiếp tục, phát hiện thêm nhánh `immutable` đọc lại manifest bằng trần 512 KiB. Lỗi được tái hiện bằng JSON 600 KiB; đã đổi sang đọc tối đa đúng độ dài payload cần đối chiếu, yêu cầu byte khớp hoàn toàn và giữ giới hạn đầu vào ở caller. [Bổ sung BUG-004](../../docs/bugs/BUG-004-selection-json-buffer-limit.md) ghi bằng chứng. Lần chuẩn bị lỗi chưa đọc PDF và chưa queue job.

Kiểm thử tập trung ban đầu: 107 passed trên Windows, 107 passed trên REMnux. Sau sửa replay manifest: 79 passed trên mỗi môi trường. 365 tệp Python qua AST, 0 Python comments; `git diff --check` và content guard 2.239 tệp index đều qua. Full suite gần nhất trước lượt sửa này còn lỗi như báo cáo audit trước; không công bố toàn bộ dự án đã xanh hay sẵn sàng production.

Release cuối: `/home/remnux/malpdf-releases/e90e0340390ddc44ffb3f3ce25dbfb087202ddd6`; nguồn gồm 403 tệp text đã duyệt, có Git snapshot riêng để truy vết. HEAD/index của repo chính không bị commit hay thay thế. Parser, normalizer và cấu hình trích xuất giống release của job gốc; các thay đổi hiện hữu chỉ ở hai helper runner cùng các module export/test mới.

Restricted gateway đã có `policy=mismatch` trước cập nhật helper và vẫn giữ trạng thái từ chối. Không thay policy, SSHD hoặc xác nhận giả rằng gateway đã được kiểm chứng. Offline console runner riêng đã qua kiểm tra hash helper và health Host-only. NIC/shared folders do người vận hành kiểm soát như lần trước.

## Job tiếp tục đã sẵn sàng

Job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f` đang **queued**, là job pending duy nhất; chưa có claim/result, chưa xử lý PDF thêm.

- Tái sử dụng 1.379 bundle đã xác minh; giữ nguyên cả những status timeout/unsupported đã đo, không nâng chúng thành complete.
- Xử lý 73 mẫu: 72 chưa có bundle và index 724 cần chạy lại. Không tự động chạy lại 587 timeout.
- Giữ mẫu số và split 1.452 mẫu. Có `reuse_manifest.json` gắn từng bundle với job gốc và hash, loại index 724 khỏi cache. Việc tái sử dụng khiến job này không đủ điều kiện làm benchmark thời gian cold-run.
- Bản staging chưa queue trước đó được đánh dấu superseded; chỉ chuyển thư mục cache của staging chưa có claim/result sang job cuối, sau khi kiểm tra hash và ranh giới đường dẫn. Job gốc không bị di chuyển.

Theo [human gate của dự án](../../docs/agent_workflow_and_gates.md), người vận hành đưa VM về offline và kiểm tra isolation như lần trước, rồi chạy trong console REMnux:

```bash
lab run
```

Bằng chứng chi tiết: [`run_summary.json`](../experiments/runtime_data_postrun/run_20261102T142920862759Z_4cec6c279496/run_summary.json), [`halt_diagnosis.json`](../experiments/runtime_data_postrun/run_20261102T142920862759Z_4cec6c279496/halt_diagnosis.json), [`numeric_coverage.json`](../experiments/runtime_data_postrun/run_20261102T142920862759Z_4cec6c279496/numeric_coverage.json), [`recovery_final_health.json`](../experiments/runtime_data_postrun/run_20261102T142920862759Z_4cec6c279496/recovery_final_health.json).
