# Lượt PDF thật đầu tiên, bảo toàn primary và chỉ mục Arlington

Maintenance `run_20261016T151858047438Z_ba64a514ae5a`. Generating revision `ba64a514ae5afe86b06e054f527cc066133d8afd`, dirty during code/audit work.
Final resulting HEAD/clean gate: `artifacts/tmp/maintenance/extract_pdf/postrun_final_checks.json`.

## Kết quả thật và nghiệm thu được chứng minh

Lượt `run_20261016T142851774386Z_ba64a514ae5a` chạy tại VMware console từ21:28:51
đến21:39:56 ngày16-10-2026 (UTC+7), commitba64a514ae5a sạch.64/64 records giữ đủ
mẫu số:32Train/32 exposedValidation,16/lớp/partition,seed42; không Test/model fit.
Status:56resource_limit/3decode_error/2partial/1unsupported/1encrypted/1observed.
Thời gian toàn lượt665s; median worker12.125s,P9915.361s; peak worker RSS396140544
bytes. RSS không đo virtual address space hay peak RAM toàn VM.

Audit chỉ JSON/CSV đã lưu: `run_20261016T151444703769Z_ba64a514ae5a`;
[`saved_run_audit.json`](../experiments/pdf_extraction_postrun_review/run_20261016T151444703769Z_ba64a514ae5a/saved_run_audit.json).
Đối chiếu manifest khóa và v9 `run_20261011T045223500000Z_ff3f5b65d376`:
64/64 cùng identity/hash/label/partition,64 root primary checkpoints; raw41
trường và projection173 trường đều khớp64/64, giữ nguyên nulls. Riêng đúng21
Validation partial lịch sử khớp21/21 trên cả hai phép đối chiếu. Đây là nghiệm thu
bảo toàn primary trên cohort đã khóa, không phải whole-PDF extraction/detection.
Bảy checkpoint child giữ riêng; không gộp checkpoint con vào PDF gốc.

Audit đầu `run_20261016T151203162254Z_ba64a514ae5a` failed do giả định chỉ có một
record kind=primary_checkpoint. Giữ nguyên failed report/log; audit sau chọn
root bằng đúng evidence_id primary:<document SHA256>, giữ mọi child. Chỉ đọc
lại metadata, không chạy lại PDF hoặc classifier. Không xóa failure history.
Reference metadata checksums (JSONL, không phải PDF/sample hash):

- `artifacts/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/per_file.jsonl`: `dabd070046a3fc05f2bb04b50aab6c1e92e2bf970d0af00e2e400ec155f46443`.
- `artifacts/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/paired_evidence.jsonl`: `647acc510efca81aee447488ac7fb0feb5d2d69f1063f5b7d9c4e0de53e769a1`.

Trong64 kết quả, worker statuses gồm21 resource_limit_or_signal,14 complete,
16partial,13parser_error. Reasons có21worker_signal_9,17decoded_byte_or_expansion_limit,
13arlington_metadata_limit và4ast_node_limit; các nhóm chồng lấp, không cộng thành
số mẫu khác nhau. Parent còn SIGKILL worker để cleanup sau result nên exit_code
-9 riêng lẻ không chứng minh failure/OOM/CPU. Chưa có telemetry đủ để quy21
worker ngắt cho thiếu RAM hay CPU vật lý. Không tăng caps hoặc sửa dữ liệu đầu vào.

Arlington trong lượt thật:35partial/29not_run; ScriptSemantics và byte images
43partial/21not_run. Giữ explicit unknown/not_run; chưa nghiệm thu codec native,
forensic/conformance đủ, render/emulator/Reader/CAPE hoặc detector/evidence gains.

## Thay đổi mã và bằng chứng mới

Context.entry trước đây quét lại dictionary cho mỗi rule/path và wildcard đếm
trùng bằng quét lồng nhau. Engine mới lập index trên cached IR một lần cho mỗi
node/document, giữ danh sách đầy đủ các duplicate values, thứ tự và identity node.
Index không cache kết quả rule/context: owner/revision/reference resolution,
source IDs, candidate paths, unknown predicates và mọi trần binding/check/step/
metadata/CPU/RAM/byte giữ nguyên. Không parse PDF thêm hoặc thay model/split.

Kiểm chứng **1756 passed**, 2 cảnh báo sklearn single-label đã có,
308.66s (`postrun_full.log`). Targeted89 passed/12.01s (`postrun_unit.log`),8
ca mới: repeated lookups chỉ duyệt dictionary một lần, duplicate/encoded/nonUTF8
keys, node cùng span khác owner, inherited trailer và exact output parity với
uncached reference; không sửa IR. Các test resource/unknown/timeout cũ vẫn đạt.

Synthetic lookup benchmark1024 keys ×4096 queries ×5 repeats: median
0.621249s trước,
0.016601s sau,ratio37.42.
Chỉ đo lookup trên IR tổng hợp; không tuyên bố tốc độ end-to-end/corpus cải thiện.
`postrun_index_benchmark.json` giữ mọi repeat và SHA256 source class đã commit.

Model thật **b7d880b7a3d3c8f505c025f17763397475e90503** vẫn610TSV/3976rows,LICENSE/NOTICE/checksums đúng.
Smoke `run_20261016T151024828542Z_ba64a514ae5a` đạt cả4 fixtures/all assertions:
blank page,wrong catalog type,direct pages,unknown key; metadata nguồn hợp lệ,
unsupported giữ unknown,worker cleanup và caps đúng. Không dùng fixture thay model.
Mã index mới **chưa chạy PDF thật**, không tạo/seal/launch job mới hoặc reset claim.
Desktop pin cũ vẫn là entry lịch sử đã consumed; không mở lại để thử cùng job.

Python3.11.17 `.venv` tái dùng; không đổi dependency/resource limits. pip check,
diff checks đạt. README/AGENTS và mọi báo cáo/run cũ giữ nguyên; log append-only.
1720 report files đã có trước task (gồm6 report của lượt operator) giữ nguyên từng
byte. Chỉ stage source/tests/docs và aggregate reports; PDF/blobs/IDs/paths/hashes
mẫu/credentials/checkpoints không đưa vào Git. Không đọc byte PDF gốc hoặc blob,
không JS execution/render/upload/push/NIC change/credential deletion trong lượt này.

Full sáu giai đoạn vẫn mở. Tiêu chí21-primary có bằng chứng thật tại ba64a514ae5a;
các nhánh mới và chất lượng toàn bộ cần nghiệm thu riêng. MetricsF1/MCC/ECE/Brier
N/A:không model/partition được đánh giá; Label1=malicious,ECE10equal-width bins,p=1
trong bin cuối. Hết lượt audit/code không đồng nghĩa goal đã hoàn tất.
