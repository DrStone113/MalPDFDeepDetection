# Snapshot extractor đã commit, 2026-10-16

Maintenance: `run_20261016T115814000000Z_aa27c0a28dcb`.
Người dùng đã đồng ý commit snapshot210 file trong
[bản kiểm kê](extract_pdf_release_review_2026-10-16.md), gồm cả thay đổi có trước.

Source commit: **`aa27c0a28dcb6482179afed6da5c76ad727a2a6d`**.
Parent: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`.
Tiêu đề: `feat(extraction): prepare bounded static extractor and offline LAB handoff`.
Đúng210 đường dẫn đã duyệt; SHA256 từng Git index blob và file làm việc đều
khớp bản kiểm kê. Không thêm đường dẫn khác, không push lên remote.
Biên bản/docs/log ghi nhận commit này được chốt sau bằng commit bảo trì riêng;
không sửa báo cáo kiểm kê hoặc provenance preparation cũ để gắn revision mới.

## Kiểm tra và giới hạn Git

Ignore coverage và kiểm tra có giới hạn trên UTF-8/NUL/symlink/đuôi artifact,
private-key headers/64 sealed sample identities đều đạt trước staging. Với log
chỉ kiểm nội dung append sau baseline. Index không chứa PDF/dataset/cache,
checkpoint, venv, Arlington checkout hay gói handoff riêng. Đây không phải kiểm
toán secrets/corpus tổng quát. Staged whitespace check đạt.

Trong lúc kiểm tra index phát hiện Git blob của `src/malpdf/extraction/jobs.py`
bị rỗng0 byte. Đã giữ file rỗng trong ignored runtime và tái tạo đúng blob
`b5b6e8e3991e798f2cfaa04aff7e596f90d6b0a7` từ bytes có SHA256 đã được duyệt.
Đối chiếu blob/index/working bytes đạt; không sửa mã hoặc ref khác.
Ổ đĩa lúc kiểm tra còn khoảng30GiB; chưa có bằng chứng gán lỗi này cho RAM/CPU.

Full `git fsck --full --no-reflogs` vẫn **không đạt**, exit11: còn8 loose objects
rỗng và một ref lỗi dưới `refs/codex/turn-diffs/checkpoints/`. Không object rỗng
nào thuộc3195 objects reachable từ source HEAD; toàn bộ reachable objects và
210 index blobs đọc được. Không xóa/sửa checkpoint refs hoặc object còn lại.
Vì vậy không nhận là toàn bộ Git object database đã lành mạnh.

Evidence riêng được giữ dưới `artifacts/tmp/maintenance/extract_pdf/`:
`release_git_fsck_before.log`, `release_git_object_repair.json`,
`release_git_fsck_after_source_commit.log`, `release_stage_checks.json`,
`release_source_commit.json`, `release_commit_command.log`.

## Job offline sau commit

Repo sạch và cổng `clean_code` đạt ngay sau source commit. Lệnh metadata-only
`check` xác minh lại job **`run_20261016T103345122630Z_7d02abdb85da`**:
220 source/config files,64 dòng32 Train/32 exposed Validation,seed42, Test ngoài
selection. Commit không đổi source bytes nên không sinh job mới hoặc sửa lock.
Actual PDF run sau này phải ghi generating commit thực tế của nó.

Arlington thật vẫn khóa **`b7d880b7a3d3c8f505c025f17763397475e90503`**,
610 TSV/3976 rows; checksum/Git reference/model loader đều qua metadata check.
Gói offline cũ giữ nguyên, checksum
`6fe7a89350877bb3c36fb5e5eb85ac28d40b17ae491c80917822564acc8f395e`.
Không đưa gói/job lock riêng vào Git hoặc upload ra ngoài.

Python3.11.17; `pip check` đạt. Full suite gần nhất **1662 passed**, hai cảnh báo
sklearn đã có,203.47s, tại `artifacts/tmp/maintenance/extract_pdf/triggers_full.log`.
Không thay mã/tests/dependencies nên tái dùng kết quả trên; không nhận là đã
chạy pytest mới trong lượt commit. Kiểm tra cuối commit/docs/log được giữ tại
`artifacts/tmp/maintenance/extract_pdf/release_final_checks.json`.

## Chưa chạy PDF thật

Không đọc/hash/parse PDF thật, ngắt NIC, render, thực thi/giả lập JavaScript,
mở Reader hoặc gọi CAPE trong lượt này. Người dùng trước đó chưa sẵn sàng
console; cần xác minh cô lập bằng VMware console theo
[hướng dẫn handoff](../../docs/extraction_lab_handoff.md) trước `run`.
Không tự ngắt NIC của SSH hoặc coi `--lab-isolated` là cơ chế cô lập.
Mã/tests/package chuẩn bị không chứng minh nghiệm thu corpus/21 partial hay
hoàn thành toàn bộ sáu giai đoạn trong kế hoạch.

Metrics F1/MCC/ECE/Brier N/A vì không đánh giá model/partition.
Label1=malicious; ECE10 equal-width bins,p=1 trong bin cuối.
