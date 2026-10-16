# Phạm vi chốt mã trước lượt chạy LAB

Maintenance: `run_20261016T105727000000Z_7d02abdb85da`.
Generating revision: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Đây là kiểm kê metadata/Git để người dùng duyệt phạm vi chốt mã. Chưa stage,
commit, ngắt NIC hoặc đọc/hash/parse PDF thật.

## Đề xuất cụ thể

Chốt một snapshot của **210 file văn bản đã kiểm kê**, gồm mã/tests/configs,
docs/plans và báo cáo tổng hợp hiện có, cộng báo cáo này. Tiêu đề dự kiến:
`feat(extraction): prepare bounded static extractor and offline LAB handoff`.
Snapshot này bao gồm cả thay đổi có từ trước yêu cầu extract-pdf, mô tả dưới đây;
chưa được coi là người dùng đã đồng ý đưa phần có trước vào commit.

Không đưa gói handoff riêng, job lock có metadata mẫu, PDF/dataset, cache, venv,
Arlington checkout, checkpoint hoặc file nhị phân vào Git. Không dùng `git add .`,
stash/reset/clean hay bỏ qua clean-worktree gate để đạt trạng thái sạch.

Danh sách từng đường dẫn, SHA256 nội dung và phân loại trước/sau yêu cầu ở
`artifacts/tmp/maintenance/extract_pdf/release_review_20261016T105727Z.json`.
Nếu có thay đổi sau snapshot này, phải kiểm kê lại trước khi stage.

## Thay đổi đã có trước yêu cầu extract-pdf

Baseline đầu lượt được lưu tại
`artifacts/tmp/maintenance/extract_pdf/current.json` lúc2026-10-15.
Trong18 file baseline,12 file vẫn giữ nguyên SHA256 ban đầu:

- `AGENTS.md`, `README.md`, `docs/workspace_layout.md`.
- `plans/extract-pdf/plan.md` và `tests/test_workspace_layout.py`.
- `reports/progress/progress_report_2026-10-11.html`.
- `scripts/19_validate_pdf_evidence_v8.py`, `scripts/21_validate_pdf_evidence_v9.py`.
- `src/malpdf/data/kaggle_export.py`, `src/malpdf/data/kaggle_notebook.py`.
- `src/malpdf/experiments/multi_cohort_v4.py`.
- `src/malpdf/provenance/research_runs.py`.

Phần có trước sắp xếp tài liệu từ README sang docs, chuyển notebook sinh ra
sang `notebooks/generated/`, chuyển runtime maintenance vào thư mục quy định,
ghi source hashes thay cho sao chép source tree và bảo toàn root `.venv` đã có.
Không gán những sửa đổi này cho lượt triển khai extractor.

Sáu file dùng chung đã được bổ sung trong lượt extractor: `.gitignore`,
`docs/README.md`, `docs/development.md`, `docs/research_status.md`,
`docs/workflows.md`, `reports/research_log.md`. Baseline chỉ giữ SHA của docs,
không giữ bản nội dung đầu lượt, nên không nhận là có thể tách mọi hunk docs
theo tác giả. Prefix606826 bytes của research log đầu lượt vẫn giữ nguyên.

## Phần extractor và kiểm chứng hiện có

Mã reusable trong `src/malpdf/extraction/`, tích hợp worker/static inspector,
CLI22/23, profile config, Arlington lock, các test tổng hợp và tài liệu đi kèm.
Phạm vi chi tiết và các yêu cầu chưa hoàn thành nằm trong
[acceptance](../../plans/extract-pdf/acceptance.md) và
[báo cáo gần nhất](extract_pdf_triggers_2026-10-16.md).

Full suite hiện tại: **1662 passed**, hai cảnh báo sklearn single-label đã có,
203.47s; log `artifacts/tmp/maintenance/extract_pdf/triggers_full.log`.
Không thay mã/tests/dependencies trong lượt kiểm kê này nên tái dùng kết quả
suite trên, không nhận là một lần chạy pytest mới. Python3.11.17, `pip check`,
`git diff --check` và metadata-only `check` đều đạt ở lượt kiểm kê.
Prepared job vẫn xác minh220 source/config files,64 dòng Train/Validation và
Arlington thật610 TSV tại `b7d880b7a3d3c8f505c025f17763397475e90503`.

Trước khi thêm báo cáo này có209 candidate files:17 modified và192 untracked;
tất cả là file thường UTF-8, không có NUL, symlink hoặc đuôi artifact nhị phân
bị cấm. Không thấy private-key header hoặc64 locked sample identities trong
nội dung được kiểm tra; với research log chỉ kiểm phần append sau baseline.
Đây là kiểm tra có giới hạn, không phải kiểm toán credentials/corpus tổng quát.
Index hiện rỗng. Ignore coverage được kiểm tra bằng các đường dẫn giả, không
đụng file mẫu thật.

## Điều kiện còn lại

[AGENTS.md](../../AGENTS.md:53) yêu cầu: “Official experiments start from a clean
committed worktree.” Đồng thời phải “Preserve unrelated local changes.”
Runner kiểm toàn bộ worktree, gồm cả docs/report chưa track. Vì snapshot đề xuất
chứa18 file đã có trước, cần người dùng chốt phạm vi gồm chúng; AGENTS không
quy định một bước xin phép commit chung.

Sau khi phạm vi được chốt, commit các đường dẫn đã kiểm kê, kiểm repo sạch và
chạy lại metadata-only `check`. Commit không đổi source bytes vẫn dùng được job
đã khóa; actual run sẽ ghi revision thực tế, không sửa provenance preparation.

Người dùng hiện chưa sẵn sàng VMware console. Sau khi chốt mã mới chuyển sang
xác minh cô lập từ console theo [runbook](../../docs/extraction_lab_handoff.md).
Không tự ngắt SSH NIC. PDF thật và21 partial lịch sử vẫn **chưa chạy**; render,
JS execution/emulation, Reader/CAPE chưa được duyệt. Giữ Test ngoài lượt này.
Gói offline đã chuẩn bị vẫn giữ nguyên; không sinh thêm job chỉ để kiểm kê Git.
