# Launcher extractor offline, 2026-10-16

Maintenance: `run_20261016T125532000000Z_19de287ea30a`.
Generating commit: `19de287ea30a4672658907ccf046b5e5ce89a925`, dirty during build.
Người dùng yêu cầu tạo launcher thay cho thao tác nhiều lệnh thủ công.

Đã cài **`/home/drstone/Desktop/Extract PDF Offline.desktop`**, mode0700,
không ghi đè shortcut khác hoặc tự mở ứng dụng. Entry mở terminal và gọi
`scripts/launch_pdf_extraction.sh` với job ID cố định, dùng root `.venv` Python
ở chế độ `-I` và ba BLAS/OpenMP thread variables=1. Không unset SSH/agent/token
hoặc che credentials; không tải phụ thuộc, đổi NIC hay chọn newest job.

Reusable logic ở `src/malpdf/extraction/launcher.py`, CLI mỏng24 và shell wrapper
ở `scripts/`. Preflight chỉ đọc metadata, hiện diện credentials và resource
admission; không ghi report/claim, đọc/stat/hash PDF hoặc gọi extractor. Check-only
không prompt; code0 nếu software checks đạt,2 nếu blocked,1 nếu metadata/runtime
lỗi. Mọi preflight vẫn `operator_attested=false`, `execution=not_run`.

Default cần stdin/stdout TTY và nhập đúng **`CHAY TINH`** sau khi đủ điều kiện
VMware/credentials/snapshot. Nhập khác hủy. Runner hiện có kiểm lại mọi gate sau
xác nhận, trước claim/PDF; giữ single-use claim/evidence khi lỗi/ngắt, không retry.
Chỉ in aggregate run status/paths, không echo private exception text hoặc sample
identities. Đây vẫn là bounded static extraction, không render/JS runtime/Reader/CAPE.

Guard dùng chung nay đọc presence của home/repo `.codex/auth.json`, kể cả broken
symlink, bên cạnh các paths/environment names/SSH keys đã có. Không đọc giá trị,
xóa hoặc di chuyển credentials. Presence checks không thay kiểm toán credentials
thủ công và không chứng minh VMware clipboard/network settings.

## Kiểm chứng

**1698 passed**, hai cảnh báo sklearn single-label đã có,197.90s.
Log `artifacts/tmp/maintenance/extract_pdf/launcher_full.log`.
Lượt targeted ban đầu44 passed/2.71s trước ca integration cuối; log `launcher_unit.log`.
Thêm36 cases so với suite1662 trước đó. Dùng fixture/state tổng hợp, không PDF thật.

Bao gồm cancellation/exact phrase, noninteractive/SSH/root/network/shared mounts,
Codex auth paths/broken symlink/agent/env/private-key presence không đọc nội dung,
code dirty/claim/RAM/Python/output boundary, private error sanitization và no retry.
Ca integration với runner thật nhưng fixture metadata chứng minh NIC reconnect
sau prompt vẫn bị từ chối trước claim/extractor. Shell transport được chạy bằng
fake interpreter tổng hợp tại đường dẫn có spaces: giữ argv/credential sentinel,
threads=1, exit0/17; thiếu venv từ chối và không download.

`sh -n`, isolated Python CLI `--help`, `desktop-file-validate` trên file đóng gói
và file Desktop đều đạt. Không nhấp đúp GUI trong phiên kết nối này; không nhận
là đã kiểm desktop activation thực tế. Reuse `.venv` Python3.11.17 từ pyproject,
không đổi dependency hoặc resource cap. Kiểm tra cuối ghi trong private receipt
`artifacts/tmp/maintenance/extract_pdf/launcher_final_checks.json`.

## Job và package thay thế

Job **`run_20261016T130402057603Z_19de287ea30a`**,223 source/config files, gồm
shell launcher. Job cũ từ chối source drift. Lock SHA256
`ca4f2a327cdaba18f6b3e08868c506bcbb4d0c7a59f42137da7332023d068cb6`.
Giữ nguyên chính xác rows/selection hash/manifest provenance từ job trước:
32 Train/32 exposed Validation,16 mỗi lớp mỗi partition,seed42; không chọn Test
hoặc chia lại dữ liệu. Nguồn và đường dẫn manifest/hash giữ trong saved preparation.

Arlington thật **`b7d880b7a3d3c8f505c025f17763397475e90503`** được kiểm lại:
**610 TSV/3976 rows**, checksum/lock/Git reference hợp lệ, không fallback fixture.
Evidence `launcher_job_checks.json` cùng domain private.

Package mới **`run_20261016T130519507883Z_19de287ea30a`**:

- Archive dưới `artifacts/tmp/maintenance/extract_pdf/offline_handoff/`,121582 bytes,
  11 files, SHA256 `c8e108ea92ff6b379f4d098224f2c30593e2cd702d251379ed5436bf43e46047`.
- Có shortcut job-pinned, RUNBOOK.vi.md, job/config/environment/preflight và
  checksum từng file. Dùng repo/.venv/Arlington đã có; không phải installer.
- Không chứa PDF, source-tree copy, wheels hoặc model weights. Job lock có sample
  metadata nên package riêng, ignored và không upload/commit.
- Checksum file/archive và safe tar paths đã kiểm. Gói/report cũ giữ nguyên;
  saved preflight mô tả lúc build còn dirty, current launcher luôn đọc lại trạng thái.

[Summary aggregate](../deployment/pdf_extraction_offline/run_20261016T130519507883Z_19de287ea30a/handoff_summary.json)
ghi pending install ở thời điểm đóng gói; `launcher_desktop_install.json` ghi xác
nhận cài thật sau đó. Không sửa record lịch sử để thay trạng thái.

## Phần chưa chạy

Chưa chạy PDF thật/21 partial, chưa nhận xác nhận cô lập console. Phiên phát triển
còn SSH/network/credential presence nên launcher phải chặn trước PDF; cài shortcut
không chứng minh LAB sẵn sàng. Không tự xử lý credentials hoặc ngắt SSH NIC.
Toàn bộ kế hoạch sáu giai đoạn còn mở. F1/MCC/ECE/Brier N/A vì không đánh giá
model/partition; Label1=malicious,ECE10 equal-width bins,p=1 trong bin cuối.
