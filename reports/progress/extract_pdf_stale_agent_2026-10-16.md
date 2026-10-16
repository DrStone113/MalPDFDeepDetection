# Agent đã thoát nhưng desktop giữ biến cũ, 2026-10-16

Maintenance `run_20261016T142124780201Z_08911504a237`; generating revision `08911504a237fffd39f255075674673a86b685a6`, dirty during build.
Final HEAD/clean gate lưu tại `artifacts/tmp/maintenance/extract_pdf/stale_final_checks.json`.

Ảnh sau Enter không còn chặn mạng; người dùng xác nhận tắt cả NAT và host-only.
Đọc metadata process/socket của console xác nhận SSH_AGENT_PID và SSH_AUTH_SOCK
còn trong desktop nhưng PID đã mất, socket không tồn tại. Launcher cũ chỉ xử lý
agent còn sống, nên lặp thông báo không xác minh được. Không đọc/list keys hoặc
signal agent thật trong chẩn đoán. Bản sửa xử lý đúng trạng thái đã xác minh này.

Sau Enter và guard cô lập, nếu không có agent hợp lệ đang sống, nhánh stale chỉ
bỏ hai biến trong tiến trình launcher khi PID hợp lệ được pidfd_open xác nhận
không còn (ESRCH), socket lstat không có, không dangling symlink/symlink parent,
selection không đổi và kiểm lại socket. Không signal/force-kill/unset biến khác.
PID sống/reused, permission/unknown, socket xuất hiện lại hoặc selection đổi vẫn
chặn. Sau cleanup lặp toàn bộ preflight; runner guard và exclusive claim giữ nguyên.
Check-only/noninteractive/hủy/còn mạng không cleanup.

**Mục còn lại:** kiểm tra chỉ sự hiện diện xác nhận `~/.codex/auth.json` tồn tại
trong HOME của chính console; không SSH private-key name hoặc env credential
khác ngoài agent được thấy trong phạm vi kiểm tra. Không đọc nội dung hoặc xóa
file đăng nhập. Nhánh sửa agent vẫn giữ chặn credential này: operator cần xử lý
kho đăng nhập hoặc dùng tài khoản phân tích không có credentials trước PDF thật.
Không coi tắt NAT/host-only là đã đáp ứng kiểm tra credentials/hypervisor còn lại.
Evidence redacted: `artifacts/tmp/maintenance/extract_pdf/stale_diagnosis.json`.

Kiểm chứng **1748 passed**, 2 cảnh báo sklearn đã có,222.66s;
`stale_full.log`. Targeted95 passed/5.49s (`stale_unit.log`),21 ca mới. Process/
socket fixture riêng kiểm absent/live/reused/surviving/dangling/permission/change/
reappear/offline refusal; UI xác nhận credential khác vẫn chặn và không cleanup
trước Enter/cô lập. Không gọi extractor thật hoặc dừng agent thật.
Python3.11.17 `.venv` tái dùng; không dependency/cap tăng. pip/diff/shell/help và
desktop-file-validate đạt. Actual GUI cleanup/analysis chưa được chạy ở console.

Job `run_20261016T141614750605Z_08911504a237`:224 source/config files,lock SHA256
`246b257284bf30f2a9f9a52af36885d712024a9df5f57cc5eba02ae67b67cc45`. Giữ đúng64 rows/selection/manifests trước:
32Train/32 exposedValidation,16 mỗi lớp mỗi partition,seed42; không Test/chia lại.
Arlington thật `b7d880b7a3d3c8f505c025f17763397475e90503`:610TSV/3976rows kiểm checksum/model thật.

- split_manifest: `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv`; SHA256 `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643`.
- source_manifest: `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv`; SHA256 `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b`.
- normalization_manifest: `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv`; SHA256 `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f`.

Gói `run_20261016T141713997359Z_08911504a237`:11 files/121575bytes,SHA256
`5d0cbb352ddf1ecb458aae179e175804f4894327e0f4eeeb3aad12e5081d7e6a`. Metadata/config/runbook/desktop pin riêng và ignored;
không source-tree copy/PDF/wheels/model weights. Desktop được đối chiếu checksum
cũ rồi cập nhật atomically mode0700 và validate, không auto-launch. Package summary
lưu pending lúc build; `stale_desktop_install.json` lưu cập nhật thật.1714 reports
sau task gồm1707 file báo cáo cũ giữ nguyên và7 file mới; research-log prefix và
gói cũ giữ nguyên. Không upload/push/đổi NIC/xóa credentials hoặc nguồn dữ liệu.

**PDF thật/21 partial vẫn chưa chạy; kế hoạch tổng thể còn mở.** Không render/
JS runtime/Reader/CAPE/model evaluation/Test. Metrics N/A:không model/partition
được đánh giá; Label1=malicious; ECE10 equal-width bins,p=1 trong bin cuối.
