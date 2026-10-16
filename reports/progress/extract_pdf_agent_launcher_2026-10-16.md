# Dừng agent ngay trong launcher, 2026-10-16

Maintenance `run_20261016T132130000000Z_7c69699dab3a`.
Generating revision `7c69699dab3a16e971890144c49393529718bae4`, dirty during build.
Người dùng yêu cầu đưa bước dừng ssh-agent vào launcher thay cho gõ tay.

## Hành vi

Launcher tương tác thêm lựa chọn **`DUNG AGENT`** khi chỉ còn nhóm chặn agent/
credential, các điều kiện code/metadata/RAM/SSH/network/shared mounts đã đạt.
Không chạy bước này trong check-only, stdin/stdout không có TTY hoặc còn nhóm
chặn khác. Hủy prompt không phát signal hoặc đọc PDF.

`local_agent.py` đọc metadata có giới hạn: PID hợp lệ, bốn process UIDs thuộc
tài khoản hiện tại, tên `ssh-agent`, Unix socket cùng UID và identity không đổi.
Giữ Linux pidfd để tránh phát signal sang PID tái sử dụng; kiểm lại console và
identity sau prompt. Gửi SIGTERM rồi chờ tối đa3s. Chỉ khi tiến trình đã thoát,
socket biến mất và selection không đổi mới dọn **hai biến** SSH_AUTH_SOCK/
SSH_AGENT_PID trong tiến trình launcher. Không đụng môi trường parent desktop,
file key/token, credential khác, cấu hình dịch vụ hoặc NIC; không đọc/list keys.

Unknown/forwarded/stale selection, thiếu pidfd, lỗi hoặc socket còn thì giữ biến
và chặn PDF. Không fallback kill theo PID số hoặc force-kill. Sau bước agent,
launcher kiểm lại toàn bộ preflight; credential khác vẫn chặn. **CHAY TINH** và
runner guard/single-attempt claim vẫn bắt buộc riêng trước PDF.

## Kiểm chứng

**1720 passed**, hai cảnh báo sklearn single-label đã có,222.49s.
Log `artifacts/tmp/maintenance/extract_pdf/agent_full.log`.
Targeted67 passed/3.24s, gồm22 ca thêm so với suite1698; `agent_unit.log`.

Fixture tiến trình Python/socket riêng, không keys, tắt dumpability để kiểm tình
huống metadata proc bị hạn chế. Kiểm PID/user/name, socket khác, process exit,
isolation recheck, selection đổi, timeout và socket còn; môi trường khác giữ
nguyên. Fixture UI kiểm success/cancel/unknown/failure/remaining credential/
network/check-only/noninteractive; không gọi extractor ngoài mock runner được
xác nhận. Chỉ signal tiến trình fixture do test tạo, không dừng agent thật.

Reuse Python3.11.17 `.venv`; không đổi dependency/caps. `desktop-file-validate`
đạt cho package/Desktop; chưa kiểm nhấp đúp bước mới hoặc dừng agent thật ở
console người dùng. Không dùng fixture để nhận runtime trên LAB đã nghiệm thu.
Final checks lưu riêng `artifacts/tmp/maintenance/extract_pdf/agent_final_checks.json`.

## Job/package và bảo toàn

Job mới **`run_20261016T132849869208Z_7c69699dab3a`**,224 source/config files;
lock SHA256 `e1fbcdd2d6a60ae75aeaffc7aa5b326bde3e0716494d1ed8a51cdbf0ca26c6cb`.
Rows/selection hash/manifests đúng như job trước:32 Train/32 exposed Validation,
16 mỗi lớp mỗi partition,seed42; Test không chọn, không chia lại dữ liệu.
Source lock cũ từ chối drift. Arlington thật vẫn
**`b7d880b7a3d3c8f505c025f17763397475e90503`**, **610 TSV/3976 rows** đã kiểm.

Package **`run_20261016T132953367901Z_7c69699dab3a`**,11 files/121995 bytes,
SHA256 `66d4b85ec88236fd4b17c0390f35fb6822782b3e51368834605c65912731f9ac`.
Có job/config/environment/RUNBOOK/desktop pin và checksums; dùng repo/.venv/model
đã có, không phải installer, không source-tree copy/PDF/wheels/model weights.
Giữ private/ignored vì job lock có metadata mẫu; không upload hoặc đưa vào Git.

Đã cập nhật `/home/drstone/Desktop/Extract PDF Offline.desktop` sau khi đối chiếu
checksum bản trước, không tự mở. Các package/report trước giữ nguyên. Summary
lúc đóng gói ghi pending update; `agent_desktop_install.json` ghi cập nhật thật
sau đó. `agent_baseline.json`/`agent_job_checks.json`/`agent_handoff_checks.json`
giữ evidence riêng; không sửa lịch sử để thay trạng thái preparation.

Chưa chạy PDF thật/21 partial, chưa nhận xác nhận cô lập đầy đủ. Toàn bộ kế hoạch
sáu giai đoạn còn mở. Metrics F1/MCC/ECE/Brier N/A vì không đánh giá model/
partition; Label1=malicious,ECE10 equal-width bins,p=1 trong bin cuối.
