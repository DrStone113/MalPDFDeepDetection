# Launcher chờ người dùng ngắt mạng, 2026-10-16

Maintenance `run_20261016T135803079927Z_b979e7832732`. Generating revision `b979e7832732ddb3a8a8404a20cb30848ede1fe2`, dirty during build;
code/tests/docs/log committed together for the clean-code gate. Resulting HEAD
and final metadata checks are saved in `artifacts/tmp/maintenance/extract_pdf/wait_final_checks.json`.

Mở **Extract PDF Offline** tại VMware console khi còn mạng, tự ngắt NIC rồi
nhấn **Enter**. Launcher kiểm lại điều kiện, dừng agent cục bộ đã xác minh nếu
cần, rồi chạy tĩnh một lần khi mọi guard đạt. Không còn hai câu xác nhận riêng.
Còn mục chặn môi trường thì chờ Enter tiếp trong cùng cửa sổ; không polling,
đổi NIC, gọi job bị chặn hoặc đọc PDF lúc chờ. Nonempty input (q) hủy.
Code/job/model/RAM/claim lỗi vẫn từ chối. Check-only và noninteractive không dừng
agent; credential khác, runner recheck, mọi caps và exclusive claim giữ nguyên.

Kiểm chứng: **1727 passed**, 2 cảnh báo sklearn single-label đã có,
496.32s; `artifacts/tmp/maintenance/extract_pdf/wait_full.log`.
Targeted **74 passed/13.53s** (`wait_unit.log`);7 ca mới so với1720. Fixture kiểm
mở khi còn mạng, ngắt mạng trong prompt rồi một Enter chạy, Enter nhiều lần khi
vẫn còn mạng/SSH/share/unknown, reconnect và code drift sau xác nhận; real runner
refuse nếu reconnect trước claim. Agent chỉ là process/socket fixture riêng.
Python3.11.17 `.venv` được tái dùng, không đổi dependency/caps. pip check,
diff whitespace, shell syntax, CLI help và desktop-file-validate đạt. Không tự
mở GUI hoặc dừng agent thật; hành vi mới chưa được người dùng chạy tại console.

Job `run_20261016T134919360105Z_b979e7832732` khóa224 source/config files, SHA256
`711e37e1969b2b2f5736d1c785ea8fb9010912ac9d213dcc41ea97b6403b6fae`; giữ đúng64 rows/selection/manifests trước đó:
32Train/32 exposedValidation,16 mỗi lớp mỗi partition,seed42. Không Test/chia lại.
Arlington thật **b7d880b7a3d3c8f505c025f17763397475e90503**, **610 TSV/3976 rows** đã kiểm bằng
model/checksum đã khóa; model không bị thay bằng fixture. Manifest giữ nguyên:

- split_manifest: `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv`; SHA256 `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643`.
- source_manifest: `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv`; SHA256 `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b`.
- normalization_manifest: `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv`; SHA256 `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f`.

Package `run_20261016T134953300090Z_b979e7832732`:11 files/121396bytes, SHA256
`fd5dae307bdad5f6290709af1ab041815f2edadf11b3df2b7043551e08248d0a`. Chứa metadata/config/runbook/desktop pin;
không source-tree copy/PDF/wheels/model weights, dùng repo/.venv/model hiện có.
Giữ private/ignored; không upload/commit sample metadata. Đã đối chiếu checksum
Desktop trước khi cập nhật atomically, mode0700, validate đạt; không auto-launch.
`wait_desktop_install.json` ghi cập nhật thật; package summary ghi trạng thái
pending tại lúc đóng gói. Giữ nguyên1700 file báo cáo đã có, prefix research log
và archive trước; mọi kiểm tra cuối lưu dưới maintenance domain hiện có.

**PDF thật/21 partial chưa chạy; không có classifier/Test evaluation hoặc kết
quả nghiệm thu corpus.** Chưa render/chạy JS/Reader/CAPE, không đọc/hash/parse
PDF thật, xóa credentials, ngắt NIC, push hoặc upload bên ngoài. Các phần thiếu
của kế hoạch sáu giai đoạn vẫn mở. Metrics N/A (không model/partition được đánh
giá); Label1=malicious; ECE10 equal-width bins,p=1 trong bin cuối.
