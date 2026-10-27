# Dùng LAB Runner

Windows là nơi sửa mã. REMnux là nơi chạy công việc đã duyệt. Hai giao diện đã
được triển khai trong source; việc cài chúng lên VM cần operator duyệt một lần.

## Dùng hằng ngày trên Windows

```powershell
.\lab.ps1 status
.\lab.ps1 doctor
.\lab.ps1 prepare
.\lab.ps1 test
.\lab.ps1 report
```

`test` mặc định dùng **gateway giới hạn**, không có prompt quản trị. Xem
[cài gateway một lần](lab_gateway.md). Trước khi gửi source, client xác minh
khóa runner riêng, policy/harness được ghim và các phép thử từ chối shell,
subsystem, forwarding, PDF và đối số lạ. Chỉ sau khi các gate đạt mới tạo
snapshot mã nguồn có hash và gửi job cố định. Không cần commit mỗi lần thử;
snapshot không stage/commit thay đổi của người dùng và không chứa data/raw.

`doctor` chỉ đọc metadata systemd/checkpoint/job qua audit key; không chạy lại
installer, service hoặc job. Endpoint chưa nâng cấp sẽ báo
`diagnostics_upgrade_required`; cần operator cài helper mới một lần. Sau đó
Codex tự lấy chẩn đoán đã lọc để tiếp tục sửa source và kiểm thử trong profile
syntax/synthetic đã duyệt.

```powershell
.\lab.ps1 test -Mode syntax
.\lab.ps1 test -Mode synthetic
.\lab.ps1 report -Refresh
```

Synthetic hiện là **6 ca lexer được operator ghim trong bộ cài**, không thu thập
test từ release gửi lên. Đây không phải toàn bộ pytest hay đánh giá parser/ML.
Worker chạy qua systemd bằng UID riêng, filesystem tối giản, source chỉ đọc,
không mạng/credential/corpus và tài nguyên hữu hạn. Audit key vẫn chỉ đọc;
runner key không có shell, sudo, SCP/SFTP hoặc forwarding. Thiếu gateway hoặc
proof cách ly thì báo `NOT READY`, không rơi về tài khoản quản trị.

`prepare` độc lập vẫn đóng gói commit sạch theo cơ chế cũ. `report` đọc cache
local nếu có job gateway; `report -Refresh` chỉ lấy schema tổng hợp qua audit.
Sau mất SSH, giữ job ID và đọc trạng thái; không submit lại hoặc chạy lại claim.
Luồng operator cũ chỉ được chọn rõ bằng `-Operator`; offline runner ở dưới vẫn
là tác vụ console riêng, không thuộc standing authorization của gateway.

`prepare -Gateway` tạo snapshot allowlist từ worktree hiện tại để review local,
không SSH, stage hoặc commit. `runner.installed` trong status là marker của
runner console cũ, tách biệt với runner/worker của gateway; không cài thêm luồng
quản trị cũ chỉ để đổi marker. Xem [ý nghĩa từng trạng thái](lab_gateway.md#ý-nghĩa-trạng-thái-và-kiểm-tra-cấu-hình).

Chế độ A chỉ chấp nhận guest IPv4 `192.168.217.10/24`, một adapter hoạt động,
route Host-only/loopback, không gateway/default route/IPv6 global hoặc shared
mount. Host-only vẫn tiếp xúc với Windows; kiểm tra này không thay firewall,
cấu hình VMware, kiểm tra clipboard của operator hay chứng minh containment.

## Chuẩn bị rồi chạy khi ngắt toàn bộ mạng

Tạo đề xuất PDF trên Windows trước khi cài/chạy:

```powershell
.\lab.ps1 prepare -Mode offline -Kind pdf-static
```

Lệnh chỉ đọc source/config và metadata VMware cố định, tạo snapshot source LF
có manifest cùng proposal chưa được phê duyệt. Không đọc dataset/PDF, không
SSH, không gửi job và không thay VMware. Proposal ghi rõ ba checksum manifest,
64 mẫu/seed, giới hạn, đầu ra giữ tại LAB và recovery. Các lần chuẩn bị cùng
source/profile có cùng job ID. Cần người dùng duyệt kế hoạch này riêng trước
khi operator queue/chạy PDF.

Host preflight đọc VMX có giới hạn và chỉ gọi vmrun list/listSnapshots. Nó không
in tên snapshot, đường dẫn shared folder hay raw VMX. Thiếu cờ copy/paste/share
tường minh được báo chưa xác minh; snapshot count không chứng minh recovery
dùng được. Cấu hình Host-only, VMX hoặc VMware Tools không xác nhận NIC runtime
đã ngắt, credential đã sạch hay guest đủ cô lập để đọc PDF.

Khi còn kết nối và đã cài runner console, operator chọn một tác vụ:

```powershell
.\lab.ps1 test -Mode offline -Kind syntax
.\lab.ps1 test -Mode offline -Kind synthetic
```

Lệnh chỉ chuẩn bị release và job, không chạy job offline. Sau khi operator
ngắt mọi NIC và xác minh snapshot/shared folders/clipboard/drag-drop/credentials,
trên console REMnux dùng:

```sh
lab status
lab preflight
lab run
lab report
lab menu
```

Chạy các lệnh này bằng tài khoản phân tích thường, không dùng `sudo lab run`.

`lab preflight` là lệnh **chỉ đọc** để biết vì sao `lab run` sẽ bị chặn, trước khi
bấm chạy. Output chỉ chứa số đếm và **tên** file/biến, không có nội dung file,
không có giá trị biến:

```json
{"credentials": ["home:.codex/auth.json", "env:SSH_AUTH_SOCK"], "network_changed": false, "pending_jobs": 1}
```

`credentials` rỗng nghĩa là cửa credential đã sạch. Khi `lab run` bị chặn bởi
`credential_present`, nó in lại đúng danh sách này và không claim job.

Hoặc mở **MalPDF LAB Runner** trong menu ứng dụng/Desktop. Mục 1 hiển thị
`lab preflight` cùng trạng thái runner; mục 2 chạy job. Nếu chỉ có một job,
runner tự chọn nó; nếu có nhiều job, chọn bằng số. Xác nhận console một lần,
không gõ hash hoặc đường dẫn. Guest networking, SSH session, shared mounts,
release và resource được kiểm tra lại. Hypervisor controls là xác nhận của
operator, không được trình bày như quan sát tự động từ guest.

Kết quả offline giữ trong LAB. `report -Refresh` trên Windows bị chặn cho mọi
job offline. Không tự kết nối lại VM; xuất dữ liệu sau phân tích cần quy trình
review/recovery riêng.

## PDF thật: phê duyệt riêng

Profile `pdf-static` hỗ trợ cohort CIC64 cố định bên dưới. Profile riêng
`pdf-static-cve` hỗ trợ đúng năm mẫu CVE-T4PDF theo manifest ghim checksum.
Đường dẫn thư mục do người dùng cung cấp không thay đổi hai cohort này. Với tập
PDF khác, cần xác định thư mục cụ thể, manifest và số mẫu hữu hạn, rồi review
luồng xử lý tương ứng trước khi queue; không dùng lệnh CIC64 như thể nó đã chọn tập mới.
Không duyệt đệ quy toàn bộ thư mục `data` hoặc đọc PDF để tự suy ra lựa chọn.

Chỉ khi đã duyệt cohort, môi trường và isolation mới chọn:

```powershell
.\lab.ps1 test -Mode offline -Kind pdf-static
```

Đây là lệnh do operator chạy trong PowerShell riêng: nó yêu cầu xác nhận thật
và mật khẩu SSH quản trị. Agent không nhập xác nhận/mật khẩu. Source được đóng
gói từ worktree allowlist, chuẩn hóa LF và kiểm lại sau xác nhận; không yêu cầu
commit các thay đổi không liên quan. Transfer chỉ cài release bất biến/queue
metadata; `pdf_prepare` chỉ kiểm dependency và selection metadata, chưa đọc PDF.
Runner root-owned phải khớp hash trong source package. Không gửi qua restricted
gateway syntax/synthetic, không mở thêm action PDF cho khóa gateway.

### Chạy song song trong một job

`policy('pdf-static')` đặt `workers` lớn hơn 1. `pdf_task` tách job thành `workers`
shard theo `index % workers`; mỗi shard là một tiến trình `pdf-worker` riêng
(`--shard i --of N`), dùng chung một deadline, và chỉ ghi
`private_bundles/{index:04d}.json` của mình nên không cần lock.

Từng shard ghi `pdf_summary.<shard>.json`; parent hợp nhất thành `pdf_summary.json`
gồm chín bộ đếm cũ cộng `status_counts`, histogram theo đúng từ vựng trạng thái
của bundle (`observed`, `partial`, `decode_error`, `encrypted`, `timeout`,
`resource_limit`, `unsupported`, ...). Nhờ đó `failed` không còn là một khối mù:
`result.json` in ra ở console và mọi export được duyệt sau này đều mang theo
histogram, không cần thêm tệp phụ. Contract kiểm ba điều kiện fail-closed: khóa
lạ ngoài từ vựng bị từ chối, `sum(status_counts) == completed`, và tổng theo
nhóm phải khớp `observed`/`partial`/`failed`.

Giới hạn trung thực: `normalize_profile` gộp mọi lý do không khớp từ khóa về
`partial`, nên lỗi đọc/khớp checksum đầu vào cũng hiện thành `partial` chứ không
thành nhãn riêng. Muốn tách nhóm đó phải sửa `src/malpdf`, không suy đoán từ
chuỗi tự do. `catalog()` cũng bỏ qua các job cũ không còn khớp `policy` hiện tại
(`job_mismatch`) thay vì làm hỏng toàn bộ danh sách job.

Số worker là hằng số policy đã review, không tự suy ra từ số CPU của guest; phải
khớp với RAM/cgroup thực tế của LAB. Giới hạn mỗi file (`file_cpu_seconds`,
`file_wall_seconds`, `file_memory_bytes`) không đổi khi tăng `workers`.
`RLIMIT_AS` của mỗi tiến trình shard giữ 2 GiB như lượt chạy đơn đã chứng minh;
đó là trần **địa chỉ**, không phải RSS. Nếu pilot shard trả về `resource_limit`
hoặc VM bắt đầu swap, hạ `workers` trước khi siết trần này — đổi cả hai biến cùng
lúc sẽ không còn phân biệt được nguyên nhân.

### Đối chiếu hai lần chạy tại console LAB

Chứng minh sharding không đổi kết quả, chạy tại console (không cần Windows, không
xuất bundle):

```text
lab report <job_single>
lab report <job_sharded>
lab compare <job_single> <job_sharded>
```

`report` với job cũ vẫn in `status`, `reason`, `pdf_summary` kể cả khi policy đã
đổi, nhưng chỉ sau khi summary khớp schema lịch sử (chín bộ đếm) hoặc schema hiện
tại; job lạ/hỏng bị từ chối. `compare` chỉ in số nguyên: `compared`, `identical`,
`status_mismatch`, `feature_mismatch`, `missing_bundles`, `first_mismatch_index`,
`same_selection`, `same_commit`. Nó so `status` và digest của `feature_store`
từng `index`, không in giá trị feature, đường dẫn hay văn bản từ PDF. Hai job
phải cùng số mẫu; khác commit vẫn so được nhưng `same_commit=false` cảnh báo
rằng khác biệt có thể do source chứ không do shard.

Release offline hiện được khóa theo base commit. Nếu LAB đã có release cùng
base nhưng khác manifest, receiver từ chối `release_mismatch`; không ghi đè hay
xóa release cũ. Trường hợp đó cần một phiên bản source/commit mới được review
riêng. Snapshot chỉ loại bỏ yêu cầu commit thay đổi không liên quan cho trường
hợp chưa xung đột release; không đổi content hash thành Git commit giả.

Lần duyệt này nói rõ **64 CIC:32 Train/32 Validation, seed42, không Test**,
theo ba manifest checksum trong `configs/cic_static_benchmark.yaml` của release.
LAB kiểm tra đầy đủ dependency đã khai báo và chuẩn bị selection chỉ bằng
metadata, không đọc PDF. Các CSV, model Arlington và môi trường đã có phải
khớp; không tải hoặc thay dataset để vượt lỗi. `setup` không tự cài dependencies.

Sau đó `lab run` khi thực sự offline sẽ kiểm tra lại selection, nguồn, model
Arlington, credentials và tài nguyên, rồi mới đọc PDF. Năm tiến trình shard
(`workers=5`),10MiB/file, 20s wall/12s CPU/1GiB address space mỗi parser; lượt
tối đa30phút,512MiB bundle riêng tư,8MiB/file và không renderer/JS runtime/Reader/CAPE. Worker riêng áp
giới hạn CPU/RAM/file/FD/process trước khi import stack parser. Không ghi raw
blobs và không fit model. Một worker không dọn sạch sẽ dừng phần còn lại.

Giới hạn process theo UID dùng chung với các ứng dụng khác; thiếu tài nguyên
thì dừng. Chạy ở tài khoản/môi trường đã rà soát, không tăng trần ngầm để vượt
lỗi. Report giữ số mẫu dự kiến, hoàn thành, partial/lỗi và primary checkpoint;
không suy độ chính xác hay độ phủ toàn diện từ số đếm. Các bundle riêng tư ở
`/var/lib/malpdf/jobs/<job_id>/private_bundles/` không được tự chuyển ra Windows.

## Lượt thử năm mẫu CVE-T4PDF

Chuẩn bị đề xuất local, chưa truy cập dataset hoặc SSH:

```powershell
.\lab.ps1 prepare -Mode offline -Kind pdf-static-cve
```

Đầu vào tại LAB là đúng năm tệp trong
`/home/remnux/MalPDFDeepDetection/data/raw/cve_t4pdf/`:
`bank_statment.pdf`, `link_URI.pdf`, `rce_foxit.pdf`, `url2_invoice_template.pdf`
và `xss_popup.pdf`. Manifest metadata là
`data/processed/source_preparation/run_20261001T133833267219Z_3efd81e782c1/cve_t4pdf/source_pdf_manifest.csv`,
SHA-256 `3dd3412cfdd277b3b14ff198db807679557b3b32bcb20af8b2f2770610eea4aa`.
Manifest tham chiếu các bản copy đã chuẩn bị; helper xác minh đúng tên/ID, giữ
đường dẫn gốc của manifest trong selection và ánh xạ tường minh sang năm tệp raw.
Hash từng PDF raw phải khớp hash tương ứng khi thực sự chạy offline. Không thay
thế bằng bản copy khác nếu raw thiếu hoặc sai; không duyệt cả cây thư mục.

Helper root-owned `lab_jobs.py` và `lab_runner.py` phải được operator cập nhật
qua bộ cài gateway đã review rồi xác minh lại gateway. Không mở thêm action
PDF cho runner key. Runner console đã cài được giữ lại; thay đổi source Windows
không tự cập nhật helper LAB. Khi policy local/LAB lệch, dừng với
`local_policy_mismatch`; không dùng helper cũ để queue profile mới.

Sau khi người dùng chọn cohort và duyệt gói source/metadata, operator queue bằng:

```powershell
.\lab.ps1 test -Mode offline -Kind pdf-static-cve
```

Queue chỉ kiểm dependency, CSV có checksum và metadata năm tệp regular, không
symlink/hardlink, không rỗng/quá cỡ; chưa đọc byte PDF. Nó lưu `selection.json`
bất biến trước khi ngắt mạng. Lỗi metadata trả reason cố định, không đưa stdout,
traceback hoặc nội dung file của worker về Windows. Thiếu manifest/dependency
thì dừng; không download hoặc tự cài để vượt gate.

Sau khi snapshot/recovery, clipboard/shares/drag-drop, credentials và mọi NIC
đã được operator kiểm tra, dùng `lab status` rồi `lab run` tại console vật lý.
Console in job ID, profile, cohort, giới hạn và nơi lưu trước xác nhận thật.
Đúng năm mẫu, một worker, tối đa 180 giây/lượt; mỗi parser 20 giây wall,
12 giây CPU, 1GiB, 10MiB input. Private JSON tối đa 8MiB/tệp, 40MiB/lượt,
chỉ lưu trong LAB. Helper kiểm lại guest isolation/credentials trước mỗi mẫu,
tái sử dụng bounded `extract_pdf` và model Arlington có checksum. Không render,
chạy JavaScript, mở Reader, detonate, fit model hoặc đánh giá độ chính xác.
Nhãn lịch sử do người dùng gán được giữ làm provenance, không coi là ground truth
đã kiểm chứng. `planned` luôn là 5; partial/lỗi và mẫu chưa hoàn thành được giữ.

Không reconnect sau phân tích. Giữ claim, private bundles và backups khi lỗi;
recovery hoặc export thực hiện theo quy trình review riêng. Báo cáo PDF không
được tải tự động qua audit hay `report -Refresh`.

## Bộ cài console/offline cũ

Với gateway và audit đã được xác minh, chuẩn bị bộ cài từ source Windows hiện tại:

```powershell
.\lab.ps1 setup -Mode offline
.\lab.ps1 setup -Mode offline -Transfer
```

Bootstrap có **12 tệp**, source helper/installer và public audit key hiện có;
không gồm PDF, dataset hoặc private key. Transfer có gate TTY/xác nhận/mật khẩu
thật, kiểm lại manifest rồi copy vào thư mục mới
`/home/remnux/malpdf-offline-bootstrap/<manifest-id>`, không cài hoặc queue job.
Operator duyệt manifest và chuyển đúng thư mục bootstrap. Không
dùng Shared Folders/clipboard để vận hành phiên offline. Từ thư mục bootstrap
tại console REMnux, hai lệnh ngắn là:

```sh
sudo sh setup_runner.sh --check
sudo sh setup_runner.sh --install
```

`--check` chỉ kiểm tra. `--install` kiểm checksum tự động, cài helper kiểm tra
cục bộ, `/usr/local/bin/lab`, `/etc/malpdf/runner.json`, private jobs và menu.
`setup_runner.py` kiểm gateway config/proof thực, root ownership, hash của sáu
helper dùng chung và public key audit hiện tại trước mọi thay đổi. Nếu lệch
policy, thiếu gateway verified hoặc audit key khác, nó từ chối; không ghi lại
helper/keys/accounts/SSHD/systemd của gateway và không reload SSH. Nó chỉ cài
check_local, runner.json, CLI/menu cùng thư mục jobs/inbox/releases cần thiết,
lưu backup riêng và kiểm gateway lần nữa. Thư mục jobs đã có phải riêng tư 0700,
đúng UID/GID; state khác chủ/quyền cần operator review, không reset tự động.
Các directory mới dùng no-follow và thao tác qua FD khi gán quyền.

Nó không sửa adapter, route, firewall, dataset hoặc cài dependencies. `--check`
không đọc PDF và không ghi file; chưa phải xác nhận dependency/cohort đủ dùng.

Mặc định data root là `/home/remnux/MalPDFDeepDetection`, Python lấy `.venv/bin/python`
nếu có, nếu thiếu dùng `/usr/bin/python3` cho tác vụ stdlib. Các giá trị phải
được operator kiểm tra tại setup; PDF sẽ bị chặn nếu môi trường không khớp.
Không suy rằng dependency trên Windows cũng đã có trong VM.

Source cũ và runtime đang dùng không bị đổi. Root helpers/config có backup ở
`/var/tmp/malpdf-runner-setup.*`, với bản cũ của check_local, runner.json, CLI và
menu được đánh số. Rollback ở console chỉ khôi phục các tệp đã có từ backup sau
khi review; tệp mới cần xử lý riêng. Không xóa report/job/claim hoặc reset một
lượt đã chạy. Không tự revert snapshot làm mất evidence, không reconnect sau
phân tích. Giữ VM offline khi lỗi và áp dụng quy trình phục hồi/export được duyệt.
Cài nhiều tệp không phải giao dịch rollback tự động; lỗi giữa chừng cần operator
kiểm tra backup. Gateway/audit đã xác minh được giữ nguyên.

## Khi có lỗi

| Mã ngắn | Xử lý |
| --- | --- |
| `source_dirty` | Review/commit thay đổi trên Windows, không bỏ qua gate |
| `setup_required` | Review/cài bootstrap mới một lần; endpoint audit cũ vẫn chỉ đọc |
| `network_blocked` | Kiểm tra đúng mode, route, NIC và shared mounts ở console; script không sửa chúng |
| `release_mismatch` | Kiểm lại source/manifest; không ghi đè release cũ |
| `manifest_unavailable` | Chuẩn bị metadata/job trước khi ngắt mạng; không thay bằng cohort khác |
| `dependency_mismatch` | Review môi trường LAB đã có; cài package là tác vụ riêng được duyệt |
| `credential_present` | Chạy `lab preflight` để xem đúng tên file/biến gây chặn (chỉ tên, không giá trị); dùng LAB đã rà soát không có credential; không tự xóa key/token |
| `already_claimed` | Xem báo cáo/diagnostic tại LAB; không tự retry hoặc xóa claim |
| `export_requires_review` | Giữ kết quả offline tại LAB, dùng quy trình export/recovery riêng |

Prompt/TTY không phải access-control. Giữ credential quản trị và phiên operator
ngoài quyền điều khiển Codex; report có schema không phải attestation của VM.
