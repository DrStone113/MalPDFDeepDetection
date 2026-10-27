# Gateway cho Codex tự kiểm thử LAB

Sau một lần operator cài và xác minh quyền, Codex có thể sửa source trên Windows,
kiểm tra local, gửi snapshot bất biến và nhận báo cáo syntax/synthetic mà không
hỏi mật khẩu hay yêu cầu duyệt từng test. Audit key hiện có giữ nguyên vai trò
chỉ đọc. Mã mới chưa đồng nghĩa gateway đã được cài trên VM.

## Tài khoản operator, root và automation

`remnux@remnux` nghĩa là user `remnux` trên máy có hostname `remnux`. Tài khoản
này tách biệt với `root` (UID 0). Một lệnh `sudo` được phép chạy với quyền root
không biến toàn bộ phiên terminal thành root. `id -u` trả UID thực tế của phiên;
chỉ giá trị 0 mới là root. Không cần tạo thêm root hoặc bật root SSH để cài Gateway.

| Tài khoản | Vai trò |
| --- | --- |
| `remnux` | Operator; tự nhập password khi chuyển bộ cài và dùng sudo cho setup đã review |
| `root` | Tài khoản hệ thống UID 0; sở hữu cấu hình/helper, không phải tài khoản chạy job |
| `malpdf-audit` | Chỉ đọc status/report đã lọc qua key và forced command riêng |
| `malpdf-runner` | Chỉ nhận job/source hợp lệ qua key và forced command riêng, không sudo/shell tùy ý |
| `malpdf-worker` | UID chạy job trong sandbox systemd; không đăng nhập SSH |

Installer `configure_accounts()` tạo runner/worker nếu thiếu, khóa password và
kiểm UID/home/shell/group/quyền sudo/process nếu đã có. Audit là prerequisite
riêng và key audit không được dùng cho runner. Việc có user chưa chứng minh
Gateway đã sẵn sàng: vẫn phải đạt policy, proof, negative tests và containment.
Không tạo một account tùy ý để né lỗi SSH operator, không nâng quyền cho account
automation và không dùng root SSH thay cho bước xác minh lỗi `remnux`.

## Ý nghĩa trạng thái và kiểm tra cấu hình

`runner.installed` trong status schema 2/3 là marker của **runner console/offline
cũ**, chỉ kiểm sự tồn tại của `/etc/malpdf/runner.json`. Gateway không tạo marker
này. Không cài luồng quản trị cũ hoặc tự ghi marker để biến trường đó thành true;
gateway dùng UID runner/worker, unit và proof riêng. Với kiểm thử tự động, dùng
`gateway` cùng `verify` và `doctor` làm điều kiện sẵn sàng.

`gateway.installed` chỉ được đặt true sau khi toàn bộ `config()` đạt: cấu trúc
`/etc/malpdf/gateway.json`, UID tách biệt, allowlist profile, hash helper, ba unit
systemd và drop-in SSHD. File `lab_gateway.py` tồn tại chưa đủ. Nếu `installed`
false và `policy_sha256` null, lỗi xảy ra trước khi `config()` hoàn tất; trạng
thái này **không xác định được** một file cụ thể bị thiếu hay bị sai quyền/hash.

`policy_sha256` là SHA-256 của JSON canonical ánh xạ tên 10 helper tới SHA-256
nội dung từng file. Unit/SSHD được ghim hash riêng. Proof root-owned phải khớp
policy, profile, unit và SSHD hiện tại; chỉ đổi cờ `verified` không đủ. Cơ chế
này dùng hash và quyền root, không dùng chữ ký số độc lập. Client so sánh lại
policy với source Windows đã chuẩn hóa CRLF thành LF. Config, helper, unit,
drop-in và proof phải là file thường root-owned, không có bit ghi cho group/
other, không symlink hoặc hardlink.

`offline_guest_ready` kiểm guest không có SSH session, NIC kết nối, interface
chưa rõ hoặc shared mount. Phiên SSH Host-only đang hoạt động khiến phép kiểm
offline từ chối là hành vi đúng. Trường này không chứng minh clipboard, VMware
shares hoặc containment cho malware đã được xác minh độc lập.

## Codex tự chẩn đoán

```powershell
.\lab.ps1 doctor
```

Đây là chẩn đoán chỉ đọc qua audit key hiện hữu, bằng đúng forced command
`diagnose gateway`. Không cần kết nối GitHub hay cấp shell quản trị. Endpoint
chỉ gọi `systemctl show` cho đúng ba unit gateway, trong tối đa 4 giây và 16KiB
output; chỉ giữ enum trạng thái, exit code, cờ đã chạy/kết thúc và timer trigger.
Không nhận tên service, đường dẫn hoặc shell command do caller chọn, không đọc
journal/raw logs, không in mô tả unit, hostname, credential hay nội dung PDF.
Xem [systemctl show](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Báo cáo doctor API 2 bổ sung `configuration_checks` cho đúng sáu nhóm cố định:
`configuration`, `helpers`, `policy`, `units`, `sshd`, `proof`. Mỗi nhóm chỉ trả
enum `passed`, `missing`, `unreadable`, `unsafe`, `invalid`, `mismatch` hoặc
`not_checked`; không xuất đường dẫn, lỗi Python hay nội dung file. Đây là cùng
verifier dùng để chặn job. Client vẫn đọc được API 1, nhưng không suy ra các
kiểm tra mới đã đạt. Doctor từ chối ready khi hash policy local khác hoặc không
đọc được. Khi endpoint cũ từ chối `diagnose gateway`, client chỉ lấy thêm đúng
`status` đã kiểm schema vào `audit_status`, vẫn báo `diagnostics_upgrade_required`.

Installer ghi checkpoint giai đoạn/lỗi tại `/etc/malpdf/gateway-installation.json`
và trong backup của lần cài. Probe/worker ghi kết quả đã lọc ngay cả khi thất
bại; các report job và claim bất biến vẫn được giữ. Hai pointer `last-job.json`
ở queued/reports được cập nhật nguyên tử để doctor thấy job mới đang chờ hoặc
kết quả gần nhất, không quét corpus hay xóa lịch sử. Doctor đọc đúng các tệp
metadata cố định, kiểm schema/kích thước phía LAB rồi kiểm lại trên Windows.

Doctor phân biệt endpoint chưa nâng cấp, LAB không kết nối, metadata không hợp
lệ, cài đặt chưa xong, unit/probe lỗi, timer chưa hoạt động, job đang chờ, job
thất bại và job gần nhất đạt. `inactive (dead)` của service oneshot không được
coi là lỗi hoặc bằng chứng đã chạy test. Exit code: `0` ready, `1` failed,
`3` not_ready, `4` pending. Bản chẩn đoán mới được lưu riêng dưới local workflow
cache; mất SSH vẫn báo `lab_unreachable`, không dùng cache cũ để nhận vơ kết quả
mới hoặc tự kết nối lại VM offline.

Khi SSH không truy cập được, doctor tự bổ sung trường `host_vmware` từ VMware
trên Windows: VM có đang chạy, trạng thái Tools và IP guest có khớp endpoint
dự kiến hay không. Nó chỉ gọi `vmrun list`, `checkToolsState` và
`getGuestIPAddress` cho VM đã nhận diện tại `C:\VirtualMachine\Remnux.vmx`,
không truyền guest username/password, chạy program/script, đọc tệp trong guest,
chuyển tệp, bật VM hoặc đổi mạng. Mỗi query tối đa 3 giây, chỉ chấp nhận output
tối đa 4 KiB và trả enum/IP đã lọc; không in danh sách VM/path hoặc stderr.
Metadata này không chứng minh dịch vụ SSH hoạt động hoặc LAB đủ containment.
Endpoint không tự đổi theo IP được báo. Nếu chưa có VMware/Tools hoặc metadata
không hợp lệ thì giữ trạng thái chưa xác minh. `-Mode offline` bỏ cả truy vấn
SSH lẫn VMware; không dùng guest Tools làm đường chạy lệnh thay cho gateway.

`doctor -Mode offline` không gọi SSH; nó chỉ lưu trạng thái
`offline_result_requires_review`. Kết quả riêng của phiên PDF/offline tiếp tục
ở LAB và chờ quy trình phục hồi/export được duyệt.

Nếu audit trả `diagnostics_upgrade_required`, operator cần chuyển/cài bộ helper
mới một lần theo hướng dẫn dưới. Sau đó Codex có thể tự doctor, sửa source
Windows và gửi các job syntax/synthetic mới qua gateway đã xác minh. Doctor
không cấp quyền chạy job, không tự start/restart/reload service, cài đặt, nâng
quyền hoặc xử lý PDF thật. Client test vẫn kiểm các quyền phủ định độc lập;
cùng job đã claim không được tự gửi/chạy lại.

## Cài một lần

Trên Windows, chuẩn bị bộ cài:

```powershell
.\lab.ps1 setup -Gateway
```

Lệnh chỉ chạy local. Nó tạo riêng khóa Ed25519 `id_ed25519_malpdf_runner` nếu chưa
có; không đọc/in private key, không ghi đè cặp khóa hiện hữu, không dùng khóa
audit hoặc GitHub. Chỉ public key được đưa vào bootstrap. Bộ cài gồm 14 tệp có
manifest SHA-256, ghi rõ base commit và nguồn là snapshot đã review, không nhận
vơ rằng nội dung chưa commit đã nằm trong Git.

Operator review manifest, source installer/helper/harness và các thay đổi tài
khoản/SSHD/systemd dưới đây. Để chuyển bộ cài, mở **PowerShell riêng trên Windows**
tại `C:\Project\MalPDFDeepDetection`, rồi chạy:

```powershell
.\lab.ps1 setup -Gateway -Transfer
```

Lệnh tự tìm/tạo đúng bộ cài, kiểm lại 14 tệp và hash, hiển thị endpoint,
manifest/thư mục đích, rồi chờ operator nhập `y`. Windows OpenSSH có thể hỏi
mật khẩu REMnux hai lần: tạo thư mục mới và chép các tệp. Chỉ nhập mật khẩu trong
terminal đó. Client giữ strict host-key checking; nếu host key chưa được xác
minh hoặc thay đổi thì dừng, không bỏ qua kiểm tra.

Đích là `Home/malpdf-gateway-bootstrap/<manifest-id>` trên REMnux. Thư mục đã
tồn tại sẽ bị từ chối; không ghi đè hoặc tự xóa bản chép dở. Lệnh không chạy
installer, không gọi sudo và không chuyển dữ liệu ngược về Windows. Codex không
gọi luồng quản trị này hoặc nhập xác nhận/mật khẩu thay operator.

Tại console REMnux, dùng Files mở thư mục vừa nhận trong
`Home/malpdf-gateway-bootstrap`, chọn **Open in Terminal**, rồi chạy:

```sh
sudo sh setup_gateway.sh --check
sudo sh setup_gateway.sh --install --allow-synthetic
```

`--check` không ghi hệ thống. `--install` không có `--allow-synthetic` chỉ duyệt
AST/syntax. Cờ `--allow-synthetic` là phê duyệt một lần cho đúng harness đi kèm,
không cho phép chạy pytest/tên test/command do source gửi lên chọn.

Installer giữ backup root-only ở `/var/tmp/malpdf-gateway-setup-*`, cài hai UID
riêng `malpdf-runner` và `malpdf-worker`, khóa mật khẩu, kiểm không có sudo hoặc
group lạ; giữ nguyên khóa audit. Nó cài helper root-owned, SSHD forced command,
systemd service/probe/timer và runtime tại `/var/lib/malpdf-gateway`. Chỉ source
uploads/requests và báo cáo/claim của gateway được ghi; không ghi dataset,
release/runtime cũ, NIC, route, firewall, Internet hoặc dependency.

Installer kiểm cấu hình SSHD hiệu lực và chạy probe cách ly thật trong cùng cấu
hình worker. Nếu probe hoặc SSHD không đạt, trạng thái được giữ `NOT READY`.
Cài nhiều tệp không phải giao dịch rollback nguyên tử; operator phải dùng backup
ở console nếu lỗi. Không xóa job, claim, report hoặc dữ liệu để khắc phục.

Mỗi lần cài chủ động thu hồi proof cũ **trước khi** sửa thành phần cấu hình.
Lỗi ở bước tài khoản/layout/helper cũng được ghi checkpoint `configuration`
với reason cố định và giữ proof vô hiệu. Cài lại phải chạy lại probe và kiểm
SSHD; không giữ kết quả ready từ lượt trước. Job đã claim được giữ nguyên qua
nâng cấp. Job chưa claim nhưng dùng policy/profile cũ bị từ chối có báo cáo
cuối cùng, không chạy source và không chặn các job mới theo policy hiện tại.

Rollback chỉ tại console operator: dừng timer gateway, chọn đúng backup của
lượt cài và đối chiếu `targets.json` với các file backup có tiền tố số. Giữ
proof vô hiệu; khôi phục các helper/config/unit/drop-in đã review từ cùng một
bộ, giữ owner/mode, không chép lẫn nhiều phiên bản. Kiểm `sshd -t` và effective
policy trước reload SSH; daemon-reload systemd sau khi phục hồi unit. Không
phục hồi riêng cờ verified cũ hoặc bật timer trước khi chạy lại các verifier và
probe. Không xóa uploads/releases/requests/reports/claim, tài khoản hay dữ liệu
để rollback; giữ cả backup và checkpoint thất bại cho việc đối chiếu.

### Nếu chuyển bộ cài báo Permission denied

Nếu ngay sau prompt `remnux@192.168.217.10's password:` xuất hiện
`Permission denied (publickey,password)`, kết nối đã tới bước xác thực nhưng
chưa đăng nhập thành công. Trong luồng này, kết nối đầu tiên chuẩn bị thư mục;
chỉ sau khi lệnh đó thành công mới chạy SCP. Với lỗi xác thực ở kết nối đầu,
chưa có thao tác chép source của lượt đó. Không suy ra trạng thái thư mục từ
một mã thoát SSH chung vì lỗi kết nối ở thời điểm khác có thể để lại trạng thái
dở dang.

Client cố định tài khoản Linux `remnux`, IP `192.168.217.10`, không dùng alias
`lubuntu`, bỏ user/system SSH config bằng `-F none`, chỉ dùng phương thức
`password` và giới hạn một lần nhập cho mỗi kết nối. Password bị từ chối không
chứng minh chính xác là gõ sai: tài khoản bị khóa/hết hạn, yêu cầu xác thực kết
hợp, policy SSH/PAM hoặc keyboard layout cũng cần được phân biệt. Danh sách
`publickey,password` trong lỗi không chứng minh máy chủ bắt buộc cả hai cách.
Audit key đăng nhập được cũng không chứng minh password của `remnux` hợp lệ.

Operator trước hết kiểm tra đăng nhập ngay tại console VMware bằng đúng tài
khoản và cùng mật khẩu, nhập riêng tại console; không gửi mật khẩu vào chat.
Nếu console cũng từ chối, cần kiểm tra credential/account tại console trước.
Nếu console đăng nhập được mà SSH vẫn từ chối, operator mới kiểm tra trạng
thái account và effective SSHD/PAM policy dành riêng cho `remnux`. Đây là thông
tin mà endpoint audit hiện tại không cung cấp; không mở rộng allowlist hoặc
dùng key audit/runner làm đường chuyển file thay thế.

Khi đã có console `remnux`, hai phép kiểm chỉ đọc tối thiểu là:

```sh
passwd -S remnux
sudo /usr/sbin/sshd -T -C user=remnux,addr=192.168.217.1,host=192.168.217.1,laddr=192.168.217.10,lport=22 | grep -E '^(authenticationmethods|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|usepam) '
```

`passwd -S` chỉ trả trạng thái password, không trả password/hash. Phép kiểm
SSHD không ghi cấu hình hoặc reload service; `sudo` do operator thực hiện tại
console. Địa chỉ trong `-C` phải khớp kết nối thực tế; Windows đã quan sát route
chọn nguồn `192.168.217.1` tới endpoint `192.168.217.10` trong lượt kiểm tra
2026-10-22. Nếu topology thay đổi, xác minh lại trước khi diễn giải Match.
Chỉ cần các dòng trạng thái được lọc ở trên; không gửi password, private key
hoặc raw authentication logs. Nếu chúng chưa giải thích được lỗi, việc xem
account expiry/PAM/authentication logs là bước operator tiếp theo tại console,
không phải quyền đọc log tùy ý cho agent.

Nếu hai phép kiểm trên cho password status `P`,
`passwordauthentication yes`, `authenticationmethods any` nhưng lần chuyển
vẫn bị từ chối, operator có thể lấy nhãn lỗi cố định tại console:

```sh
sudo journalctl -u ssh -n 200 --no-pager -o cat | grep -F remnux | grep -Eo 'Failed password|authentication failure|account expired|not allowed|pam_faillock|pam_access|pam_nologin' | sort -u
```

Chỉ gửi các nhãn được lọc, không gửi raw log. `Failed password` cùng
`authentication failure` xác nhận kiểm tra xác thực đã thất bại, không tự nó
chứng minh duy nhất lỗi gõ sai hoặc loại trừ mọi PAM rule. Các nhãn chỉ phản ánh
các bản ghi được lấy; không dùng sự vắng mặt của một nhãn làm bằng chứng phủ định.

Với trường hợp này, bước khắc phục credential có phạm vi hẹp là operator chủ
động đặt lại password của riêng tài khoản `remnux` tại console:

```sh
sudo passwd remnux
```

Operator tự chọn và nhập password mới hai lần, không gửi password vào chat.
Chỉ tiếp tục sau thông báo `passwd: password updated successfully`. Đây là thay
đổi credential có chủ ý do operator thực hiện, không phải agent tự reset để né
gate. Nó không chứng minh đã giải quyết nguyên nhân nếu PAM/account vẫn từ chối.
Sau đó operator chạy lại `lab.ps1 setup -Gateway -Transfer` trên Windows và
nhập password mới cho mỗi prompt SSH. Chỉ báo chuyển thành công khi có `COPIED:`;
chưa coi Gateway ready trước các bước cài đặt và verify. Nếu vẫn bị từ chối,
dừng ở lý do account/PAM tiếp theo, không reset lặp lại hoặc mở rộng SSH.

Không tự reset password, mở khóa account, bật password authentication toàn cục
hoặc bỏ các giới hạn của runner/audit. Bộ cài local vẫn hợp lệ; thay thông báo
client không làm đổi manifest bootstrap. Chỉ thử chuyển lại sau khi bước xác
thực được giải quyết, giữ nguyên việc từ chối thư mục đích đã tồn tại.

Thông báo mới phân biệt `directory_preparation` với `file_copy`, kèm mã thoát
và `command_failed`/`command_timeout`/`client_unavailable`. Mã thoát 255 riêng
lẻ không được gán thành lỗi password; OpenSSH vẫn trình bày nguyên nhân trực
tiếp cho operator. Client không lưu password, không thu raw stderr vào report,
không tự retry hoặc xóa phần chuyển dở.

### Nếu chuyển bộ cài báo Connection refused

Nếu SSH báo `banner exchange ... Connection refused`, chưa có xác nhận bước
tạo thư mục hay chép bộ cài thành công. Không kết luận sai mật khẩu hoặc tự
gửi lại job. Đối chiếu endpoint hiệu lực trước: client hiện dùng IP cố định
`192.168.217.10`, cổng `22` và `-F none`, bỏ cấu hình người dùng/hệ thống theo
[tài liệu OpenSSH](https://man.openbsd.org/ssh#F). Dùng `ssh -G` chỉ in cấu
hình hiệu lực, không kết nối.

Khi audit cũng không kết nối được, xem `host_vmware` của doctor trước; thường
không cần operator chép IP từ console nữa. Nếu metadata chưa đủ, operator có
thể xem ngay tại console REMnux bằng hai lệnh chỉ đọc:

```sh
ip -br -4 addr
ss -lnt 'sport = :22'
```

Đối chiếu IP thực tế và địa chỉ/cổng đang listen trước khi xem xét dịch vụ
SSH. Không tự sửa NIC, route, firewall hoặc khởi động lại dịch vụ để thử.
`lab.ps1 status` trả `ssh_unavailable` khi transport lỗi/timeout, và
`audit_response_invalid` khi đã nhận dữ liệu nhưng schema không hợp lệ;
không gán những trường hợp này thành worker đã chạy rồi thất bại. Kênh
doctor vẫn trả `lab_unreachable` nếu không nhận được chẩn đoán hợp lệ.

### Nếu `--check` dừng ở sudo policy

Thông báo mới chỉ rõ giai đoạn và mã lỗi, ví dụ
`NOT READY [preflight/sudo_policy_invalid]`. Bộ cài cũ chỉ in thông báo chung;
có thể chạy kiểm tra trực tiếp tại console REMnux để thấy nguyên nhân:

```sh
sudo /usr/sbin/visudo -c
```

Đây là chế độ chỉ kiểm tra cú pháp, ownership và permissions của sudoers theo
[tài liệu visudo](https://www.sudo.ws/docs/man/visudo.man/). Nếu đúng tệp
`/etc/sudoers.d/remnux` được báo `bad permissions, should be mode 0440`, operator
có thể sửa riêng quyền tệp đó rồi kiểm lại:

```sh
sudo chmod 0440 /etc/sudoers.d/remnux
sudo /usr/sbin/visudo -c
sudo sh setup_gateway.sh --check
```

Chỉ tiếp tục `--install --allow-synthetic` khi các kiểm tra đạt. Trường hợp sai
owner, lỗi cú pháp hoặc một tệp khác cần được xem xét theo đúng lỗi được báo;
installer không tự sửa sudo policy hoặc bỏ qua kiểm tra. Bản bộ cài đã chuyển
vẫn dùng được sau khi operator sửa quyền, không cần chép lại chỉ để đổi thông
báo chẩn đoán.

### Nếu preflight báo existing_privilege_or_session

Bộ cài cũ dùng cùng một mã khi `pgrep` tìm thấy tiến trình hoặc khi phép liệt
kê sudo cho runner/worker trả về thành công. Mã thoát `0` của lệnh liệt kê
không chứng minh tài khoản đích có quyền: sudo có thể in `User ... is not
allowed to run sudo on ...` rồi vẫn trả thành công khi root liệt kê quyền.
Lỗi này có thể làm preflight chặn nhầm tài khoản không có sudo. Không tự kill
tiến trình, sửa sudoers, đổi group hoặc bỏ qua gate để cài tiếp.

Nếu doctor không thể truy cập LAB hoặc helper mới chưa được cài, operator có
thể đọc PID ngay tại console:

```sh
sudo pgrep -u malpdf-runner,malpdf-worker
```

Không có output chỉ cho biết tại thời điểm kiểm tra không tìm thấy PID. Nếu
cần xem quyền sudo, operator kiểm riêng `sudo -n -l -U malpdf-runner` và
`sudo -n -l -U malpdf-worker` ở console; không gửi toàn bộ policy hoặc cấp thêm
quyền cho hai tài khoản này. Việc sửa quyền thực tế cần một thao tác quản trị
được review riêng.

Source mới phân biệt `runner_process_present`, `worker_process_present`,
`runner_sudo_listing_allowed`, `worker_sudo_listing_allowed` và trường hợp
không kiểm tra được. Nó cố định locale `C`, bỏ biến môi trường kế thừa và chỉ
chấp nhận đúng một dòng từ chối cho tài khoản đang kiểm tra, với mã thoát
`0` hoặc `1`, không có stderr và output tối đa 16 KiB. Chỉ mã `1`, output
rỗng, lỗi plugin, kết quả lạ, dòng thêm hoặc cảnh báo đều chưa đủ để qua gate.
Listing có quyền vẫn bị chặn để operator review. Cùng phép kiểm
layout/group/process/sudo chạy cả với tài khoản có sẵn lẫn ngay sau khi
tạo/khóa tài khoản mới, trước khi cài key.

Hành vi listing được đối chiếu với
[mã nguồn sudo display_privs](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/display.c#L499-L514)
và [sudoers_list](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/sudoers.c#L896-L904).
Nếu đang dùng bootstrap cũ `d101e4e...` hoặc `c482ac31...`, operator cần
chuyển bộ cài mới từ Windows theo quy trình phía trên rồi chạy `--check`
trong thư mục mới. Không chỉnh trực tiếp các tệp của bootstrap cũ vì manifest
sẽ không còn khớp. Sau khi `--check` đạt mới chạy installer tại console.

### Nếu cài đặt dừng ở installation/probe

`--check` đạt chỉ xác nhận điều kiện đầu vào. Nếu `--install` đã ghi helper và
báo lỗi, audit có thể trả `installed: true, verified: false`; trạng thái đó chưa
cho phép gửi job. Giữ backup và không chạy lại installer chỉ để lấy traceback.
Từ console REMnux, đọc trạng thái probe trước:

```sh
sudo systemctl status malpdf-gateway-probe.service --no-pager -l
```

Lệnh không khởi động lại service. Nếu probe chưa chạy, xem các bước kiểm SSHD
và unit trước đó thay vì kết luận lỗi containment. Source installer mới phân
biệt `sshd_config_invalid`, `sshd_policy_mismatch`, `systemd_unit_invalid`,
`containment_probe_failed`, `forced_command_probe_failed` và lỗi reload/timer.
Không bỏ kiểm tra, mở shell/forwarding hoặc giảm isolation để cài cho qua.

### SSH không khởi động vì PermitUserEnvironment trong Match

Bootstrap cũ, gồm bản `25302b72...`, có lỗi đặt `PermitUserEnvironment no`
trong `Match User malpdf-runner`. OpenSSH 9.6 chỉ cho phép tùy chọn này ở
global scope; xem [bảng keyword của OpenSSH](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c#L611).
Lỗi được operator xác nhận bằng `sudo /usr/sbin/sshd -t`, tại dòng 18 của
`/etc/ssh/sshd_config.d/00-malpdf-runner.conf`. Khi đó SSH không chạy nên
Codex không thể dùng chính SSH để sửa cấu hình.

Riêng khi đúng tệp/tùy chọn trên được báo lỗi, operator có thể phục hồi tại
console REMnux. Dòng đầu giữ bản sao tên có timestamp, rồi bỏ đúng dòng
`PermitUserEnvironment no` trong drop-in runner; dòng sau chỉ start dịch vụ
nếu kiểm tra cú pháp đạt:

```sh
sudo sed -i."$(date +%s%N)".bak '/^[[:space:]]*PermitUserEnvironment[[:space:]]\+no[[:space:]]*$/d' /etc/ssh/sshd_config.d/00-malpdf-runner.conf
sudo /usr/sbin/sshd -t && sudo systemctl start ssh
```

Không xóa drop-in hoặc các giới hạn forced command/forwarding. Nếu cú pháp
vẫn lỗi, giữ backup và xem đúng lỗi mới thay vì start lặp lại. Quyền phục hồi
quản trị cần operator hoặc ủy quyền cụ thể; luồng synthetic tự động không
tự mở SSH hay dùng Tools để chạy lệnh trong guest.

Bản sửa Windows bỏ keyword không hợp lệ khỏi `Match`, vẫn bắt buộc
`sshd -T -C user=malpdf-runner,...` trả `permituserenvironment no` cùng các
giới hạn khác. Không tự đổi tùy chọn toàn cục của các tài khoản khác. Preflight
kiểm cấu hình SSH hiện hành trước khi ghi cài đặt; chỉ áp drop-in mới ở giai
đoạn kiểm SSHD. Tệp được thay nguyên tử. Nếu syntax/policy của candidate
không đạt, installer giữ `sshd.rejected` và phục hồi nội dung/mode/group cũ
hoặc bỏ đúng candidate mới khi trước đó không có drop-in. Bản rejected và
backup cũ được giữ, không xóa job/report. Nếu tệp bị operator sửa đồng thời
hoặc restore không thành công, dừng với `sshd_restore_failed` để review,
không ghi đè thay đổi lạ. Đây là phục hồi riêng SSHD, không phải rollback
nguyên tử cho toàn bộ quá trình cài đặt.

Ngay trước `systemctl reload ssh`, installer kiểm lại nội dung candidate,
chạy lại `sshd -t` và `sshd -T -C ...`, rồi xác nhận candidate vẫn khớp trước
khi reload. Policy bắt buộc cả `permituserenvironment no` và `maxsessions 1`.
Nếu kiểm tra lại hoặc reload lỗi, nó dùng cùng cơ chế phục hồi tệp cũ và giữ
candidate bị từ chối trong backup. Một cấu hình đã qua probe trước đó chưa
đủ để bỏ qua bước kiểm tra sát thời điểm kích hoạt. Nếu operator đã sửa tệp
trong thời gian chờ, installer dừng và giữ nguyên thay đổi đó.

Không cài lại các bootstrap cũ còn chứa dòng lỗi; dùng manifest mới đã review
sau khi phục hồi SSH.

## Sau cài đặt

```powershell
.\lab.ps1 verify
.\lab.ps1 doctor
.\lab.ps1 test -Mode syntax
.\lab.ps1 test -Mode synthetic
.\lab.ps1 report
```

Để review source snapshot từ worktree đang có thay đổi mà chưa gửi LAB:

```powershell
.\lab.ps1 prepare -Gateway
```

Lệnh dùng lại snapshot/content guard hiện có, tạo archive và manifest có hash
trong cache local; không stage/commit, không SSH và không yêu cầu Gateway ready.
`prepare` không có `-Gateway` vẫn giữ cơ chế commit sạch cũ. CLI Python trực
tiếp cũng hoạt động: `python -B scripts/lab/gateway_client.py doctor`.

Codex được phép gọi các lệnh này theo standing authorization trong AGENTS.md.
`verify` còn kiểm từ Windows rằng shell, subsystem, PDF/đối số lạ và forwarding
bị từ chối. Phép thử forwarding chỉ nhắm `127.0.0.1:22` ở LAB; không chuyển tiếp
tới dịch vụ Windows. Không gửi source khi bất kỳ phép thử nào chưa đạt. Không
có fallback sang mật khẩu/tài khoản `remnux`.

`test` chạy kiểm tra local rồi snapshot allowlist source, không stage/commit hay
đụng tới thay đổi khác của người dùng. Base commit, hash manifest/archive,
profile và policy ghim được buộc vào job ID. Cùng snapshot/profile/policy chỉ có
một job; khi SSH mất kết nối, client giữ receipt và chỉ đọc status, không tự gửi
lại một job có thể đã chạy. Job đã claim không được chạy lại kể cả sau crash.

`report` chỉ đọc cache Windows; `report -Refresh` nhận JSON tối đa 16KiB từ audit
forced command `report-job <64-hex>`. Không chuyển raw stdout/stderr, traceback,
source/PDF bytes hoặc arbitrary fields. Snapshot source giữ ở slot riêng theo
hash manifest, không ghi đè slot cũ. Gateway giới hạn 32 snapshot/64 job và kiểm
free disk; hết quota thì cần operator review retention, không tự xóa evidence.

## Probe thất bại trong containment

`ProtectHome=yes` làm `/home`, `/root`, `/run/user` không truy cập được và rỗng
trong namespace worker; nó không đòi hỏi các mount point phải biến mất. Xem
[systemd.exec: ProtectHome](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ProtectHome=).
Verifier cũ dùng `Path.exists()` với `/root`, nên placeholder được systemd tạo
có thể làm probe từ chối dù cơ chế che chắn đang hoạt động.

Verifier hiện thử mở đọc đúng các đường dẫn host bị cấm bằng cờ nonblocking,
no-follow và close-on-exec. Chỉ `ENOENT`, `EACCES`, `EPERM` được xem là bị che;
mọi đường dẫn mở đọc được đều đóng ngay và làm probe thất bại, không đọc nội
dung. Lỗi I/O, symlink và trạng thái không xác định cũng từ chối. Không tắt
ProtectHome, RootDirectory, network isolation hay bất kỳ giới hạn systemd nào
để sửa lỗi này.

Probe kiểm cả soft/hard RLIMIT hữu hạn cho RAM, CPU, FD, process và output;
core dump phải bằng 0. Nó kiểm riêng cgroup memory/swap/tasks/CPU, đọc giá trị
kernel có trần byte thay vì dựa vào kích thước metadata của pseudo-file. Socket
INET/INET6 vẫn phải bị từ chối và source vẫn phải từ chối tạo file. Giá trị
unlimited/âm, memory/tasks bằng 0 và mọi giới hạn quá trần đều làm thất bại.

Report chỉ bổ sung các reason cố định cho UID, host-path access, RLIMIT,
cgroup memory/swap/tasks/CPU/unavailable, network hoặc source. Không trả số UID,
đường dẫn, kernel text, traceback hay raw output. Doctor ưu tiên lỗi cài/probe
đã biết so với `proof_mismatch` do installer cố ý thu hồi proof khi thất bại.
Reason chi tiết của probe chỉ được dùng cho checkpoint cài tương ứng khi policy
hash khớp. Các schema/reason cũ vẫn được đọc, nhưng không được suy thành pass.

Sau sửa helper, tạo và chuyển bootstrap có manifest mới theo luồng operator,
rồi chạy lại check/install tại console. Giữ backup của lượt lỗi và các report/
claim/release cũ. Chỉ sau native probe và client verify đạt mới cho phép gửi job.

Nếu systemd báo `result=signal`, `exit_code=2`, `exit_status=31` trên REMnux
x86-64, tiến trình đã bị `SIGSYS` trước khi ghi report mới. Không dùng record
probe cũ để kết luận lỗi hiện tại; doctor báo `containment_probe_signalled`
cho probe cài đặt bị signal, kể cả khi proof đã bị thu hồi.

Probe chủ động thử tạo socket INET/INET6 và yêu cầu lỗi từ chối. Bộ lọc syscall
của cả probe và worker dùng `@network-io:EPERM`: toàn bộ nhóm network I/O vẫn
bị chặn, trả lỗi `EPERM` để probe kiểm được kết quả và ghi metadata đã lọc.
Các nhóm mount/privileged/debug/raw-io/reboot/swap giữ hành vi kết thúc tiến
trình; không đặt `SystemCallErrorNumber` toàn cục. `PrivateNetwork=yes`, giới
hạn address families, filesystem và resource caps tiếp tục được áp dụng.
Cú pháp errno theo nhóm và mặc định `SIGSYS` được mô tả trong
[systemd.exec](https://www.freedesktop.org/software/systemd/man/256/systemd.exec.html#SystemCallFilter=).

Khi timer đã chạy, `LastTriggerUSecMonotonic` trong `systemctl show` có thể là
timespan như `2h 17min 4.123456s`, thay vì số microsecond thuần. Doctor kiểm
chuỗi có trần, đơn vị cố định và đúng thứ tự; chỉ xuất boolean
`timer_triggered`. Đơn vị lạ, giá trị âm/unlimited, overflow, thành phần lặp,
fraction nhỏ hơn microsecond và ký tự không hợp lệ đều bị từ chối. Timestamp
start/exit vẫn chỉ nhận uint64 microsecond. Quy tắc hiển thị theo tên property
được xác định trong
[systemd v255 bus printer](https://github.com/systemd/systemd/blob/v255/src/shared/bus-print-properties.c).
Sửa formatter đã pin cần bootstrap mới do operator cài, kể cả khi job vẫn chạy
đạt với formatter cũ.

Các test workflow dùng cache tạm riêng cho cả legacy và gateway, đồng thời
chặn audit/runner transport chưa được mock. Cache thật từ job đầu tiên không
được tác động đến kết quả test cục bộ. `report -Mode offline` luôn bỏ qua cache
gateway và không refresh qua SSH. Nếu kiểm tra Windows thất bại, lệnh test báo
`local_checks_failed`, chỉ tới receipt cục bộ và không yêu cầu cài lại gateway.

## Profile và containment

- Syntax: AST parse có giới hạn, không import hay chạy code của release.
- Synthetic: syntax trước, sau đó đúng 6 ca lexer số nguyên, reference, tên,
  string, boolean và depth limit. Harness root-owned nằm ngoài source gửi lên,
  chỉ nạp hai module lexer/execution với input inert; không chạy test từ release.
- Worker UID riêng, root filesystem tối giản chỉ bind `/usr`, source chỉ đọc và
  các đường dẫn gateway cần thiết. Không bind `/home`, dataset, credential hoặc
  socket của host. Runtime/system dependencies phải có trong `/usr`; không dùng
  venv của tài khoản `remnux`. Operator phải giữ corpus/credential ngoài cây hệ
  thống `/usr` và vùng gateway.
- systemd namespace chặn mạng host/Windows, syscall mạng/mount/privilege bị hạn
  chế; giới hạn 512MiB, 60s CPU, 90s/job, 32 task, 64 FD, output 1MiB. Một lần
  nhận source giữ khóa loại trừ; không có parallel parser không giới hạn.
- Mỗi worker kiểm lại UID, socket denial, source read-only, host paths ẩn,
  RLIMIT và trần kernel cgroup v2 (RAM/swap/CPU/process) trước khi đọc job. Chỉ
  cgroup riêng của unit được bind chỉ đọc vào runtime. Các pin config/helper/unit/SSHD phải khớp operator
  proof; thay mã bảo mật hoặc harness cần cập nhật bootstrap có review riêng.

Các thiết lập dựa trên [tài liệu systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
và [SSHD ForceCommand/DisableForwarding](https://man.openbsd.org/sshd_config.5).
Đây là containment theo cấu hình và negative probes, không phải remote
attestation hay bảo đảm chống mọi lỗ hổng kernel/SSH/parser. Report vẫn là dữ
liệu không tin cậy, được kiểm schema hai phía.

PDF thật, feature export từ malware, offline runner/detonation, thay adapter,
phục hồi VM và cài đặt hệ thống tiếp tục cần workflow duyệt riêng. 6 ca lexer
không chứng minh độ chính xác, độ phủ toàn diện hay tính an toàn của PDF thật.
