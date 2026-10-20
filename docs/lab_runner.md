# Dùng LAB Runner

Windows là nơi sửa mã. REMnux là nơi chạy công việc đã duyệt. Hai giao diện đã
được triển khai trong source; việc cài chúng lên VM cần operator duyệt một lần.

## Dùng hằng ngày trên Windows

```powershell
.\lab.ps1 status
.\lab.ps1 prepare
.\lab.ps1 test
.\lab.ps1 report
```

`test` chạy từ terminal Windows riêng của operator. Script kiểm tra Git, nguồn,
dependency Windows và gói đã commit; đọc readiness qua khóa audit; hiển thị
commit/job/tác vụ/giới hạn rồi hỏi **một lần duyệt cả công việc**. Operator chỉ
nhập `y` và xác thực bằng Windows OpenSSH nếu được yêu cầu. Không nhập SHA hoặc
lệnh SSH dài. Không đưa mật khẩu quản trị cho Codex.

Một kết nối quản trị gửi gói nguồn có giới hạn, receiver kiểm tra lại network,
Python/Git, manifest và từng hash trước khi nhận release. Sau đó chạy AST và
self-test synthetic đã rà soát, lưu báo cáo theo job ID và trả JSON đã lọc.
Mọi source/runtime check thất bại đều dừng. Không tự cài package hoặc sửa mạng.
Các helper cài trên LAB phải khớp hash của helper trong source release; nếu đổi
chính sách/helper thì cập nhật bootstrap có duyệt trước. Thay extractor thông
thường không đòi cài lại helper. Dry-check dùng Python `-B` để không làm bẩn
bootstrap bằng bytecode cache và vẫn kiểm được lại cùng manifest.
Dependency của AST/synthetic là Python3.11–3.13, Git và thư viện chuẩn; đây không
phải xác nhận đầy đủ stack parser/ML của LAB.

`prepare` yêu cầu commit sạch. Codex tiếp tục sửa/test trên Windows; commit vẫn
cần được duyệt. `report` mặc định đọc bản đã lưu trên Windows, không mở SSH.
Với **job Host-only**, `report -Refresh` lấy lại đúng job sau mất kết nối. Khi
mất SSH, không tự submit lại; job có claim không được chạy lại ngầm.

Chế độ A chỉ chấp nhận guest IPv4 `192.168.217.10/24`, một adapter hoạt động,
route Host-only/loopback, không gateway/default route/IPv6 global hoặc shared
mount. Host-only vẫn tiếp xúc với Windows; kiểm tra này không thay firewall,
cấu hình VMware, kiểm tra clipboard của operator hay chứng minh containment.

## Chuẩn bị rồi chạy khi ngắt toàn bộ mạng

Khi còn kết nối, chọn một tác vụ:

```powershell
.\lab.ps1 test -Mode offline -Kind syntax
.\lab.ps1 test -Mode offline -Kind synthetic
```

Lệnh chỉ chuẩn bị release và job, không chạy job offline. Sau khi operator
ngắt mọi NIC và xác minh snapshot/shared folders/clipboard/drag-drop/credentials,
trên console REMnux dùng:

```sh
lab status
lab run
lab report
lab menu
```

Chạy các lệnh này bằng tài khoản phân tích thường, không dùng `sudo lab run`.

Hoặc mở **MalPDF LAB Runner** trong menu ứng dụng/Desktop. Nếu chỉ có một job,
runner tự chọn nó; nếu có nhiều job, chọn bằng số. Xác nhận console một lần,
không gõ hash hoặc đường dẫn. Guest networking, SSH session, shared mounts,
release và resource được kiểm tra lại. Hypervisor controls là xác nhận của
operator, không được trình bày như quan sát tự động từ guest.

Kết quả offline giữ trong LAB. `report -Refresh` trên Windows bị chặn cho mọi
job offline. Không tự kết nối lại VM; xuất dữ liệu sau phân tích cần quy trình
review/recovery riêng.

## PDF thật: phê duyệt riêng

Chỉ khi đã duyệt cohort, môi trường và isolation mới chọn:

```powershell
.\lab.ps1 test -Mode offline -Kind pdf-static
```

Lần duyệt này nói rõ **64 CIC:32 Train/32 Validation, seed42, không Test**,
theo ba manifest checksum trong `configs/cic_static_benchmark.yaml` của release.
LAB kiểm tra đầy đủ dependency đã khai báo và chuẩn bị selection chỉ bằng
metadata, không đọc PDF. Các CSV, model Arlington và môi trường đã có phải
khớp; không tải hoặc thay dataset để vượt lỗi. `setup` không tự cài dependencies.

Sau đó `lab run` khi thực sự offline sẽ kiểm tra lại selection, nguồn, model
Arlington, credentials và tài nguyên, rồi mới đọc PDF. Một worker,10MiB/file,
20s wall/12s CPU/1GiB address space mỗi parser; lượt tối đa30phút,512MiB bundle
riêng tư,8MiB/file và không renderer/JS runtime/Reader/CAPE. Worker riêng áp
giới hạn CPU/RAM/file/FD/process trước khi import stack parser. Không ghi raw
blobs và không fit model. Một worker không dọn sạch sẽ dừng phần còn lại.

Giới hạn process theo UID dùng chung với các ứng dụng khác; thiếu tài nguyên
thì dừng. Chạy ở tài khoản/môi trường đã rà soát, không tăng trần ngầm để vượt
lỗi. Report giữ số mẫu dự kiến, hoàn thành, partial/lỗi và primary checkpoint;
không suy độ chính xác hay độ phủ toàn diện từ số đếm. Các bundle riêng tư ở
`/var/lib/malpdf/jobs/<job_id>/private_bundles/` không được tự chuyển ra Windows.

## Cài một lần, theo một đợt duyệt

Sau khi review và commit source mới:

```powershell
.\lab.ps1 setup
```

Lệnh này chỉ chuẩn bị bootstrap **11 tệp** trên Windows. Operator duyệt manifest
và chuyển đúng thư mục bootstrap theo kênh quản trị riêng đã được phép. Không
dùng Shared Folders/clipboard để vận hành phiên offline. Từ thư mục bootstrap
tại console REMnux, hai lệnh ngắn là:

```sh
sudo sh setup_runner.sh --check
sudo sh setup_runner.sh --install
```

`--check` chỉ kiểm tra. `--install` kiểm checksum tự động, cài helper root-owned,
`/usr/local/bin/lab`, `/etc/malpdf/runner.json`, private jobs và shortcut; gọi lại
bộ cài audit hiện có để giữ forced-command chỉ đọc và kiểm SSHD trước reload.
Nó không sửa adapter, route, firewall, dataset hoặc cài dependencies.

Mặc định data root là `/home/remnux/MalPDFDeepDetection`, Python lấy `.venv/bin/python`
nếu có, nếu thiếu dùng `/usr/bin/python3` cho tác vụ stdlib. Các giá trị phải
được operator kiểm tra tại setup; PDF sẽ bị chặn nếu môi trường không khớp.
Không suy rằng dependency trên Windows cũng đã có trong VM.

Source cũ và runtime đang dùng không bị đổi. Root helpers/config có backup ở
`/var/tmp/malpdf-runner-setup.*`; SSHD/account có backup riêng từ installer audit.
Rollback ở console: chọn lại release cũ; nếu cần khôi phục helper/config/CLI từ
backup, kiểm tra SSHD bằng `sshd -t` trước reload. Không xóa report/job/claim hoặc
reset một lượt đã chạy. Cài đặt nhiều tệp không phải giao dịch rollback tự động;
lỗi giữa chừng cần operator kiểm tra backup.

## Khi có lỗi

| Mã ngắn | Xử lý |
| --- | --- |
| `source_dirty` | Review/commit thay đổi trên Windows, không bỏ qua gate |
| `setup_required` | Review/cài bootstrap mới một lần; endpoint audit cũ vẫn chỉ đọc |
| `network_blocked` | Kiểm tra đúng mode, route, NIC và shared mounts ở console; script không sửa chúng |
| `release_mismatch` | Kiểm lại source/manifest; không ghi đè release cũ |
| `manifest_unavailable` | Chuẩn bị metadata/job trước khi ngắt mạng; không thay bằng cohort khác |
| `dependency_mismatch` | Review môi trường LAB đã có; cài package là tác vụ riêng được duyệt |
| `credential_present` | Dùng LAB đã rà soát không có credential; không tự xóa key/token |
| `already_claimed` | Xem báo cáo/diagnostic tại LAB; không tự retry hoặc xóa claim |
| `export_requires_review` | Giữ kết quả offline tại LAB, dùng quy trình export/recovery riêng |

Prompt/TTY không phải access-control. Giữ credential quản trị và phiên operator
ngoài quyền điều khiển Codex; report có schema không phải attestation của VM.
