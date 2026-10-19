# Lượt thử PDF thật: đề xuất duyệt ngày 2026-10-19

Test fixture đã có chỉ chứng minh các trường hợp tổng hợp. Đánh giá độ phủ,
tỷ lệ lỗi và bảo toàn đặc trưng chính cần chạy PDF thật trong REMnux.
Tài liệu này là đề xuất thực hiện; chưa có lượt PDF thật mới.

## Trạng thái đã kiểm tra từ Windows

- `scripts/lab/labctl.py status` trả về schema1, role `malpdf-audit`, connection
  `read-only-command-gate`. Đây không phải kiểm chứng isolation hay dependencies.
- Khóa audit chỉ nhận `status` và `report <SHA>`; không có quyền chạy extractor,
  đọc corpus tùy ý hoặc deploy. Không mở rộng khóa này để chạy thử.
- Mã extractor hiện còn ở working tree. Gói của commit
  `5222a287af896ae5320037850790036e5abf998b` không chứa các cải tiến chưa commit.
- Ba CSV được chỉ định trong `configs/cic_static_benchmark.yaml` không tồn tại
  tại Windows. Không đọc PDF, không suy rằng chúng cũng thiếu trên REMnux.
- Các tài liệu cũ có đường dẫn Lubuntu/user khác. Không dùng chúng làm bằng
  chứng về VM REMnux hiện tại hoặc tái sử dụng job/claim đã tiêu thụ.

## Phạm vi đề nghị cho lượt đầu

| Hạng mục | Phạm vi |
| --- | --- |
| Môi trường | REMnux, tài khoản không phải root, chạy từ VMware console |
| Đầu vào | 32 Train và32 Validation CIC theo phép chọn seed42 đã có; chỉ sau khi xác minh ba manifest bên dưới |
| Mã | Baseline và candidate nhận diện riêng bằng full commit SHA/manifest nguồn; không thay nguồn đã cài hoặc dữ liệu cũ |
| Phân tích | `deep-static`, không render, thực thi JavaScript, Reader hay CAPE |
| Tài nguyên | Một worker, tối đa10MiB/file,20s wall/12s CPU/1GiB address space mỗi file |
| Giới hạn lượt | Tối đa64 mẫu; tổng wall tối đa30phút, output quota được chốt sau preflight dung lượng; dừng nếu worker không được dọn sạch |
| Đầu ra riêng tư | Thư mục mới trong LAB; không ghi đè bundle/blob/claim hay run trước |
| Xuất về Windows | Chỉ bảng tổng hợp/schema được duyệt: số mẫu, trạng thái/lỗi cố định, độ phủ, primary parity, median/P99/RSS; không PDF/blob/code/raw log/tên mẫu |
| Khôi phục | Snapshot và nguồn cũ giữ nguyên; khi lỗi dừng tiến trình của lượt, giữ bằng chứng, không tự retry/reset claim/đổi mạng |

Ba manifest kỳ vọng từ cấu hình hiện tại:

| Tên | SHA-256 |
| --- | --- |
| split_manifest | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| source_manifest | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| normalization_manifest | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

Đây là identity kỳ vọng, chưa được xác nhận trên REMnux trong lượt này. Không
thay manifest, tự tìm corpus khác, chọn Test hay tải dữ liệu để vượt qua lỗi.

## Trình tự cần thực hiện

1. Duyệt đúng diff extractor và manifest hash của working tree đã kiểm tra;
   cho phép commit riêng, không push. Đóng gói source của full SHA mới bằng
   `labctl.py prepare --commit <SHA>`; review manifest trước khi chuyển.
2. Operator thực hiện deployment từ phiên quản trị riêng theo
   [Windows–LAB workflow](windows_lab_workflow.md). Codex không gọi hay cung cấp
   input cho `deploy`. Không cài dependencies hoặc đổi bootstrap/SSHD trong
   lượt PDF nếu chưa có duyệt riêng.
3. Operator kiểm tra metadata tại console: VM/root repository thực tế, phiên bản
   Python/parser, vị trí môi trường, hash ba CSV, subset64, baseline có thể so
   sánh, dung lượng và địa điểm output mới. Không đọc PDF ở bước preflight.
   Xác minh source release và data root riêng; không giả định release có `.git`,
   dataset, Arlington checkout hay môi trường của repository cũ.
4. Chốt chính xác lệnh chạy với các đường dẫn/identity đã xác minh. Trước PDF
   đầu tiên, kiểm tra snapshot/recovery, adapter/routes, shared folders,
   clipboard/drag-drop và credentials. Operator ngắt các NIC theo quy trình
   đã duyệt và chạy từ console; không đổi isolation từ SSH. Biến môi trường
   xác nhận không thay thế các kiểm tra này.
5. Chạy lượt hữu hạn đã duyệt. Giữ mọi thất bại trong mẫu số và primary checkpoint;
   so candidate với baseline trên đúng cùng identity và budget. Chỉ sau khi
   review output schema mới cho phép trả số liệu tổng hợp về Windows.

Lệnh thực thi PDF và output quota còn chờ preflight thực tế; đề xuất này không
ủy quyền chạy corpus hoặc thực thi lệnh tùy ý qua khóa audit. Không dùng lệnh
`vm` không giới hạn cho lượt thử trên. Chưa tuyên bố extractor vượt trội.

## Căn cứ cần phần thao tác của operator

[AGENTS.md](../AGENTS.md) mục4 quy định: “Codex must not call, script, approve,
or supply input to this operation” đối với `labctl.py deploy`. Mục3 yêu cầu
kiểm tra VM/isolation, manifest/output, resource/time bounds và recovery cho
mỗi lượt mẫu thật. Vì vậy approval commit/đóng gói và bước console phải được
chốt trước; quyền audit hiện có không thể thay phần thao tác này.
