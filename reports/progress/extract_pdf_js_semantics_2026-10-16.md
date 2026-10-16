# Ngữ nghĩa JS/XFA tĩnh, 2026-10-16

Đã tích hợp một tầng phân tích AST tĩnh có giới hạn vào deep-static: chuẩn hóa
scope/binding, suy luận scalar hữu hạn/unknown và đồ thị lời gọi có nguồn. Chỉ
kiểm thử script/PDF tổng hợp lành tính. Không gọi hàm JavaScript, builtin,
getter, eval body, Acrobat DOM; không render hoặc chạy PDF thật. Kế hoạch sáu
giai đoạn vẫn mở.

Run ID dùng UTC; ngày báo cáo theo UTC+7. Commit sinh mã:
`7d02abdb85da108b64c92b51dfe10ddb02858cd3`; worktree dirty, giữ thay đổi có sẵn.
Maintenance ID: `run_20261015T134933947462Z_7d02abdb85da`.

## Thay đổi và hợp đồng

- [js_abstract.py](../../src/malpdf/static/js_abstract.py): domain tối đa4 giá
  trị scalar/function/name-path hoặc Top. Ghép chuỗi, toán tử số nguyên an toàn,
  strict comparison và primitive unary transfers; không đoán coercion/precision.
  Chuỗi có cùng dãy UTF16, kể cả surrogate pair tường minh, có cùng giá trị;
  không chuẩn hóa Unicode NFC. Độ dài chuỗi tính bằng UTF16 code units.
- [js_semantics.py](../../src/malpdf/static/js_semantics.py): prepass scope và
  binding, function var hoisting, block lexical/TDZ, alpha fingerprint, branch
  joins/short circuit và widening vòng lặp. Không lặp cụ thể hay gọi hàm.
  Getter, free/host state, opaque call và coercion chưa biết làm unknown trạng
  thái có thể bị tác động, kể cả compound/update. Primitive const có thể giữ hằng.
- [script_semantics.py](../../src/malpdf/extraction/script_semantics.py): observer
  worker giữ cây đã parse/kiểm tra, dedup bằng decoded UTF8 SHA; không parse AST
  hay decode PDF thêm. Nhánh chạy sau checkpoint primary/filter/carver/native/
  raw/Arlington với CPU/RAM/wall dùng chung. Từng script hoàn thành có checkpoint
  riêng; timeout giữ kết quả trước đó và primary. Chưa có semantic facts nếu
  bị ngắt trước khi script đầu kết thúc.

Summary/code/v8 và đặc trưng chính giữ nguyên. Mỗi fact/call/binding có range
trong script đã giải mã và liên kết tới evidence giữ cùng decoded hash. Range
là code point của Esprima-Python, không phải byte offset PDF. Key/tên biến,
literal, URL và nội dung mẫu không được xuất plaintext. PDF con giữ node nguồn
riêng; repaired/mixed original–MuPDF provenance được giữ, không đổi thành bằng
chứng authored. Không xuất fact từ cây không tìm được source metadata tương ứng.

Graph có caller → callsite → API hoặc hàm cục bộ, phân biệt spelling cú pháp,
conditional target, unvisited, excluded và uninvoked function body. Function
bodies được phân tích riêng với input/outer state unknown; không được gọi, không
truyền return value cho caller. Call `eval`, `unescape`, `atob`, `Function`,
`String.fromCharCode` chỉ tạo metadata, không thực thi hay parse generated code.
Hai fixture cùng có JavaScript vẫn giữ `/OpenAction` và `/AA/WC` cùng API khác nhau;
các trigger chỉ là kế hoạch not_run.

Alpha digest là đặc trưng cấu trúc có chuẩn hóa biến trong mô hình lexical,
không chứng minh tương đương hành vi hay file identity. Reflection/global
properties/shared scripts/Annex B còn unknown; không dùng digest để thay split
hoặc nhóm dữ liệu. Đây chưa phải đầy đủ SAFE-PDF, DOM hay JS emulator.

## Giới hạn và kiểm thử

Mặc định: capture trong64 scripts/20000 AST nodes/4MiB decoded source đã được
parse bởi pipeline cũ; supplementary budget dùng chung128 scopes,512 bindings,
1024 facts/calls,40000 bước,depth100,2048 UTF16 units mỗi hằng và512KiB compact
ASCII JSON metadata. Không cấp lại parser/decoder hay CPU/RAM/wall allowance.

Metadata ledger và guard serialization cuối giữ output có giới hạn; nếu có
growth ngoài ledger, quay về checkpoint hợp lệ gần nhất, báo partial/lower bound.
Stress tổng hợp trước sửa tạo10790 byte với trần8192; test guard cuối chứng minh
checkpoint không vượt trần. `finish` lặp lại không được resume quota hoặc biến
partial thành success. Những bộ đếm bị ngắt không phải allowance có thể tái dùng.

**77 ca JS riêng** và suite cuối **1409 passed**, hai cảnh báo sklearn
single-label đã có,159.21s. `pip check` không có dependency hỏng;
`git diff --check` qua. Log:
`artifacts/tmp/maintenance/extract_pdf/js_semantics_release_pytest.log`.
Giữ các log qua trung gian1404/1406; sau đó bổ sung guard/UTF16/coercion và kiểm
chứng lại mã cuối. Không dùng kết quả suite cũ thay cho các ca mới.

Các ca chính: alpha/scoping/shadowing, unknown và finite-set, số nguyên/signed
zero/coercion, UTF16 và surrogate concatenation, branch/loop, target alias,
caller/API graph, mọi callsite sau call đầu, XFA/PDF con, mixed provenance,
serialization/cross-store refs, parity primary/code/v8 và timeout/cleanup.

Ba bundle evidence cuối được giữ riêng dưới domain maintenance:

| Fixture | AST nodes được capture | Script khớp nguồn | Calls | API candidate |
| --- | ---: | ---: | ---: | --- |
| PDF gốc tự sinh | 13 | 1 | 1 | app.launchURL |
| XFA tự sinh | 13 | 1 | 1 | util.printf |
| PDF con tự sinh | 11 | 1 | 1 | app.launchURL |

Các tệp `artifacts/tmp/maintenance/extract_pdf/js_semantics_release_fixture_{root,xfa,child}.json`
đã qua deserialize/validate. Mọi source/edge/feature reference hợp lệ trong
phạm vi fixture; extra AST parses=0, functions invoked=false. Từng worker đo
được wall20s, CPU soft/hard12s, address space1GiB, process group riêng và cleanup
thành công. Các cap/process không chứng minh LAB đã cô lập.

Python3.11.17; pikepdf10.17.0/QPDF12.4.2,
PyMuPDF1.26.7/MuPDF1.26.12, pypdf6.18.1, esprima4.0.1;
torch2.11.0+cpu/torchvision0.26.0+cpu, CUDA build=None. Reuse venv đã được cài
mới ở lượt native-parser; không thêm dependency hoặc tuyên bố fresh install
mới/đồng nhất với Kaggle. Phiên bản và fingerprint đầy đủ nằm trong evidence.

## Job và provenance dữ liệu

Job metadata cuối:
[run_20261015T174826506117Z_7d02abdb85da](../experiments/pdf_extraction_prepare/run_20261015T174826506117Z_7d02abdb85da/run_summary.json).
Khóa212 tệp nguồn/cấu hình, môi trường/caps và Arlington đã chốt610 TSV. Dùng
đúng cùng64 bản ghi như job Arlington trước: 32 Train và32 Validation đã lộ,
16 mỗi lớp/partition, seed42. Không chia lại split, không chọn Test, không đọc
byte PDF thật. Các source fingerprint cũ được kiểm tra từ chối.

Đường dẫn/hash manifest giữ nguyên, được lưu trong locked methodology và checks:

- `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv`:
  `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643`.
- `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv`:
  `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b`.
- `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv`:
  `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f`.

Lệnh tái lập không cần PDF thật:

```bash
.venv/bin/python -m pytest tests/test_js_semantics.py
.venv/bin/python -m pytest tests/
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T174826506117Z_7d02abdb85da
```

Evidence bàn giao: `artifacts/tmp/maintenance/extract_pdf/js_semantics_release_checks.json`
và `js_semantics_preservation_checks.json`; research log được append riêng.
Giữ122 tệp baseline ngoài phạm vi sửa và prefix research log; không staging/
commit, không đưa PDF/binary/model artifacts ra ngoài ignore. Scratch kiểm thử
được dọn sau khi giữ ba bundle JSON tổng hợp.

PDF thật/21 partial, full interprocedural/heap/reflection/global-script semantics,
media/byte-image/visual, reingestion, export/plugin/release và các tầng động vẫn
còn mở theo [acceptance](../../plans/extract-pdf/acceptance.md). LAB cần console
kiểm tra NIC/sharing/clipboard/credentials; không tự ngắt SSH. Render/JS runtime/
Reader/CAPE chưa được duyệt. Không có classifier fitting, Test inference hay
tuyên bố tăng detection/coverage corpus. Label=1 malicious; ECE10 bin xác suất
bằng nhau, p=1 ở bin cuối. F1/MCC/ECE/Brier N/A vì chỉ maintenance/synthetic checks.
