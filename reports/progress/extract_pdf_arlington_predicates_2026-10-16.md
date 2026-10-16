# Predicate bitmask Arlington và Contains tĩnh, 2026-10-16

Maintenance `run_20261016T153451981141Z_a0d008e252ea`; generating revision `a0d008e252ea8ec9d470453316583a1a8e9f6d4b`, dirty during build.
Final HEAD/clean gate: `artifacts/tmp/maintenance/extract_pdf/predicate_final_checks.json`.

## Thay đổi gắn với giai đoạn3

Bổ sung BitClear,BitSet,BitsClear,BitsSet cho đúng trường hiện tại trong type
branch bitmask. Context được tạo riêng theo key/branch, giữ tham chiếu gốc và
resolve qua cache IR/xref đã kiểm; không parse/decode thêm PDF. Vị trí bit1–32,
range inclusive/phải tăng và đúng arity. Sai đối số model hoặc context chưa biết
vẫn Unknown kể cả dưới NOT. Missing/duplicate/unverified reference không trở thành
pass/fail giả. Integer32 signed two's-complement và unsigned được xem qua32 bit;
không đổi giá trị gốc, không truncate integer lớn hoặc làm tròn real/bool. Integer
ngoài phạm vi[-2^31,2^32-1] vi phạm assertion32-bit. Inheritance giữ source owner.

Contains sửa từ chỉ mảng sang typed scalar hoặc mảng theo grammar; phân biệt
name/string/Boolean/number, giữ Unknown khi thiếu context/member và tính từng
phần tử mảng vào budget expression hiện có. Không áp dụng logic Python truthiness
cho Unknown. Không thay primary/IR/model/split hoặc nâng CPU/RAM/byte/check caps.

Nguồn: [INTERNAL_GRAMMAR của commit đã khóa](https://github.com/pdf-association/arlington-pdf-model/blob/b7d880b7a3d3c8f505c025f17763397475e90503/INTERNAL_GRAMMAR.md),
local Git blob`a4a00fd72fe3c1469dff36d78e1951d9ed3f6998` khớp cây commit;
SHA256`81c0bec3e07aadff7e781cae8888fe3c07eb91903e0f2ca0f88c455fcb3c236f`. Web commit/raw cache không sẵn; Git text local
đã xác minh là nguồn ngữ nghĩa. Không tải thêm datasets. Các4 hàm bit có174 call
sites trong model (BitClear12/BitSet5/BitsClear154/BitsSet3); đây là số lần xuất
hiện, không phải174 rules/context hoặc PDF đã được xác minh. Contains có9 calls.
Các context Extension,FileSize,ArraySortAscending,IsHexString,tree/font/page
và conditional logic chưa hỗ trợ vẫn indeterminate/unsupported như trước.

## Kiểm chứng

**1810 passed**, 2 cảnh báo sklearn single-label đã có,191.01s;
`artifacts/tmp/maintenance/extract_pdf/predicate_full.log`.
Targeted **143 passed/3.71s**,54 ca mới (`predicate_unit.log`). Kiểm các32 vị trí
bit bằng reference string độc lập, signed/unsigned boundaries/ranges, invalid
arity/arguments, missing/wrong context, budget exhaustion, key/type isolation,
reference/inheritance/duplicate và export source IDs/IR parity. Contains kiểm
scalar/mảng, typed equality, Unknown dưới NOT và chi phí từng phần tử.

Model thật **`b7d880b7a3d3c8f505c025f17763397475e90503`**, **610 TSV/3976 rows**,
LICENSE/NOTICE và checksum đúng. Smoke **`run_20261016T152924679939Z_a0d008e252ea`**
([verification](../experiments/arlington_model_verify/run_20261016T152924679939Z_a0d008e252ea/arlington_verification.json))
đạt6/6 fixtures/all assertions:4 ca cũ giữ nguyên và2 AcroForm mới. SigFlags=3
có BitsClear(3,32) pass; SigFlags=4 fail theo InteractiveForm.SigFlags của TSV
thật. Ba hàm bit còn lại có synthetic function/engine checks; không suy thành
đã kiểm hết174 call sites hay predicate/model conformance. Unsupported context
vẫn được fixture xác nhận rõ; whole_document_complete luôn false; caps và cleanup
đạt. PDF fixture do code tạo và giữ private/ignored, không dùng fixture thay model.

Python3.11.17 `.venv` tái dùng; không dependency mới hoặc thay config caps. pip,
diff checks đạt; tests/docs/plans/log synchronized; README/AGENTS giữ nguyên.
Toàn bộ1735 report files cũ và log prefix giữ nguyên. Chỉ code/tests/docs/aggregate
verification được commit; không raw PDF,PDF identity/hash/path,blob,credential,
checkpoint/model binary. Các run cũ và claim operator vẫn nguyên,không queue job mới.

## Giới hạn nghiệm thu

**Không chạy PDF thật cho mã predicate mới**, không đọc lại raw PDF/blob hoặc
mẫu Test, không model fitting/evaluation,JS execution/render/Reader/CAPE/network/
credential change/push/upload. Lượt64 cũ tại ba64a514ae5a và nghiệm thu21-primary
vẫn đúng revision của chúng; không dùng làm bằng chứng cho ngữ nghĩa mới.
Các giới hạn56resource_limit và roadmap media/forensic/full conformance/runtime/
visual/containment/release vẫn mở. Không reset claim hoặc đổi caps để lấy kết quả
thuận lợi. MetricsF1/MCC/ECE/Brier N/A:no model/partition evaluated; Label1=malicious,
ECE10equal-width bins,p=1 in final bin. Full goal chưa hoàn tất.
