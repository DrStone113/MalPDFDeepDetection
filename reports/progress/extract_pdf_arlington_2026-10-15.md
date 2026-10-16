# Arlington: reference đã khóa và kiểm chứng tích hợp, 2026-10-15

Đã triển khai loader, interpreter AST có giới hạn, rule engine trên raw IR và
tích hợp deep-static/job offline với **model Arlington thật đã khóa**. Lượt này
chỉ dùng reference công khai được người dùng cho phép tải và PDF tổng hợp lành
tính. Chưa chạy PDF thật, render, thực thi/giả lập JS, Reader hoặc CAPE; chưa
nghiệm thu toàn bộ kế hoạch extract-pdf.

## Nguồn và khóa model

- Nguồn: https://github.com/pdf-association/arlington-pdf-model.
- Người dùng chọn `b7d880b`; Git resolve full SHA:
  **`b7d880b7a3d3c8f505c025f17763397475e90503`**.
- Repo gốc xác minh bằng Git: `/home/drstone/MalPDFDeepDetection`.
- Snapshot: `/home/drstone/MalPDFDeepDetection/third_party/arlington-pdf-model/`;
  loader đọc `tsv/latest`. Checkout sparse, không checkout PDF của repo upstream.
- Lock: [configs/arlington.lock.json](../../configs/arlington.lock.json).
  SHA256 của chính tệp lock:
  `60387a6c67efe4392ae9e15ac31b78c936bc855c5f3219902b88e31b9d60aab9`.
- Đã nạp **610 TSV / 3976 dòng quy tắc**. Lock ghi checksum/size/Git blob cho
  612 tệp: mọi TSV cùng LICENSE và NOTICE.txt; tổng 497394 byte.
- Hai dòng DocInfo upstream thiếu ô `Note` cuối được đánh dấu loader note;
  không sửa byte TSV. Snapshot được gitignore; LICENSE/NOTICE giữ trong snapshot.

Loader kiểm tra toàn bộ danh sách file, checksum và blob thuộc đúng Git tree
trước khi trả catalog. Model thiếu, lệch checksum, sai HEAD, symlink hoặc khác
Git tree báo unavailable. Không tải mạng khi chạy, không tự chuyển sang HEAD,
không thay bằng fixture model. Tải reference không phải tải dataset PDF.

## Hành vi và giới hạn

Các module mới `arlington_model.py`, `arlington_expression.py`,
`arlington_validate.py`, `arlington_exports.py` nằm trong `src/malpdf/extraction/`.
Interpreter không dùng eval/thực thi mã; rule engine chỉ đọc cây raw và object
cache đã có, sau checkpoint forensic. Không parse/decode thêm PDF. Có kiểm tra
required, type/version, direct/indirect, possible values, special cases được hỗ
trợ, schema link OR, wildcard và nhóm array lặp.

`IndirectReference=FALSE` chấp nhận cả direct/indirect; MustBeDirect riêng biệt.
Null dictionary được xét absent trừ kiểu null tường minh; null array vẫn giữ
nguyên. Inherited/default là evidence có nguồn riêng, không sửa IR/reference/
null/primary features. Key lạ và key wildcard giữ node nguồn và hash, không
thêm plaintext nội dung mẫu. Deprecated có notice, không tự coi là invalid.

Check có table/line/checksum model và evidence nguồn. Các schema thay thế là
ứng viên OR; fail của một ứng viên không tự thành vi phạm của PDF. Predicate,
path/extension, tree/date/text semantics chưa hỗ trợ, thiếu context, cycle và
boolean reduction có điều kiện chưa xác định đều giữ Unknown/indeterminate,
với trạng thái unsupported khi phù hợp. Không có cờ xác nhận PDF hợp chuẩn.

Rule pass mặc định có trần 256 bindings, 2048 checks, depth24, 50000 AST steps
và512KiB metadata; hết step budget dừng và giữ check đã xong. Trần CPU/RAM/wall
chung với pipeline. Checkpoint Arlington riêng giữ bằng chứng trước đó khi
worker bị dừng. `complete=true` chỉ nói traversal ứng viên đã kết thúc trong
phạm vi này; observation vẫn partial, whole-document conformance chưa xác minh.

## Kiểm chứng bằng model thật đã khóa

Lượt cuối:
[run_20261015T133950289306Z_7d02abdb85da](../experiments/arlington_model_verify/run_20261015T133950289306Z_7d02abdb85da/arlington_verification.json).
Mọi checksum được kiểm tra, cả bốn fixture đều đạt mọi assertion:

| Fixture tự sinh | Check ứng viên | pass | fail | indeterminate |
| --- | ---: | ---: | ---: | ---: |
| Trang trắng | 301 | 268 | 6 | 27 |
| Catalog Type sai, vô hại | 301 | 266 | 10 | 25 |
| Pages trực tiếp thay vì reference | 727 | 641 | 20 | 66 |
| Key lạ vô hại | 302 | 268 | 6 | 28 |

Fail ở fixture trang trắng là các schema ứng viên không phù hợp khi thử nhánh
thay thế, không phải kết luận PDF sai hay mã độc. Đây không phải số quy tắc độc
lập trong toàn bộ catalog đã bao phủ. Unknown vẫn giữ nguyên; không có đo F1,
MCC, ECE, Brier hay độ phủ corpus.

Fingerprint smoke cuối khớp hoàn toàn với job cuối: 209 tệp nguồn/cấu hình,
Python/package/native versions, model và caps. Từng worker được kiểm tra cap
thực tế wall20s, CPU soft/hard12s, address space1GiB, process group riêng và
cleanup thành công. Python3.11.17; pikepdf10.17.0/QPDF12.4.2,
PyMuPDF1.26.7/MuPDF1.26.12, pypdf6.18.1; torch2.11.0+cpu và
torchvision0.26.0+cpu, CUDA build=None. Dùng lại venv đã được cài mới ở lượt
native-parser; không có thay đổi dependency hay tuyên bố cài mới trong lượt này.
Các cap/process này không chứng minh LAB đã cô lập khỏi host/Internet.

Lượt đầu `run_20261015T132320182763Z_7d02abdb85da` thất bại do ghi lại tệp
evidence với chế độ tạo mới; đã sửa CLI thành tệp riêng, giữ nguyên lượt lỗi.
Các lượt qua trung gian vẫn được giữ. Lượt `133640873670Z` ghi fingerprint cap
mặc định8s/4s trong khi bundle worker ghi20s/12s; lượt cuối sửa và assert đối
chiếu cả requested/effective caps. Không sửa evidence lịch sử để che sai lệch.

## Split và job offline

Job cuối chỉ chuẩn bị/check metadata:
[run_20261015T134030043594Z_7d02abdb85da](../experiments/pdf_extraction_prepare/run_20261015T134030043594Z_7d02abdb85da/run_summary.json).
Giữ đúng cùng64 bản ghi như job forensic trước: 32 Train,32 Validation đã lộ,
mỗi lớp16 mỗi partition, seed42. Không chia lại split, không chọn Test hoặc
đọc byte PDF thật. Hai lock cũ được kiểm tra từ chối vì fingerprint nguồn đổi.

Manifest giữ nguyên đường dẫn và SHA256:

- Split:
  `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv`;
  `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643`.
- Source:
  `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv`;
  `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b`.
- Normalization:
  `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv`;
  `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f`.

Lệnh tái lập từ repo root; smoke không cần dữ liệu thật:

```bash
.venv/bin/python scripts/23_arlington_model.py verify
.venv/bin/python scripts/23_arlington_model.py smoke
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T134030043594Z_7d02abdb85da
```

Job `run` chưa được thực thi: cần console VMware xác nhận NIC/sharing/clipboard/
drag-and-drop/credentials đúng phạm vi LAB và code sạch đã commit khớp lock.
Không tự ngắt NIC SSH. Render/JS execution/Reader/CAPE vẫn ngoài phạm vi.

## Kiểm tra bàn giao

- `pytest tests/`: **1332 passed**, hai cảnh báo sklearn single-label đã có,
  143.21s. Log: `artifacts/tmp/maintenance/extract_pdf/arlington_final_pytest.log`.
- `python -m pip check`: không có phụ thuộc hỏng; `git diff --check` qua.
- Unit tests dùng TSV/Git/PDF tổng hợp, độc lập snapshot/mạng/dataset. Có kiểm
  tra checksum drift, null, alternatives, redaction, quota và timeout/cleanup.
- Giữ78 tệp có sẵn ngoài phạm vi sửa và toàn bộ prefix research log. Không
  staging/commit; không có artifact nguy hiểm mới nằm ngoài ignore. Scratch
  của các lượt test đã dọn; runtime evidence giữ trong domain maintenance.
- Commit sinh mã: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty
  có cả thay đổi người dùng được giữ nguyên. Không coi đây là experiment sạch.
- Evidence kiểm tra:
  `artifacts/tmp/maintenance/extract_pdf/arlington_release_checks.json` và
  `arlington_preservation_checks.json`; script tự append mọi invocation vào
  [research log](../research_log.md).

Kế hoạch tổng thể còn mở theo [acceptance](../../plans/extract-pdf/acceptance.md):
đầy đủ Arlington/reachability và static-JS semantics, media/visual, reingestion,
export/release, nghiệm thu PDF thật/21 partial và các tầng động chưa hoàn tất.
Label=1 là malicious; ECE quy ước10 bin xác suất p(malicious) bằng nhau, p=1 ở
bin cuối. Các metric N/A vì chỉ maintenance/reference/synthetic verification.
