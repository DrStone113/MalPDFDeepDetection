# Kiểm chứng hợp đồng/schema độc lập, 2026-10-16

Đã đồng bộ JSON Schema của ba store với metadata backend thực tế và bổ sung
những invariant runtime còn thiếu. Chỉ dùng bytes/JSON fixture tổng hợp lành
tính và metadata đã lưu; không đọc PDF thật hoặc chạy phân tích động. Toàn bộ
kế hoạch extract-pdf vẫn mở.

Maintenance ID: `run_20261015T192417026322Z_7d02abdb85da`.
Commit sinh mã `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Ngày báo cáo UTC+7; mọi run ID/timestamp là UTC thực tế, giữ nguyên khi lượt
công việc đi qua ngày UTC. Không stage/commit.

## Vấn đề được xác minh và cách sửa

Verifier Draft2020-12 độc lập phát hiện26 lỗi `additionalProperties` trong
coverage schema cũ trên bốn bundle pipeline tổng hợp:7,7,6,6 lỗi. Các backend
đã xuất `scope`, `version`, model Arlington và trạng thái graph/lexical nhưng
schema chỉ cho `observation_status`/`limitations`. Evidence/feature schemas của
các fixture này không có lỗi. Giữ nguyên schema cũ và kết quả đối chiếu ở
`artifacts/tmp/maintenance/extract_pdf/schema_original_schemas.json` và
`schema_before_checks.json`.

- [schemas.py](../../src/malpdf/extraction/schemas.py) khai báo các field backend
  hợp lệ với kiểu tường minh và optionality. Không bật đại trà additional fields.
  Core stores/records/groups vẫn đóng; edge cần id/source/target và vẫn giữ
  attributes mở. Partial measurement có giá trị cũng bắt buộc có evidence refs.
  Schemas được materialize thành JSON tree độc lập để không alias template enum.
- [contracts.py](../../src/malpdf/extraction/contracts.py) kiểm tra core shape,
  backend types/status/scope, string-list limitations, capability/conflict object
  arrays, global observation counts và whole-document completion. Global counts
  phải khớp feature records, có thể ghi thêm các trạng thái có count0. V1 vẫn
  bắt buộc `whole_document_complete=false`.
- Metadata opaque vẫn phải JSON-safe: không coercion numeric dict key thành
  string, không NaN/Infinity, object không hỗ trợ hoặc cycle. JSON failures trả
  mã lỗi cố định. Coverage ratio rất lớn bị từ chối bằng validation error, không
  rò OverflowError. Không sửa dữ liệu đầu vào hoặc đặc trưng model để đạt schema.
- Runtime giữ những kiểm tra ngoài khả năng schema độc lập: store identity,
  node/edge uniqueness, source references, locator ordering và count equality.
  JSON Schema xem1.0 là số nguyên toán học; Python protocol vẫn yêu cầu int thực
  cho locator/count columns. Schema-valid không thay thế `validate_bundle`.

Opaque details, edge attributes, capability/conflict objects, worker/provenance
và bundle envelope extensions được giữ nguyên. Điều chỉnh fixture exporter để
status counts phản ánh đúng các feature synthetic đã thêm; không bỏ assertion
hay sửa output pipeline thật.

## Kiểm thử và đối chiếu độc lập

**1559 passed**, hai cảnh báo sklearn single-label đã có,207.47s.
Log cuối: `artifacts/tmp/maintenance/extract_pdf/schema_full.log`.
69 ca mới ở `tests/test_extraction_contracts.py` đã được collect độc lập;134 ca
contracts/extraction/exporter hồi quy qua trong18.31s (`schema_unit.log`).
`pip check` và `git diff --check` qua, log cùng domain.

Các ca chính:9 observation states, absence/null/evidence rules, metadata backend
legitimate và malformed, unknown core fields, limit/scope/type/count/completion
errors, JSON safety/cycles, runtime-only identity/reference invariants, independent
schema trees và từ chối remote schema references. Registry không tải reference
ngoài; test chặn socket/URL functions khi kiểm metaschema và instance.

| Bundle tổng hợp đã lưu | Coverage errors trước | Errors sau trên cả3 stores |
| --- | ---: | ---: |
| Root byte-image fixture | 7 | 0 |
| Nested-PDF byte-image/Arlington fixture | 7 | 0 |
| XFA/script fixture | 6 | 0 |
| Child-PDF/script fixture | 6 | 0 |

Đã kiểm12 store instances bằng Draft202012Validator và toàn bộ bundle bằng
runtime validator; byte source JSON giữ nguyên SHA. Source paths và counts ở
`schema_after_checks.json`, schema mới ở `schema_release_schemas.json`.
Không theo source PDF, raw blob hoặc URL từ bundle. Các số lỗi là kết quả schema
conformance của fixture, không phải chất lượng nhận diện mã độc.

Một phép kiểm riêng dùng `.venv/bin/python -S`, nạp bundle fixture qua stdin,
import source trực tiếp và chạy runtime validator/schema generator khi tắt
site-packages: hợp lệ,3 schema documents, không nạp jsonschema/pypdf/pyarrow/torch.
Evidence: `schema_stdlib_runtime.json`. `jsonschema` chỉ là dev oracle, không trở
thành runtime dependency của extraction.

## Dependency và lệnh tái lập

Thêm `jsonschema==4.26.0` trong `[project.optional-dependencies].dev`, cài lại
editable project từ `pyproject.toml` với CPU index. Không cài tool ngoài khai báo
hoặc đổi dependency runtime có sẵn. Giữ install log `schema_install.log`.
Tái dùng Python3.11 `.venv` được tạo fresh ở lượt native-parser; không nhận là
tạo một fresh venv mới hoặc môi trường giống lượt trước sau khi thêm dev tools.

Môi trường hiệu lực: Python3.11.17; jsonschema4.26.0,
referencing0.37.0, jsonschema-specifications2025.9.1, rpds-py2026.9.1,
attrs26.1.0. Các version runtime/pytest hiệu lực được ghi đầy đủ trong
`schema_environment.json`. Không tuyên bố đã kiểm các thay đổi này trên Python3.13.

```bash
.venv/bin/python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu -e '.[dev]'
TMPDIR="$PWD/artifacts/tmp/tests" MPLBACKEND=Agg OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 .venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pip check
git diff --check
```

Runtime validator và schema generator dùng standard library. Verifier độc lập
theo [API Draft202012Validator](https://python-jsonschema.readthedocs.io/en/stable/validate/)
với [registry từ chối reference ngoài](https://python-jsonschema.readthedocs.io/en/stable/referencing/).
Quy tắc numeric của schema theo [Draft2020-12](https://json-schema.org/draft/2020-12/json-schema-validation).
Các schema/instance được kiểm cục bộ, không upload metadata hay tải metaschema.

## Job metadata và provenance

Job mới: **`run_20261016T062326082446Z_7d02abdb85da`**,
217 source/config files; lock SHA256
`98674fd6359d832f8d54c01c55df671e61b5be81cf7a07c07fff3e14d964d884`.
Giữ nguyên chính xác64 dòng của job trước:32 Train/32 exposed Validation,
16 mỗi lớp mỗi partition, seed42. Không chọn Test hoặc chia lại dữ liệu.
Lock trước từ chối source/dev-declaration drift; không sửa report/lock cũ.

| Manifest | Đường dẫn | SHA256 |
| --- | --- | --- |
| Split | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| Source | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| Normalization | `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

Prepare/load đã xác minh model Arlington thật tại
**`b7d880b7a3d3c8f505c025f17763397475e90503`**,610 TSV/3976 dòng và
LICENSE/NOTICE/checksum/Git tree. Không fallback HEAD hoặc model fixture.
Kiểm schema cho synthetic backend `fixture` chỉ chứng minh kiểu dữ liệu, không
thay cho kiểm model thật. Evidence riêng:
[prepared job](../experiments/pdf_extraction_prepare/run_20261016T062326082446Z_7d02abdb85da/run_summary.json)
và `schema_job_checks.json`.

170 file baseline ngoài phạm vi sửa giữ nguyên SHA;646152 byte prefix research
log được giữ trước các append. README/AGENTS và report cũ giữ nguyên trong lượt
này. Dọn hai basetemp của lượt này sau khi giữ logs; không dọn môi trường người
dùng hay output cũ. Ignore coverage và staged paths được kiểm tra cuối;
`schema_preservation.json`, `schema_release_checks.json` giữ bằng chứng.

## Chưa nghiệm thu

Chưa đọc/hash/parse PDF thật, chưa chạy21 partial hoặc đo classifier/corpus
coverage. F1/MCC/ECE/Brier N/A vì không đánh giá model/partition nghiên cứu;
Label1 là malicious, ECE10 equal-width bins, p=1 trong bin cuối.
Mọi kết quả ở đây là conformance của synthetic metadata và invariant runtime.

Các nhánh parser/codec/semantics/reachability đầy đủ, plugin/container release,
native PyG/DGL, page render/OCR/QR, emulator/Reader/CAPE và reingestion vẫn cần
triển khai/nghiệm thu theo [toàn bộ acceptance](../../plans/extract-pdf/acceptance.md).
PDF thật/dynamic chờ xác nhận phạm vi và cô lập LAB tại console; không suy quyền
chạy từ schema hợp lệ, kiểm thử xanh hoặc job đã chuẩn bị.
