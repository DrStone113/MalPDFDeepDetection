# Exporter JSONL/Parquet và đồ thị, 2026-10-16

Đã bổ sung CLI/API xuất bundle có sẵn thành sáu bảng JSONL/Parquet, đồ thị
NetworkX và tensor COO tùy chọn. Giữ nguyên dữ liệu gốc, null, observation
status, phạm vi và nguồn bằng chứng; không đọc PDF hoặc theo đường dẫn blob.
Chỉ kiểm chứng metadata tổng hợp lành tính. Kế hoạch sáu giai đoạn chưa hoàn tất.

Maintenance ID: `run_20261015T185157088755Z_7d02abdb85da`.
Commit sinh mã `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Ngày báo cáo UTC+7; run ID dùng UTC. Không stage/commit trong lượt này.

## Hợp đồng và triển khai

- [tabular.py](../../src/malpdf/extraction/tabular.py): schema Arrow cố định
  `pdf-tabular-v1` cho documents/features/evidence/edges/coverage_groups/backends.
  JSON original giữ mọi field, metadata, capability/conflict, trigger và extension.
  Bool/int/float tách cột; -0.0 giữ sign, null không đổi thành0. Int/locator vượt
  int64 giữ giá trị JSON chính xác và flag overflow, không ép float hay truncate.
  `restore_bundle` kiểm tra bundle và toàn bộ projection trước khi khôi phục.
- [graph_exports.py](../../src/malpdf/extraction/graph_exports.py): node-link
  directed multigraph với original records lồng dưới `record`; giữ cạnh trùng,
  self-loop, isolates và provenance repaired. Torch int64 COO có `num_nodes`
  tường minh và original IDs. Không tạo nhãn/node features hoặc coalesce cạnh.
- [exporters.py](../../src/malpdf/extraction/exporters.py): explicit JSON inputs,
  đọc tuần tự, quota, checksum, phiên bản hiệu lực và manifest running/completed/
  failed/interrupted. Output mới trong ignored `data/processed/`; từ chối
  symlink/collision. Prefix hoàn tất và file chưa hoàn tất được giữ khi lỗi.
- `malpdf export` và lazy library APIs; tái dùng guard processed-output của
  orchestrator. Không thay pipeline parser, Markov float32, model, split hay
  ngưỡng. Không mở tham chiếu raw/decoded/artifact hoặc URL.

Khóa join là `(export_id, bundle_id)` rồi ID evidence/feature. Sample SHA có thể
trùng/null, không phải occurrence key. Mỗi input/retry được giữ riêng, kể cả
bundle timeout/resource/error. Input JSON không hợp lệ làm batch failed với
input index, không tạo kết quả completed bằng cách bỏ mẫu. JSON object key order
không phải semantics; chỉ số coverage/backend được sắp theo key. Array order
và mọi giá trị JSON gốc giữ nguyên.

Caps:256 inputs,64MiB source/canonical JSON mỗi bundle,512MiB total input,
200000 rows/bundle,2000000 rows tổng, JSON depth128/1000000 entries,
2GiB data output và2MiB manifest điều khiển. Duplicate keys, NaN/Infinity và
malformed contracts bị từ chối. Các giới hạn parser/PNG/raw cũ không đổi.
Chi tiết và ví dụ consumer:
[hợp đồng exporter](../../docs/pdf_extraction.md#existing-bundle-tabular-and-graph-exports).

## Kiểm thử cuối và các lần sửa

**1490 passed**, hai cảnh báo sklearn single-label đã có,292.93s.
Log: `artifacts/tmp/maintenance/extract_pdf/exports_release_pytest.log`.
Trong đó35 ca ở `tests/test_extraction_exports.py` kiểm tra typed values/null,
signed zero, overflow, full reconstruction, metadata, repeated/failed inputs,
khóa các lượt riêng, empty schemas, topology, caps, collision, symlink,
interruption và CLI thực. PyArrow/NetworkX/Torch thực được dùng; không gọi PyG/DGL.
`pip check` không có dependency hỏng và `git diff --check` qua; lưu log cùng domain.

Giữ bằng chứng trung gian:

- `exports_unit.log`:57 passed/2 failed,12.75s. Round-trip phát hiện chỉ số
  coverage/backend phụ thuộc insertion order dù JSON canonical đã đổi thứ tự.
  Đã sắp mapping theo key và thêm regression, giữ nguyên record arrays.
- `exports_regression.log`:73 passed,13.45s; sau đó thêm khóa export để tránh
  ghép nhầm các occurrence ở nhiều lượt.35 ca riêng qua trong7.00s.
- `exports_full.log`:1490 passed,279.09s trước khi thêm kiểm tra metadata
  nested-list chặt. Phép kiểm bundle pipeline phát hiện schema mặc định gọi
  field con `item`, còn compliant Parquet dùng `element`. Logical types và
  table metadata bằng nhau nhưng strict nested-field comparison chưa bằng.
- Đã khai báo `element` trong Arrow schema, giữ Parquet compliant encoding và
  thêm assertion `schema.equals(..., check_metadata=True)` cho cả sáu bảng.
  `exports_schema.log`:35 passed,9.99s; sau đó chạy lại suite cuối1490 passed.

Lượt xuất prototype được giữ nguyên tại
`data/processed/pdf_extraction_exports/run_20261015T190439253615Z_7d02abdb85da/`.
Manifest của utility ghi completed vì các file đã xuất; kiểm chứng strict
schema sau đó ghi failed trong `exports_initial_fixture_checks.json`. Không
đổi manifest cũ để che lỗi hoặc dùng suite trước sửa làm bằng chứng mã cuối.

## Kiểm chứng bundle pipeline đã lưu

Lượt xuất mã cuối:
`data/processed/pdf_extraction_exports/run_20261015T190759331131Z_7d02abdb85da/`.
CLI nhận bốn JSON bundle tổng hợp từ các increment trước, không chạy lại parser.
Đã xác minh53 file bằng checksum, tổng16098226 byte data output. Mỗi bundle
khôi phục chính xác từ JSONL và Parquet, strict Arrow schema/metadata bằng nhau,
mọi node/cạnh NetworkX và từng cột tensor index khớp nguồn. Status nguồn ở cả
bốn bundle là observed và được giữ nguyên; whole-document coverage vẫn false.

| Bundle tổng hợp | Feature records | Nodes | Edges |
| --- | ---: | ---: | ---: |
| Root có private stream và JS syntax | 578 | 170 | 192 |
| Root chứa PDF con/private stream và model Arlington | 1080 | 722 | 1030 |
| XFA có script syntax | 529 | 156 | 183 |
| PDF con từ fixture JS trước | 1002 | 178 | 195 |

Các số trên chỉ là số record của fixture, không đo corpus/threat coverage.
Checks và đường dẫn input JSON đầy đủ:
`artifacts/tmp/maintenance/extract_pdf/exports_release_fixture_checks.json`.
CLI log: `exports_schema_release_cli.log`. Không đọc source PDF hay PNG/blob;
những đường dẫn nguồn đã dọn trong các bundle cũng không được theo.

Môi trường hiệu lực: Python3.11.17, PyArrow19.0.1, NetworkX3.6.1,
Torch2.11.0+cpu. Tái dùng `.venv` đã cài từ pyproject ở lượt native-parser;
không thêm dependency hoặc tuyên bố fresh install ở lượt này. NetworkX có sẵn
trong dependency stack của Torch. PyG/DGL không được cài hay kiểm thử native;
chỉ xác minh layout COO theo convention đã ghi trong tài liệu.

Lệnh tái lập, từ repo root với JSON bundle đã được phép xử lý:

```bash
.venv/bin/malpdf export /path/to/authorized/bundle.json \
  --output-root data/processed/pdf_extraction_exports --formats jsonl parquet graph
TMPDIR="$PWD/artifacts/tmp/tests" MPLBACKEND=Agg OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 .venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pip check
git diff --check
```

## Job tĩnh và provenance được giữ

Job metadata cuối: **`run_20261015T190845295617Z_7d02abdb85da`**,
217 source/config files; lock SHA256
`a1461f795529517c43a6187f90b920cf76bc9ff39bfd60cdf2a5bba1f07fa3f0`.
Giữ nguyên chính xác64 dòng của job trước:32 Train +32 exposed Validation,
16 mỗi lớp mỗi partition, seed42. Không chọn Test hay tạo split mới.
Job prototype trước sửa schema tự từ chối source drift; không thay lock cũ.

| Manifest | Đường dẫn | SHA256 |
| --- | --- | --- |
| Split | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| Source | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| Normalization | `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

Prepare đã nạp/xác minh model Arlington thật ở
**`b7d880b7a3d3c8f505c025f17763397475e90503`**,610 TSV/3976 dòng,
LICENSE/NOTICE và checksum/Git tree. Không fallback HEAD hay fixture. Các rule
results đã có trong bundle được xuất nguyên trạng; lượt này không phải chạy
smoke PDF mới hoặc chứng minh Arlington conformance đầy đủ.
[Preparation evidence](../experiments/pdf_extraction_prepare/run_20261015T190845295617Z_7d02abdb85da/run_summary.json).

156 tệp baseline ngoài phạm vi sửa giữ nguyên SHA;641989 byte prefix research
log được giữ trước các append. README/AGENTS/pyproject và báo cáo cũ không bị sửa
trong increment này. Dọn sáu basetemp do task tạo sau khi giữ logs; hai lượt xuất
và report/job cũ đều còn. Blobs/Parquet/reference snapshot ignored; không có
artifact nhị phân hoặc dữ liệu được stage. Checks cuối:
`exports_preservation.json`, `exports_release_checks.json` trong domain maintenance.

## Phạm vi chưa hoàn tất

Chưa đọc/hash/parse PDF thật, chưa nghiệm thu21 partial hoặc đo cải thiện mô
hình. F1/MCC/ECE/Brier N/A vì không có classifier/partition nghiên cứu được đánh
giá. Label1 là malicious; quy ước ECE10 equal-width bins, p=1 vào bin cuối.
Chưa đo scale/latency/RAM hay downstream benchmark trên corpus thật.

Plugin/container release, phần native media, semantics/reachability đầy đủ,
page render/OCR/QR, JS emulator, Reader/CAPE và reingestion động còn mở.
Các thao tác động và PDF thật chờ phạm vi/cô lập LAB được xác nhận, không suy
quyền chạy từ việc exporter đã qua kiểm thử. Kiểm kê toàn kế hoạch tiếp tục ở
[acceptance.md](../../plans/extract-pdf/acceptance.md).
