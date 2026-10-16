# SDK plugin tĩnh và kiểm chứng tài nguyên, 2026-10-16

Đã triển khai ba giao diện `BaseParserPlugin`, `BaseDecoderPlugin` và
`BaseFeaturePlugin`, tích hợp thật vào worker `deep-static`. Chỉ dùng PDF/bytes
tổng hợp lành tính và metadata đã lưu. Không đọc/hash/parse PDF thật, không chạy
JS, render, Reader/CAPE hoặc Test. Toàn bộ kế hoạch sáu giai đoạn vẫn mở.

Maintenance ID: `run_20261016T064856581319Z_7d02abdb85da`.
Commit sinh mã `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Không stage/commit hoặc sửa README/AGENTS/các báo cáo lịch sử trong lượt này.
Hướng dẫn API và hợp đồng nằm tại
[contributing_plugins.md](../../docs/contributing_plugins.md).

## Hành vi đã triển khai

- [plugins.py](../../src/malpdf/extraction/plugins.py) cung cấp registry explicit,
  lớp triển khai importable, source path/SHA256, version, config hash và seed.
  Config JSON được snapshot; descriptors không xuất giá trị config. Không nạp
  module từ PDF, tự tìm plugin, cài dependency hoặc ghi đè builtin/Crypt.
- Chỉ JSON đi qua spawn. Worker kiểm source/module path và import plugin sau
  khi áp giới hạn CPU/address-space và chuyển stdout/stderr vào devnull.
  Constructor/method chạy trong worker. Pin áp dụng cho file triển khai, không
  tự khóa toàn bộ dependency tree; plugin là mã Python đáng tin được operator
  duyệt. OS caps không chứng minh containment cho mã Python ác ý.
- Parser bổ sung view vào inventory và differential merger hiện có; dùng chung
  quota raw stream. Offset được đối chiếu header object/generation, claim không
  xác minh giữ metadata và public offset=null. Repaired flag bảo thủ, raw stream
  vượt cap unavailable với digest=null, không biến thành stream rỗng quan sát được.
- Decoder dùng chung dispatcher và decoded-byte ledger qua root streams, PDF
  con và raw XRef/ObjStm. Chỉ nhận tham số integer được đăng ký; output qua writer
  có cap, prefix lỗi không đi tiếp. Suppress overflow vẫn không thành success.
  Checkpoint phân biệt đăng ký, bắt đầu constructor và gọi method; checkpoint
  raw structural đang dở cũng xuất backend partial. Native allocations ẩn trong
  plugin cần implementation review; wrapper chỉ đếm bytes thực sự xuất.
- [plugin_features.py](../../src/malpdf/extraction/plugin_features.py) chạy sau
  checkpoint built-in, dùng bản sao bundle và buffers đã giữ. Mỗi batch có
  namespace/source refs, forward-reference repair propagation và validation
  transactional; không sửa/ghi đè đặc trưng chính. Batch lỗi bị loại cùng nhau,
  plugin sau vẫn chạy; batch hoàn tất giữ được khi worker timeout.
- Seed qua `set_random_seed`. Tối đa8 plugins, context JSON4MiB; toàn bộ feature
  plugins dùng chung256 evidence/512 features/1024 edges/512KiB metadata với
  terminal reserve. Chỉ được hạ các ceiling này. Các byte/object/depth/deadline
  cũ tiếp tục áp dụng; hook không cấp thêm ngân sách decode.

CLI và job CIC hiện không nhận module path hoặc tự bật registry. Fingerprint
job ghi rõ `plugins.enabled=[]`. Plugin study cần cấu hình/lock riêng và giữ
nguyên các nguyên tắc Protocol G/Test. API minh họa chỉ dùng module importable
và main guard; không có plugin bên ngoài nào được tải để kiểm thử.

## Kiểm thử và evidence tổng hợp

**1608 passed**, hai cảnh báo sklearn single-label đã có,384.23s.
Log: `artifacts/tmp/maintenance/extract_pdf/plugins_full.log`.
49 ca SDK được collect độc lập; targeted cuối115 passed/21.02s
(`plugins_wire.log`), regression252 passed/88.23s (`plugins_regression.log`).
`pip check` và `git diff --check` qua; không thêm/sửa dependency trong lượt này.
Tái dùng `.venv` Python3.11.17 đã cài từ pyproject; không nhận là fresh venv mới.
Versions hiệu lực ở `plugins_environment.json` trong cùng maintenance domain.
Chưa kiểm trên Python3.13.

Fixture worker kiểm ba hook thực, custom decoder cộng Flate qua PDF cha/con,
shared byte ledger, source/config drift, quota, malformed contribution,
namespace collision, repaired source chain/cycle, immutable primary và timeout
checkpoint. Probe của module ghi **import-time CPU cap12s/address-space1GiB**,
trùng cap khi gọi feature; PID khác parent. Fixture dùng wall30s, còn job CIC
vẫn wall20s. Primary features, code và v8 bằng baseline trên cùng bytes tổng hợp.
Worker fixture hoàn thành khoảng6.10s, peak RSS267776000 bytes và cleanup=true;
exit -9 được giữ nguyên trong evidence sau cleanup, không được suy là OOM chỉ
từ exit code. Không dùng thời gian fixture để dự báo runtime corpus thật.

Giữ bundle và13 blobs tổng hợp/3468 bytes dưới
`artifacts/tmp/maintenance/extract_pdf/plugins_fixture_bundle.json` và
`plugins_fixture_blobs/`. SHA256 bundle:
`914dee2cae956bf3315eb691364a7d0bff267c741837bd201fbf14a518e04e10`.
Bundle có228 evidence,1075 features,263 edges; runtime validator và ba public
Draft2020-12 schemas độc lập đều hợp lệ, không theo references ra mạng.
`plugins_fixture_checks.json` giữ counts, schema errors=0, caps, backend scope
và checksum từng blob. Source paths trong bundle gốc giữ nguyên; bản sao blob
được ghi riêng trong evidence, không sửa metadata gốc để đổi provenance.

Exporter đã ghi bundle này vào
`data/processed/pdf_extraction_exports/run_20261016T072016674018Z_7d02abdb85da/`.
JSONL/Parquet đều khôi phục chính xác toàn bộ bundle từ sáu bảng; NetworkX
multigraph giữ228 nodes/263 edges, Torch COO shape2×263. Không đọc PDF hay theo
blob paths. `plugins_export_checks.json` ghi kết quả. Post-export verifier ban
đầu dùng nhầm thư mục `graph/`; đã sửa sang `graphs/` và kiểm chính output hoàn
tất đó, không chạy lại hoặc ghi đè export.

Lượt test đầu126 passed/1 failed do assertion truy cập sai đường dẫn metadata
`decoded_sha256`/artifact kind trong fixture, được sửa để kiểm đúng output và
bổ sung kiểm leaf decoded/persisted bytes; giữ `plugins_unit.log`. Không bỏ
assertion, thay fixture cho model thật hoặc đánh dấu ca lỗi là thành công.

## Câu hỏi RAM/CPU: bằng chứng hiện có

Tại `2026-10-16T07:19:23.649040+00:00`, môi trường báo4 logical CPUs/affinity4,
tổng RAM hệ thống7.70GiB, `MemAvailable`5.15GiB và swap512MiB chưa dùng.
Các file quota cgroup không hiện diện trong view kiểm tra; không suy điều đó
thành quota unlimited. Snapshot ở `plugins_resource_review.json`; đây là một
thời điểm đo, không phải profile tải toàn lượt. Chưa thấy bằng chứng thiếu RAM
toàn máy tại thời điểm này, và chưa đủ bằng chứng khuyến nghị nâng phần cứng.

Job extraction đang khóa1 worker,20s wall/12s CPU/1GiB **không gian địa chỉ**.
12s CPU là thời lượng tính toán, không phải số lõi; thêm lõi không tự chia một
worker thành nhiều worker. RSS đo RAM resident khác với RLIMIT_AS, nên peak RSS
thấp không loại trừ việc chạm giới hạn address space.

[Review lịch sử21 partial](../experiments/cic_v9_final_review/run_20261011T050628599657Z_ff3f5b65d376/review_evidence.json)
ghi13 ca MuPDF embedded bị `decoded_byte_limit`, cùng giới hạn metadata và AST
(counts chồng lấp). Đây là software caps riêng, không chứng minh máy thiếu RAM
hoặc CPU. [Cold summary v9 lịch sử](../experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/pipeline_summary.json)
ghi peak worker RSS382582784 bytes và nhiều lỗi xref/stream/parser; chúng cũng
không được sửa bằng cách thêm phần cứng đơn thuần. Những số liệu lịch sử không
được nhận là kết quả chạy lại với extractor mới hoặc VM hiện tại.

Chưa đổi resource limits/split/selection. Muốn xác định ca nào thiếu tài nguyên
cần telemetry CPU/wall/RSS/address-space và reason codes theo stage trong một
lượt LAB đã duyệt, với thiết kế so sánh ngân sách khóa riêng trên Train/Validation.
Không dùng Test hoặc tăng cap không giới hạn để ép kết quả hoàn tất.

## Job offline và model thật đã khóa

Job metadata mới **`run_20261016T071557258581Z_7d02abdb85da`** khóa219 source/
config files; lock SHA256
`9459479f78e46a97510b4630fa468506f167ec2b4c8b2b886083c3249d2d1d4c`.
Job trước từ chối source/fingerprint drift; giữ nguyên report/lock cũ. Job mới
qua `load_job`, giữ chính xác64 dòng trước:32 Train/32 exposed Validation,
16 mỗi lớp mỗi partition, seed42. Không chọn Test hoặc tái chia dữ liệu.

| Manifest | Đường dẫn | SHA256 |
| --- | --- | --- |
| Split | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| Source | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| Normalization | `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

Prepare/load xác minh Arlington thật tại
**`b7d880b7a3d3c8f505c025f17763397475e90503`**: **610 TSV,3976 rows**,
497394 verified bytes gồm LICENSE/NOTICE; checksum từng file và pinned Git tree
đều đúng, status=available. Không chuyển HEAD hoặc dùng model fixture thay thế.
`plugins_job_checks.json` giữ provenance đầy đủ;
[prepared run](../experiments/pdf_extraction_prepare/run_20261016T071557258581Z_7d02abdb85da/run_summary.json)
chỉ là metadata preparation, không phải PDF thật đã được phân tích.

```bash
TMPDIR="$PWD/artifacts/tmp/tests" MPLBACKEND=Agg OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 .venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pip check
git diff --check
.venv/bin/python scripts/22_extract_pdf.py prepare --config configs/extraction_profiles.yaml
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261016T071557258581Z_7d02abdb85da
```

## Bảo toàn và phần còn thiếu

188 file baseline được đối chiếu;17 file đổi đúng phạm vi SDK/docs/log,171 file
còn lại giữ nguyên SHA. Giữ649255 bytes prefix research log rồi append. Chỉ dọn
bốn basetemp do lượt SDK tạo sau khi giữ evidence/logs; không đụng output cũ
hoặc virtual environment. `plugins_preservation.json` và
`plugins_release_checks.json` giữ kiểm tra prefix, paths, ignore và final checks.

PDF thật/21 partial, codec/font/image/archive đầy đủ, catalog reachability và
Arlington conformance, JS liên thủ tục/heap/global, render/OCR/QR,
emulator/Reader/CAPE/reingestion và container/community/corpus release vẫn cần
triển khai/nghiệm thu theo [acceptance](../../plans/extract-pdf/acceptance.md).
Phần PDF thật chờ kiểm cô lập VMware console; không tự ngắt NIC của SSH hiện
tại hoặc suy quyền phân tích động từ test xanh.

F1/MCC/ECE/Brier N/A: không đánh giá research model/partition. Label1 là
malicious; ECE convention10 equal-width bins,p=1 thuộc bin cuối. Số test, schema
pass và toy custom filter không phải evidence exploit detection hoặc codec coverage.
