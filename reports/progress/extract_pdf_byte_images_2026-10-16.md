# Ảnh byte có offset và quota chung, 2026-10-16

Đã tích hợp ảnh byte lossless vào deep-static và kiểm chứng bằng dữ liệu tổng
hợp lành tính. Mỗi byte được ánh xạ thành một pixel grayscale8, giữ offset và
mask padding. Đây là biểu diễn byte, không phải ảnh render trang PDF. Chưa chạy
PDF thật, JS runtime, Reader hoặc CAPE; kế hoạch sáu giai đoạn vẫn mở.

Ngày báo cáo theo UTC+7; run ID dùng UTC. Commit sinh mã:
`7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Maintenance ID: `run_20261015T180339452093Z_7d02abdb85da`.

## Thay đổi

- [byte_images.py](../../src/malpdf/extraction/byte_images.py) tạo PNG bằng
  standard library, không gọi parser/render/image decoder. Thuật toán
  `raw-byte-gray8-png-v1`: tile rộng256, tối đa256 hàng, không resize hay
  normalize. Pixel hợp lệ là prefix `[0, valid_pixels)`; padding0 không phải
  dữ liệu nguồn. `pixel_offset` trả null cho padding.
- [byte_image_exports.py](../../src/malpdf/extraction/byte_image_exports.py)
  giữ source → view → tile, object/generation và repaired provenance. Original
  bytes có offset file; ObjStm/stream/artifact có namespace digest và offset
  riêng, không gán offset decoded thành offset PDF gốc. Evidence không tìm được
  nguồn được đếm riêng thay vì tạo liên kết giả.
- Worker tái dùng buffer đã được raw transport chấp nhận và chạy sau các
  checkpoint cũ; không đọc/parse/decode PDF thêm. PNG dùng chính raw sink cũ,
  không cấp lại quota hoặc capture PNG làm nguồn ảnh mới. Primary/code/v8 và
  float32 Markov probabilities giữ nguyên; không sửa model, split hay ngưỡng.
- CLI thêm `--raw-artifact-dir` cho deep-static: thư mục ignored mới dưới
  `data/processed/` hoặc `artifacts/`, không symlink. Flag không phù hợp bị từ
  chối trước PDF access. Blob vẫn mang tên SHA256 `.bin`, MIME `image/png`.
  Không yêu cầu lưu thì parent chỉ kiểm tra transport trong RAM.

Default:128 nguồn,256 lượt tile,4MiB pixel work kể cả padding,4MiB PNG duy nhất
được retain,10MiB/256 source blobs cache và512KiB metadata có terminal reserve.
Mọi PNG chia sẻ trần raw retention10MiB với byte raw/decoded của sample. Chọn
tile head/tail luân phiên, round robin giữa các nguồn đã nhận; phần bị bỏ vẫn
unobserved. Checkpoint trước giới hạn/timeout được giữ dưới dạng lower bound.

`encoded`, worker-retained, parent-verified và persisted là các phép đo riêng.
`image_availability` ghi `persisted`, `verified_not_persisted` hoặc `unavailable`;
hash không chứng minh blob tồn tại. Các view có thể chồng lấn; chỉ ratio của
root file biểu diễn phạm vi byte gốc. Backend/whole-document vẫn partial dù
mapping mọi span đã nhận có thể complete. Chi tiết:
[hợp đồng ảnh byte](../../docs/pdf_extraction.md#lossless-byte-images-with-source-offsets).

## Kiểm thử và bằng chứng tổng hợp

Mã cuối: **1455 passed**, hai cảnh báo sklearn single-label đã có,283.27s.
Trong đó **46 ca ảnh byte**, kiểm bằng Pillow độc lập trên PNG do test tự tạo:
mọi giá trị byte, mask/offset, head/tail, object generation7, decoded ObjStm,
partial object prefix, missing buffer, shared quota/dedup, metadata/idempotence,
Markov float32, repaired provenance, parent persistence, CLI và timeout/cleanup.
Các bộ test khác tiếp tục kiểm tra pipeline và các hợp đồng cũ.

Log cuối: `artifacts/tmp/maintenance/extract_pdf/byte_images_release_pytest.log`.
`pip check` không có dependency hỏng; `git diff --check` qua. Lưu log tương ứng
trong cùng domain với tên `byte_images_{pip_check,diff_check}.log`.

Giữ cả các lượt trung gian, không thay kết quả lỗi bằng số cuối:

- Hồi quy ban đầu264 passed,85.94s (`byte_images_regression.log`).
- Suite đầu1453 passed/2 failed,429.72s (`byte_images_full.log`): baseline v9
  của fixture parity chạm wall deadline; ca native chưa tạo checkpoint trong1s.
- Thử baseline v8 cho parity không tương đương vì thiếu metadata JS do v9 bổ
  sung:66 passed/1 failed,21.03s (`byte_images_deadlines.log`). Đã khôi phục v9.
- Parity dùng cùng30s wall/12s CPU/1GiB ở hai phía, giữ so sánh bằng tuyệt đối;
  đây là slack cho fixture, không thay deadline job. Ca checkpoint native tạo
  inventory trước khi bắt đầu deadline1s, tiếp tục kiểm tra giữ dữ liệu và kill
  worker. Sau sửa fixture:67 passed,23.25s (`byte_images_parity.log`), rồi suite
  cuối1455 passed. Không sửa cap production hoặc bỏ assertion parity.

Các fixture cuối được giữ dưới
`artifacts/tmp/maintenance/extract_pdf/byte_images_release_fixtures/`, mỗi fixture
có `bundle.json`, byte nguồn `.bin` và thư mục `blobs/`. Bundle root giữ nguyên
đường dẫn scratch ở provenance lúc tạo; file checks ghi ánh xạ sang vị trí lưu
bằng chứng sau kiểm thử. Mọi blob được so SHA khi đối chiếu pixel.

| Fixture | Source view / tile PNG | PNG bytes duy nhất | Kiểm tra |
| --- | ---: | ---: | --- |
| Root tự sinh585 byte, JS syntax và private stream trơ | 7 / 7 | 1181 | Mọi pixel khớp byte original/decoded đã xác minh; mọi padding offset null; parent persisted; không nguồn unmatched |
| Root chứa PDF con tự sinh, JS syntax và private stream con trơ | 9 / 9 | 1943 | Pixel original/decoded/artifact khớp; artifact và decoded stream con giữ đúng child document identity; không gán original offset cho decoded/artifact; parent persisted |

Fixture root là đầu ra test parity với cap30s/12s/1GiB. Fixture nested là phép
kiểm maintenance bổ sung sau suite, dùng đúng20s/12s/1GiB và model Arlington đã
khóa; không tính thêm vào1455 tests. Nó được tạo bằng `pdf_fixture` trong
`tests/test_byte_images.py`: child=`pdf_fixture(child=b'inert nested bytes',
js=True)`, root=`pdf_fixture(child=child,js=True)`. Sau `extract_pdf`, kiểm bundle,
so PNG decoded pixels với từng source span và xác minh namespace con. Checks:
`byte_images_release_fixture_checks.json` và `byte_images_release_nested_checks.json`
trong domain maintenance/extract_pdf. Safety flags đều false, worker cleanup
thành công. Đây không phải kết quả latency/RAM hay coverage của corpus thật.

## Arlington thật đã khóa

Git SHA đầy đủ: **`b7d880b7a3d3c8f505c025f17763397475e90503`**.
Nguồn `https://github.com/pdf-association/arlington-pdf-model`, snapshot
`third_party/arlington-pdf-model/`, loader đọc `tsv/latest` tại đó.
`configs/arlington.lock.json` xác minh610 TSV,3976 dòng và LICENSE/NOTICE với
checksum/size/Git tree; không dùng HEAD hay fixture thay model.

Lượt smoke mới với pipeline ảnh byte:
`run_20261015T183541635200Z_7d02abdb85da`.
[Evidence model](../experiments/arlington_model_verify/run_20261015T183541635200Z_7d02abdb85da/arlington_verification.json).
Mỗi fixture chạy cap20s/12s/1GiB, tất cả assertions kiểm chứng riêng đều qua,
5 view/5 tile, không nguồn unmatched, parent transport verified_not_persisted.
Không yêu cầu persistence ở lệnh smoke này nên không báo PNG đã lưu.

| Fixture | Rule checks | Pass | Fail | Indeterminate |
| --- | ---: | ---: | ---: | ---: |
| blank_page | 301 | 268 | 6 | 27 |
| wrong_catalog_type | 301 | 266 | 10 | 25 |
| direct_pages | 727 | 641 | 20 | 66 |
| unknown_key | 302 | 268 | 6 | 28 |

Fail/indeterminate được giữ nguyên, gồm fixture cố ý sai kiểu/directness và
predicate/context chưa hỗ trợ. Assertions qua không có nghĩa mọi rule qua hay
PDF đã đạt conformance đầy đủ. Nested fixture cũng xác minh dùng đúng model
thật. Aggregate checks: `byte_images_arlington_checks.json`.

Môi trường hiệu lực: Python3.11.17, pikepdf10.17.0/QPDF12.4.2,
PyMuPDF1.26.7/MuPDF1.26.12, pypdf6.18.1, esprima4.0.1,
zlib compile/runtime1.3.2, Pillow12.3.0, torch2.11.0+cpu,
torchvision0.26.0+cpu, CUDA build null. Tái dùng `.venv` đã được cài từ pyproject
ở lượt native-parser; không thêm dependency hay nhận là fresh install lần này.
Pillow là test oracle đã có trong stack torchvision; encoder runtime chỉ dùng
standard library. Evidence: `byte_images_environment.json`.

## Job offline và provenance

Job mới chỉ metadata: **`run_20261015T182643376917Z_7d02abdb85da`**, khóa214 tệp
mã/cấu hình, thuật toán/limits ảnh byte, zlib, native/package versions và model
Arlington thật. Lock SHA256:
`8d9faa42f83f64db445d3279c634a020ec32a54afd4c523ea61179d2f2f5f052`.
Giữ nguyên chính xác64 dòng từ job JS trước đó:32 Train/32 exposed Validation,
16 mỗi lớp trong từng partition, seed42; không chọn Test hoặc tạo split mới.

| Manifest | Đường dẫn | SHA256 |
| --- | --- | --- |
| Split | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| Source | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| Normalization | `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

[Preparation evidence](../experiments/pdf_extraction_prepare/run_20261015T182643376917Z_7d02abdb85da/run_summary.json)
và `byte_images_job_check.log` xác nhận metadata_verified/PDF bytes not read.
Không dùng job cũ sau source/environment drift. Job mới cũng chỉ được chạy từ
code sạch đã commit khớp lock, ở console LAB sau khi xác nhận cô lập.

Lệnh tái lập các kiểm tra an toàn, chạy từ repo root:

```bash
TMPDIR="$PWD/artifacts/tmp/tests" MPLBACKEND=Agg OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 .venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pip check
git diff --check
.venv/bin/python scripts/23_arlington_model.py smoke
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T182643376917Z_7d02abdb85da
```

139 tệp baseline ngoài phạm vi sửa giữ nguyên SHA;638068 byte đầu của research
log giữ nguyên trước các append mới. README/AGENTS/pyproject và báo cáo cũ không
bị sửa trong increment này. Không stage/commit; blob/source fixture và snapshot
reference đều ignored. Dọn sáu basetemp của lượt này sau khi giữ evidence; không
dọn thư mục người dùng hoặc lượt khác. Chi tiết cuối:
`byte_images_preservation.json`, `byte_images_release_checks.json`.

## Phần chưa nghiệm thu

Chưa đọc/hash/parse PDF thật trong lượt này, chưa chạy21 partial hay đo detector.
F1/MCC/ECE/Brier N/A vì không có classifier/partition nghiên cứu được đánh giá;
Label1 là malicious, quy ước ECE10 equal-width bins, p=1 thuộc bin cuối.

Child raw forensic objects/inventory-only streams chưa được định tuyến đầy đủ;
media/font/image decoders, steganography, page render/text/OCR/QR và whole-format
coverage chưa được chứng minh. JS/XFA vẫn static subset. Runtime/emulation,
Reader/CAPE và reingestion động cần phạm vi môi trường riêng. LAB console chưa
xác nhận NIC/shared folders/clipboard/drag-and-drop/credentials đã cô lập; không
tự ngắt NIC SSH. [Kiểm kê toàn kế hoạch](../../plans/extract-pdf/acceptance.md)
tiếp tục giữ các mục chưa hoàn tất.
