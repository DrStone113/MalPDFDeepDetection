# TriggerPlanner và gói handoff LAB, 2026-10-16

Đã mở rộng kế hoạch sự kiện tĩnh từ graph/raw IR đã xuất, kiểm thử qua worker,
và chuẩn bị gói handoff theo yêu cầu người dùng. **Chưa chạy PDF thật** hoặc
21 partial lịch sử. Toàn bộ kế hoạch sáu giai đoạn còn mở; không đánh dấu code/
package chuẩn bị là nghiệm thu corpus hoặc thực thi động.

Maintenance ID: `run_20261016T072741800632Z_7d02abdb85da`.
Generating commit: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, worktree dirty.
Lượt làm việc bị ngắt rồi tiếp tục lúc10:25 UTC; kiểm tra không có log của lệnh
pytest bị ngắt trước đó, sau đó mới khởi chạy kiểm thử. Run ID ban đầu giữ nguyên.
Không stage/commit, thay đổi NIC hoặc đọc giá trị credentials.

## Hành vi và giới hạn

[triggers.py](../../src/malpdf/extraction/triggers.py) phân loại action theo
document/page/annotation/field, thêm visit-page, nhận graph JavaScript name-tree
và event/script XFA đã có. [trigger_ir.py](../../src/malpdf/extraction/trigger_ir.py)
đọc public IR cho bookmark First/Next/Parent, OpenAction/destination links,
field text/choice/button proposals và catalog action còn thiếu trong graph cũ.
Không thêm PDF/XML/AST parse, giải mã, mở file/URL hoặc thực thi sự kiện.

Planner yêu cầu đúng root digest/owner kinds/backend, latest raw xref context,
object/generation/selected membership và boundary/container lineage. Bằng chứng
Root trùng nhưng nhất quán giữ các ID nguồn; tham chiếu mâu thuẫn hoặc object
lịch sử không được thay thế cho selected object bị thiếu. Parent bookmark sai,
vòng/reuse, A/Dest mâu thuẫn, edge/array metadata hỏng đều giữ reason rõ.
Shared DAG không bị coi là cycle; DFS nhận cả cycle qua nhiều nhánh.

Tất cả sự kiện có ID nguồn, repaired provenance, `execution_status=not_run` và
`runtime_feasibility=unverified`. `action_id` có thể null cho XFA/navigation/input.
Destination/Reader coordinates và DOM/SOM selectors chưa được xác minh; field
inheritance theo Kids chỉ là ancestor candidate nếu chưa có khai báo trực tiếp.
Không điền chữ ký; field flags/options/visibility/editability vẫn unknown.
Không xuất title/field name/script name/URI hoặc nội dung script trong plan.
Xem [hợp đồng đầy đủ](../../docs/trigger_plans.md).

Algorithm `static-events-v2`, envelope mở rộng `pdf-trigger-plan-v1`.
Mặc định128 events/128 actions mỗi chain,32768 nodes/65536 edges/150000 bước
chung/512 supporting IDs/512KiB metadata. BFS queue được chặn bằng visited state,
các lượt graph/raw dùng chung quota. Metadata guard giữ prefix sự kiện nguyên
vẹn và status partial/resource-limit. `traversal_complete` không chứng minh
whole-document hoặc event coverage. Planner chạy metadata ở parent sau worker;
không nhận là OS worker caps áp dụng cho bước parent này.

## Kiểm thử và evidence đã giữ

**1662 passed**, hai cảnh báo sklearn single-label đã có,203.47s.
Log cuối: `artifacts/tmp/maintenance/extract_pdf/triggers_full.log`.
54 ca mới collect riêng; lượt contract53 passed/3.73s trước ca worker cuối,
hồi quy90 passed/7.66s. Lượt đầu202 passed/2 failed do helper test ép root ID
literal `original:<hash>` thay vì chấp nhận v9 immutable root với cùng digest;
đã sửa theo invariant danh tính nguồn, không bỏ kiểm tra. Giữ tất cả logs.
`pip check`/`git diff --check` đạt; không thêm dependency hoặc tăng resource cap.

Các ca:24 ánh xạ event theo owner, owner/backend guards, nguồn repaired,
đường dẫn ngoài root, DAG/cycles, quotas, bookmark/destination/field proposals,
name-tree/XFA declarations, compressed objects/XRef streams, reference conflict,
array/route metadata hỏng và I/O denial. Worker fixture giữ nguyên primary
features/code/v8 so với baseline trên cùng bytes,1GiB/12s CPU/30s wall. Cấu hình
job thật vẫn1 worker/20s wall/12s CPU/1GiB address-space/10MiB input.

Bundle tổng hợp giữ tại
`artifacts/tmp/maintenance/extract_pdf/triggers_fixture_bundle.json`, SHA256
`9e0f775042e541aaae228940ce1337ae29360ee05089401f0ee71c0a9431f434`.
365 evidence nodes,644 features,456 edges;6 events thuộc5 nhóm:
open-document1,close-document1,XFA1,bookmark2,form-input1. Ba public schemas
Draft2020-12 độc lập và runtime validator đều hợp lệ. Mọi supporting/target ID
resolve; không có reason trong traversal fixture, vẫn partial về runtime scope.

Sau khi preload module mã, audit hook chặn open/socket/subprocess/process/ctypes
operations trong lúc lập lại plan: không có operation nào bị gọi, output y hệt
plan worker và bundle gốc không đổi. Đây là kiểm metadata, không phải containment
hoặc bằng chứng không-network cho parser. Plan17,204 compact JSON bytes; lưu
riêng `triggers_fixture_plan.json`/`triggers_fixture_checks.json` cùng domain.
Worker fixture hoàn tất3.52s, peak RSS376852480 bytes, cleanup=true; exit -9 giữ
nguyên sau cleanup, không suy OOM chỉ từ mã thoát. Không dự báo runtime corpus.

Exporter round-trip thực tại
`data/processed/pdf_extraction_exports/run_20261016T103655803447Z_7d02abdb85da/`:
JSONL/Parquet sáu bảng khôi phục chính xác cả plan/null action IDs; NetworkX giữ
365 nodes/456 edges, Torch COO2×456. Có14 files/4207868 data bytes có checksum;
không theo PDF/blob references. `triggers_export_checks.json` ghi bằng chứng.

Tái dùng `.venv` Python3.11.17 từ pyproject; không nhận là fresh venv mới hoặc
đã kiểm Python3.13. Package/native versions ở `triggers_environment.json`.

## Job, manifest và Arlington thật

Job **`run_20261016T103345122630Z_7d02abdb85da`**,220 source/config files;
lock SHA256 `a676499e6923c97ee96e8f74c1dd085cc78035781a7db70f198cd93188030e15`.
Job trước từ chối source drift; job mới qua metadata check, giữ nguyên chính xác
64 dòng32 Train/32 exposed Validation,16 mỗi lớp mỗi partition,seed42. Không
chọn Test, không regenerate split. Fingerprint khóa planner version/limits.

| Manifest | Đường dẫn | SHA256 |
| --- | --- | --- |
| Split | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| Source | `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| Normalization | `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

Prepare/load xác minh Arlington thật tại
**`b7d880b7a3d3c8f505c025f17763397475e90503`**, **610 TSV/3976 rows**,
LICENSE/NOTICE/checksum/Git tree đều đúng; không chuyển HEAD hay fallback fixture.
Việc này kiểm dependency thật; unit tests vẫn chỉ dùng fixture, và worker fixture
không phụ thuộc snapshot ngoài. Evidence ở `triggers_job_checks.json` và
[prepared run](../experiments/pdf_extraction_prepare/run_20261016T103345122630Z_7d02abdb85da/run_summary.json).

## Handoff theo yêu cầu chuyển sang LAB

Người dùng cho biết chưa sẵn sàng console và yêu cầu chuẩn bị gói offline trước.
Đã tạo gói metadata/runbook cho **repo LAB hiện có**, không phải installer độc lập:

- Archive: `artifacts/tmp/maintenance/extract_pdf/offline_handoff/run_20261016T104455061938Z_7d02abdb85da.tar.gz`.
- SHA256: `6fe7a89350877bb3c36fb5e5eb85ac28d40b17ae491c80917822564acc8f395e`.
- 122559 bytes,10 files; checksum archive/từng file và copied job lock đều đúng.
- Có `RUNBOOK.vi.md`, job/config/provenance/environment/preflight; không chứa PDF,
  source tree, wheels hoặc model weights. Job chứa sample metadata nên giữ private.
- Không có launcher tự chạy hoặc thay NIC. Không upload gói ra dịch vụ ngoài.

[Handoff summary](../deployment/pdf_extraction_offline/run_20261016T104455061938Z_7d02abdb85da/handoff_summary.json)
và `triggers_handoff_checks.json` ghi trạng thái thật: metadata hợp lệ, repo dirty,
console attestation chưa có. Chạy thật còn chờ **mã sạch đã commit** theo AGENTS.md
và **xác minh cô lập tại VMware console**, không SSH/agent/credentials. Kiểm presence
chỉ đọc tên/trạng thái, không đọc/in secret values; không mặc định LAB sạch.
Không tự ngắt NIC của SSH. [Hướng dẫn chuyển console](../../docs/extraction_lab_handoff.md)
giải thích thứ tự chuẩn bị, precheck, run một lần và giữ partial evidence.

## Bảo toàn và phần chưa nghiệm thu

198 files baseline được đối chiếu;10 files thay đổi đúng phạm vi docs/plan/
triggers/jobs/log,188 files còn lại giữ SHA. Giữ652822 bytes prefix research log
trước append. Dọn ba thư mục basetemp đã tạo sau khi giữ evidence/logs; prefix
contract không phát sinh thư mục vì lượt53 ca không dùng tmp_path. Không
động vào README/AGENTS, source data, môi trường hoặc output/report lịch sử.
`triggers_preservation.json`/`triggers_release_checks.json` giữ final checks.

Chưa có PDF thật/21-partial result, đầy đủ event/version semantics, XFA DOM
selectors, destination/widget/Reader feasibility hoặc classifier gain. Render,
JS emulator/execution, Reader/CAPE và reingestion vẫn ngoài phạm vi hiện tại.
Các mục forensic/codec/semantics/container/community khác trong
[acceptance](../../plans/extract-pdf/acceptance.md) vẫn mở. Metrics F1/MCC/ECE/
Brier N/A: không đánh giá model/partition; Label1=malicious,ECE10 equal-width
bins,p=1 trong bin cuối.
