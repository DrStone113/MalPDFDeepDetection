# Kiểm kê nghiệm thu toàn bộ kế hoạch extract-pdf

Review an toàn2026-10-19 thay thế mặc định VM không giới hạn: API/CLI mặc định
hữu hạn, batch một worker và đường chạy PDF theo đường dẫn bị chặn trên Windows.
Thử local chỉ dùng fixture được rà soát. Chế độ `vm` lịch sử vẫn tồn tại khi
chọn rõ; mọi lượt LAB cần quyền, kiểm tra isolation và ngân sách đã thỏa thuận
theo AGENTS.md. Xem [hợp đồng VM](../../docs/extraction_vm.md) và
[bằng chứng Windows](../../reports/progress/extract_pdf_windows_safety_2026-10-19.md).
Các hàng bên dưới giữ nguyên phạm vi bằng chứng lịch sử, không cấp quyền chạy mới.

Bản tối ưu VM cùng ngày bổ sung checkpoint coalescing, refill worker và resume
có kiểm hash. Lượt 8 PDF tổng hợp đo 44,2914 giây với 1 worker và 21,4817 giây
với 4 worker; evidence/feature giữ nguyên. Ba mẫu Train/Validation thật đối
chiếu bản cũ cũng khớp evidence/feature; không có lượt hoàn tất toàn corpus hay
đánh giá mô hình. Xem [số đo và kiểm chứng](../../reports/progress/extract_pdf_performance_2026-10-18.md).

Đây là danh sách yêu cầu của [kế hoạch gốc](plan.md), không phải tuyên bố hoàn
thành. Test fixture chỉ chứng minh hành vi trên dữ liệu tổng hợp; mọi tiêu chí
PDF thật, telemetry động hay cải thiện mô hình cần bằng chứng riêng. Danh sách
này giữ nguyên phạm vi sáu giai đoạn khi triển khai qua nhiều lượt.

| Yêu cầu | Bằng chứng hiện có | Trạng thái/điều kiện còn thiếu |
| --- | --- | --- |
| Python3.11, pyproject, fresh installation và kiểm tra phụ thuộc | Lượt native-parser tạo venv3.11.17 mới từ pyproject với CPU PyTorch; log install/pip/suite được lưu | Đối chiếu môi trường từng lượt riêng; không coi package/native versions mới giống các lượt trước |
| Ba store, JSON Schema, trạng thái quan sát và nguồn evidence_id | Independent offline Draft2020-12 checks và runtime semantic guards; schema khai báo đúng backend metadata, core shapes đóng, counts/refs/JSON safety;12 store instances từ4 bundle tổng hợp hợp lệ | Có bằng chứng fixture; vẫn cần runtime checks ngoài JSON Schema, chưa đủ bằng chứng cho toàn bộ nhóm đặc trưng/đồ thị và corpus thật |
| Worker giới hạn CPU/RAM/byte/deadline; giữ checkpoint khi nhánh phụ lỗi | `static/profile_worker.py`; fixture IPC/stream và lượt64 thật giữ64 root checkpoints;21 worker bị signal và mọi lỗi vẫn trong mẫu số | Có bằng chứng bảo toàn primary trên cohort khóa; nguyên nhân SIGKILL chưa phân biệt CPU/OOM/khác; process caps không chứng minh containment |
| 21/21 PDF Validation partial: không mất đặc trưng chính | Lượt64 thật `run_20261016T142851774386Z_ba64a514ae5a`; saved audit `run_20261016T151444703769Z_ba64a514ae5a`:21/21 cùng identity/hash/label/split, raw primary và projection173 khớp v9, nulls giữ nguyên; root checkpoints tách7 child checkpoints | Đạt tiêu chí bảo toàn primary cho cohort/code ba64a514ae5a; không suy thành complete extraction hoặc detector gain; mã chỉ mục Arlington mới chưa chạy PDF thật |
| Ba nhánh QPDF, MuPDF, raw forensic độc lập trên byte gốc | Inventory MuPDF dùng native object API, QPDF giữ native object view; raw forensic đọc grammar byte gốc. Fixture chặn pypdf object parser/QPDF/canonical dictionary text trong nhánh MuPDF mới; container/codec và lexer scalar-string vẫn dùng chung | Recovery v8 lịch sử vẫn dùng canonical-text pypdf;2 test worker Linux skipped/3 không chọn trên Windows, không coi caps/process là containment; chưa nghiệm thu corpus thật |
| DifferentialMerger giữ bất đồng object/stream/key/revision | Native/raw selected views, generation/key/value/raw stream, xref context và unresolved scope giữ riêng | Có fixture; revision chỉ gán khi footer/prefix chứng minh; toàn bộ bất đồng chưa có nghiệm thu PDF thật |
| FilterMatrix nhiều tầng và trạng thái mỗi filter | `extraction/filters.py`, `streams.py`; hai bộ test stream | Có năm general filters, predictor, Identity Crypt; media codecs và các context Crypt khác còn thiếu |
| Giữ byte raw/trung gian/prefix, chống bom giải nén | Parent v9 raw transport; decode/output/ratio/metadata caps | Có fixture cho giới hạn và blob identity; retention có trần, chưa đo trên corpus thật |
| RecursiveCarver: PDF/ObjStm/XFA/script/font/image/archive, độ sâu và chống vòng | `extraction/carving.py`, `artifact_exports.py`; `test_recursive_carving.py`: PDF/ZIP lồng nhau, ObjStm/XML/JS, lineage/dedup/checkpoint và ngân sách chung | Có fixture; font/image/media mới nhận dạng rồi unsupported, archive ngoài ZIP và PDF thật còn thiếu; không suy diễn nhãn/activation cho artifact |
| Arlington TSV có nguồn/phiên bản được chốt; key lạ giữ lại | User chọn `b7d880b7a3d3c8f505c025f17763397475e90503`; lock610TSV/3976dòng,LICENSE/NOTICE/checksums; lượt64 thật có35partial/29not_run; chỉ mục dictionary,4 bit predicates/typed Contains và6 fixtures với model thật | Predicate/context chưa hỗ trợ vẫn unknown; chưa đầy đủ conformance/reachability; mã chỉ mục/predicate mới chưa chạy PDF thật; không coi174 call sites hoặc model available là rule/whole-document coverage |
| Object graph/IR: xref, lịch sử, mọi key/value, synthetic null, orphan/dangling | Raw IR giữ node/key/value/array/ref, vị trí nguồn hoặc container, chain/hybrid, khai báo trùng, free/unlisted và synthetic missing targets | Có fixture và trần rõ; không sửa null/reference gốc; catalog reachability/conformance, biên hỏng không xác minh và PDF thật còn thiếu |
| JS/XFA AST, chuẩn hóa biến, khử che giấu, lời gọi API, abstract interpretation | Reuse AST, lexical alpha fingerprint, finite scalar/unknown transfers, branch joins/loop widening và graph caller/site/API có nguồn; fixture PDF/XFA/child/repaired/timeout, giữ parity primary | Có bounded static subset; interprocedural/heap/global scripts, reflection/native/complete SAFE-PDF-style semantics và PDF thật còn thiếu; không thực thi JS |
| Byte images theo khối/object | Lossless gray8 PNG theo file/object/decoded/artifact, offset theo namespace, mask padding, head/tail round robin, quota và parent persistence; `test_byte_images.py` kiểm pixel độc lập và parity | Có fixture; child raw forensic/inventory-only sources và PDF thật còn thiếu; byte view không chứng minh page/media/steg coverage; Markov probabilities giữ nguyên |
| Page render/text bbox/hidden text/OCR/QR/anchor–URI | Chưa triển khai | Render chưa được duyệt trong phạm vi hiện tại; cần môi trường riêng |
| TriggerPlanner: document/page/annotation/form/bookmark/Next | Bounded exported-graph/raw-IR planner cho document/page/annotation/field actions, name-tree/XFA declarations, bookmark/link destinations và form proposals; source IDs, DAG/cycle/quota và worker parity có fixture | Có static candidates; XFA DOM selectors, đầy đủ PDF-version/event semantics, destination/widget feasibility và corpus thật chưa nghiệm thu; mọi event not_run |
| JS emulator: Acrobat DOM, eval/unescape traces, natural/forced riêng | Chưa triển khai | Việc giả lập/thực thi cần phạm vi môi trường riêng trước nghiệm thu runtime |
| Reader/CAPEv2 + Sysmon + INetSim và cấu hình Reader/OS/mạng | Chỉ có hạ tầng parse report/design LAB cũ | Chưa được phê duyệt hoặc thực thi trong lượt phát triển này |
| Reingestor giữ quan hệ run/event/parent artifact | Chưa triển khai cho pipeline mới | Cần hợp đồng dữ liệu và kiểm thử trước kết nối sandbox |
| Export tabular JSONL/Parquet, graph cho downstream | Sáu bảng typed/nullable giữ JSON gốc, round-trip validator, qualified run/occurrence keys; NetworkX multigraph và Torch COO, CLI/API có cap/checksum/failure manifest | Có fixture; native PyG/DGL consumers, scale/corpus thật và benchmark downstream chưa nghiệm thu; không tự fit hay suy nhãn |
| Khóa split/phả hệ và so sánh benign/malicious phù hợp | Job chỉ metadata, seed42, cùng64 Train/Validation, Test loại khỏi selection | Chưa có thiết kế lineage/evasion/dynamic study được khóa riêng |
| Đo evidence gain/filter/event coverage, median/P99/RAM, Inconclusive, Recall@FPR | Lượt64 thật ghi median12.125s/P9915.361s,peak worker RSS396140544bytes;56 resource_limit/3 decode_error/2 partial/1 unsupported/1 encrypted/1 observed | Có số đo diagnostic và nguyên nhân chồng lấp; SIGKILL không chứng minh OOM/CPU cause; chưa đo evidence gain, Recall@FPR, dynamic/event coverage hoặc detector quality |
| Giữ mọi mẫu lỗi trong mẫu số; không chọn/tune trên Test | Job Train/Validation thực tế ghi đủ64,all failures giữ trong status denominator; saved audit xác minh64 identity/hash/label/partition và64 root checkpoints | Đạt cho lượt64 đã khóa; chưa chứng minh toàn bộ threat coverage hoặc nhóm feature mới đầy đủ; không Test/model fitting |
| Plugin interfaces parser/decoder/feature | Explicit source/config-pinned Python registry; parser vào inventory/merger, decoder dùng chung byte budget qua root/child/raw streams, feature batch transactional có nguồn/namespace; fixture kiểm worker import caps và timeout | Có SDK/static fixture; không tự nạp plugin từ PDF, job CIC mặc định tắt; chưa nghiệm thu plugin/codec cộng đồng hoặc corpus thật |
| CLI/thư viện, static worker/container, JS emulator/Compose | Có API/CLI và runner offline | Chưa có containment/container release hoặc full-hybrid một lệnh |
| Feature catalog, architecture, schema docs, adversarial test suite | Có tài liệu foundation và các fixture tổng hợp | Chưa có tài liệu/suite/release bao phủ toàn bộ pipeline |

Toàn bộ các mục còn thiếu phải được đối chiếu lại với mã và evidence hiện tại
trước khi đánh dấu mục tiêu hoàn tất. Không dùng việc chuẩn bị job, checksum
đúng, test xanh hay một nhánh có kết quả để thay cho nghiệm thu toàn hệ thống.
