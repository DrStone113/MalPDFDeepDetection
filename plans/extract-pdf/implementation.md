# Tiến độ thực thi kế hoạch extract-pdf

Kế hoạch tổng thể trong [plan.md](plan.md) được giữ nguyên. Chi tiết mã, hợp đồng
đầu ra và lệnh chạy nằm trong [docs/pdf_extraction.md](../../docs/pdf_extraction.md).
Danh sách nghiệm thu đầy đủ được theo dõi tại [acceptance.md](acceptance.md).

## Phạm vi lượt triển khai 2026-10-15

- [x] Đối chiếu nền tảng v9, bảo toàn thay đổi cục bộ và các chiến dịch cũ.
- [x] Bổ sung ba store liên kết và JSON Schema, trạng thái quan sát, kiểm tra
  danh tính/tham chiếu và phân biệt unknown với zero trong phạm vi đã duyệt.
- [x] Tái sử dụng worker giới hạn tài nguyên/checkpoint; giữ nhánh chính khi
  nhánh phụ lỗi. Thêm profiling byte/bố cục có giới hạn và AST theo từng script.
- [x] Thêm API/CLI cùng cấu hình cho fast-static và deep-static.
- [x] Sinh kế hoạch sự kiện tĩnh từ cạnh có ngữ cảnh hợp lệ; không chạy sự kiện.
- [x] Chuẩn bị job chỉ dùng metadata: manifest đã khóa, Train/Validation, kiểm
  tra nhóm trùng/liên quan, hash code/môi trường và điều kiện offline trước claim.
- [x] Bổ sung kiểm thử tổng hợp và tài liệu; ghi kết quả kiểm tra vào research log.
- [ ] Chạy job PDF thật sau xác nhận cô lập tại console VMware.
- [ ] Nghiệm thu lại 21 mẫu partial lịch sử; chưa có bằng chứng 21/21.

## Phần kế hoạch tổng thể còn lại

Theo yêu cầu tiếp theo của người dùng, bổ sung launcher console/desktop cho job
tĩnh đã khóa: precheck không ghi claim/report, không tự đổi NIC/xóa credentials,
xác nhận tương tác trước khi gọi lại runner có đủ guard. Source launcher Python
và shell được khóa; Codex auth store được chặn theo sự hiện diện. Đây là chuẩn
bị thao tác offline, không phải bằng chứng đã chạy hoặc nghiệm thu PDF thật.

Theo yêu cầu đơn giản hóa, mở launcher tại console khi còn mạng, tự ngắt NIC
trong VMware rồi nhấn Enter. Cửa sổ chờ nếu còn mục chặn môi trường, không bắt
mở lại hoặc gõ hai câu xác nhận. Enter xác nhận cô lập và cho phép dừng agent
cục bộ đã xác minh; chỉ dọn hai biến sau khi tiến trình thoát/socket biến mất,
rồi kiểm lại mọi gate. Không xóa key/token hoặc tự ngắt mạng. PDF thật chỉ chạy
khi đủ điều kiện; việc chờ không tạo claim hoặc gọi job bị chặn.
Đã bổ sung trường hợp agent thoát từ trước nhưng desktop giữ biến cũ: chỉ bỏ
hai biến của launcher khi PID được xác nhận không còn (ESRCH), socket cũng
không có và selection không đổi; không signal hoặc dọn credential khác.

Nghiệm thu forensic trên PDF thật, giải mã native media/archive ngoài ZIP,
catalog reachability/conformance đầy đủ và predicate Arlington còn thiếu, suy luận JS
liên thủ tục/heap đầy đủ, bộ phân tích font/media/hiển thị, emulator/Reader/CAPE, tái nhập hiện vật,
đánh giá đe dọa có nhãn và phát hành cộng đồng/Compose chưa hoàn tất.

Render, thực thi JS và CAPE cần phạm vi môi trường riêng. Không coi chuẩn bị
job, kế hoạch sự kiện hay test fixture là đo lường độ phủ trên PDF thật. RIT
hiện có CSV, không được suy diễn là có PDF gốc cho các đặc trưng mới.

## Bước tiếp theo đã triển khai: FilterMatrix

- [x] Giải mã có giới hạn cho Flate, LZW (EarlyChange0/1), ASCIIHex, ASCII85,
  RunLength; xử lý predictor TIFF/PNG và các alias PDF.
- [x] Lưu metadata từng lớp và byte raw/trung gian/prefix qua bộ lưu do parent
  quản lý; không cấp thêm ngân sách byte/CPU/RAM sau v9.
- [x] Phân biệt stream rỗng thật, lỗi giải mã, codec chưa hỗ trợ và thiếu ngữ
  cảnh Crypt; lớp sau lỗi không được chạy trên prefix chưa hoàn chỉnh.
- [x] Tích hợp vào deep-static và job offline, kiểm tra nguồn object/generation/
  backend/hash; giữ nguyên đặc trưng và bằng chứng primary/v8/v9.
- [ ] Chạy nghiệm thu trên PDF thật sau khi LAB được cô lập tại console.
- [ ] Bổ sung media decoder và đối chiếu raw forensic/lịch sử đầy đủ.

Chi tiết giới hạn và các kiểm thử ở
[Additive stream decoding](../../docs/pdf_extraction.md#additive-stream-decoding).

## Bước tiếp theo đã triển khai: RecursiveCarver

- [x] Định tuyến byte giải mã hoàn chỉnh theo magic/ngữ cảnh; PDF con, ZIP
  stored/deflate, cú pháp ObjStm, XFA/XML và JS AST không thực thi.
- [x] Giới hạn độ sâu/số lượng/byte/metadata, hash chống vòng và tái dùng nội dung;
  giữ đủ từng lineage và checkpoint; không cấp lại CPU/RAM/thời gian/ngân sách.
- [x] Xuất đặc trưng PDF con với namespace riêng, kế thừa nguồn repaired và giữ
  nguyên đặc trưng gốc; hành động con không sinh sự kiện mở PDF gốc.
- [x] Test fixture ZIP/PDF tổng hợp, CRC/descriptor, XML/ObjStm, shared budget,
  timeout/cleanup và nguồn bằng chứng; tài liệu ở
  [Bounded recursive artifacts](../../docs/pdf_extraction.md#bounded-recursive-artifacts).
- [ ] Decoder font/image/media, archive khác và full forensic carving.
- [ ] Nghiệm thu PDF thật/21 mẫu partial; chưa xác nhận cô lập LAB tại console.

## Bước tiếp theo đã triển khai: kiểm kê native và DifferentialMerger

- [x] QPDF qua pikepdf được khai báo; kiểm kê QPDF/MuPDF/pypdf từ cùng byte
  gốc, sau checkpoint legacy/filter/carver; không tạo hay truyền PDF repaired.
- [x] Giữ generation đã biết, offset chỉ khi khớp header, compressed-container
  metadata, hash key/value/stream và trạng thái lỗi/giới hạn từng nhánh.
- [x] Merger giữ bất đồng, không chọn parser thắng; generation MuPDF vẫn null,
  thiếu trong enumeration lỗi không trở thành absence, Decimal QPDF không ép float.
- [x] Kiểm thử fixture native, checkpoint/timeout, parity primary và trần tài nguyên;
  tạo venv Python3.11 mới từ pyproject thay vì suy từ venv được giữ trước đây.
- [x] Grammar byte độc lập, xref table/stream/hybrid, trailer/Prev, membership và
  tham chiếu theo context; ordinal chỉ khi có bằng chứng footer/prefix.
- [ ] Loại phụ thuộc parser cú pháp pypdf của adapter canonical-text MuPDF;
  định tuyến object chỉ mới thấy ở inventory sang graph/filter/carver.
- [ ] Nghiệm thu PDF thật và bộ ba QPDF/MuPDF/raw theo toàn bộ kế hoạch.

## Bước tiếp theo đã triển khai: RawForensicParser và IR

- [x] Lexer/object grammar không gọi native reader/parser; giữ mọi key/value
  trong trần IR, escaped names, literal/hex strings, số chính xác và duplicate keys.
- [x] Giữ từng khai báo vật lý trùng object/generation; xác minh biên stream từ
  Length trực tiếp hoặc reference nhất quán qua chain; không quét payload thành object.
- [x] Đọc xref table/stream, Index/W, hybrid supplement, Prev/cycle/free entries;
  decode XRef/ObjStm bằng pool byte còn lại và giữ checkpoint từng lớp.
- [x] IR/static references có evidence_id, synthetic node cho target thiếu và
  provenance container/decoded offset; raw null/reference không bị sửa.
- [x] Đối chiếu raw selection với native; membership/orphan chỉ trong scope đã
  kiểm tra, không chọn parser thắng hay suy nhãn mã độc.
- [x] Revision locator chỉ có ordinal khi footer và các body phụ thuộc nằm trọn
  trong prefix được kiểm tra; linearization/chain hop không tự thành revision.
- [ ] PDF thật/21 partial, Arlington conformance, catalog reachability và các
  vùng hỏng có biên không thể xác minh vẫn chưa nghiệm thu đầy đủ.

## Bước tiếp theo đã triển khai: Arlington đã khóa và rule engine

- [x] Theo chỉ định người dùng, tải reference công khai ở `b7d880b`, resolve Git
  thành `b7d880b7a3d3c8f505c025f17763397475e90503`; giữ LICENSE/NOTICE.
- [x] Lock 610 TSV/3976 dòng tại đường dẫn third_party đã duyệt; so checksum,
  danh sách file và Git tree trước khi dùng offline; không fallback HEAD/fixture.
- [x] Interpreter AST có giới hạn và unknown ba giá trị; kiểm tra kiểu/required/
  version/directness/possible values/link OR trên raw IR đã cache, giữ key lạ.
- [x] Giữ nguồn inherited/default ảo, null/reference/primary gốc, candidate scope
  và checkpoint; job metadata khóa luôn model provenance và từ chối drift.
- [x] Test tổng hợp độc lập snapshot; kiểm chứng riêng với model thật đã khóa
  bằng bốn fixture tự sinh, có evidence và run register riêng.
- [ ] Predicate/path/extension chuyên biệt, đầy đủ conformance/reachability và
  nghiệm thu PDF thật/21 partial; chưa tuyên bố hoàn tất giai đoạn3.

## Bước tiếp theo đã triển khai: ngữ nghĩa JS/XFA tĩnh

- [x] Observer worker giữ AST đã kiểm tra, dedup bằng decoded SHA; không parse
  hoặc decode thêm cho nhánh này, giữ nguyên summary/đặc trưng primary/v8/v9.
- [x] Chuẩn hóa scope/binding và fingerprint alpha; biến tự do/property/literal
  giữ identity riêng, không dùng fingerprint để thay split hay chứng minh file trùng.
- [x] Domain finite/unknown, ghép chuỗi và toán tử scalar có giới hạn, join nhánh,
  short circuit và widening vòng lặp; không lặp cụ thể, không gọi hàm JS/builtin.
- [x] Graph caller/site/API hoặc hàm cục bộ; tách spelling/conditional target/
  excluded/uninvoked/unknown, giữ nguồn XFA/PDF con và repaired/mixed provenance.
- [x] Chạy sau checkpoint các nhánh cũ với cap CPU/RAM/wall dùng chung; test
  scope, finite-set, metadata, timeout và source-linked serialization tổng hợp.
- [ ] Interprocedural/heap/shared-global semantics, reflection/DOM/native đầy đủ,
  nghiệm thu corpus/21 partial và lớp emulator động còn thiếu; giai đoạn3 chưa xong.

## Bước tiếp theo đã triển khai: ảnh byte theo khối/object

- [x] PNG gray8 lossless từ byte gốc/object/decoded/artifact đã được chấp nhận;
  mask padding, offset file hoặc container riêng, generation/repaired giữ nguồn.
- [x] Chọn head/tail theo khối, round robin nguồn, trần pixel/tile/source/cache/
  metadata; không parse/decode PDF thêm, không cấp lại CPU/RAM/retention.
- [x] Blob PNG qua parent raw transport chung; CLI lưu tùy chọn vào thư mục
  ignored mới, tách encoded/verified/persisted, không suy file tồn tại từ hash.
- [x] Kiểm pixel bằng decoder độc lập trên PNG tự sinh, offset nguồn/ObjStm,
  quota/timeout/cleanup và parity primary/v8/v9/float32 Markov.
- [ ] Child raw forensic/inventory-only sources và corpus/21 partial chưa nghiệm
  thu; page render/OCR/QR cần môi trường riêng; không tuyên bố xong giai đoạn3.

## Bước tiếp theo đã triển khai: exporter tabular và graph

- [x] Sáu bảng JSONL/Parquet schema cố định, typed nullable projections và JSON
  original; giữ bool/int/float/null, bigint overflow, locator/filter/repaired,
  coverage/backend metadata và toàn bộ envelope. Có validator khôi phục bundle.
- [x] Mỗi input/retry có khóa export/occurrence riêng, giữ duplicate hashes và
  sample lỗi/null identity; không dedup, điền thiếu, chọn partition hay fit model.
- [x] Directed multigraph NetworkX node-link, giữ cạnh trùng/self-loop/isolates
  và original records; Torch COO cùng thứ tự và số node tường minh.
- [x] CLI/API chỉ đọc JSON bundle explicit, không theo raw/blob/URL references;
  output ignored bất biến, cap byte/row/depth và manifest failed/interrupted.
- [ ] Native PyG/DGL consumer, corpus thật, measured scale/downstream benchmark
  và container/hybrid/community release còn thiếu; toàn bộ kế hoạch chưa hoàn tất.

## Bước tiếp theo đã triển khai: kiểm chứng hợp đồng/schema độc lập

- [x] Draft2020-12 oracle từ dev dependency đã khai báo, registry không tải
  reference ngoài; kiểm metaschema, shape hợp lệ/sai và source bundle tổng hợp.
- [x] Schema backend khai báo version/scope/model/graph thực tế; core fields vẫn
  đóng, không bỏ metadata để đạt validation hoặc nới toàn bộ additional fields.
- [x] Runtime giữ thêm count/identity/reference/completion/type/JSON-safety
  invariants; malformed metadata bị từ chối rõ, không coerces/drops hoặc đổi0.
- [x] Schemas là các JSON tree độc lập; kiểm12 stores từ4 bundle đã lưu, giữ
  nguyên source. Dataset/Test không được truy cập từ phép kiểm này.
- [ ] Nghiệm thu corpus thật, toàn bộ nhánh và dynamic/hybrid vẫn còn mở;
  schema-valid không phải bằng chứng conformance hay exploit detection.

## Bước tiếp theo đã triển khai: SDK plugin tĩnh

- [x] Ba ABC parser/decoder/feature và registry Python explicit; khóa source
  SHA/path/version/config hash/seed, không suy module từ PDF, không auto-install.
- [x] Truyền JSON qua spawn, import/constructor/method sau OS caps; parser vào
  inventory/merger, decoder dùng chung filter ledger qua root/child/raw structural.
- [x] Feature dùng context/cache đã giữ, batch transactional có namespace/source,
  repair propagation, global quotas và giữ checkpoint khi lỗi/timeout.
- [x] Fixture tổng hợp kiểm extension thật qua worker, giới hạn và parity primary;
  hướng dẫn [contributing_plugins](../../docs/contributing_plugins.md).
- [ ] Plugin/codec cộng đồng, corpus thật, container/Compose, dynamic/hybrid và
  toàn bộ sáu giai đoạn vẫn chưa nghiệm thu; job CIC hiện khóa plugins rỗng.

## Bước tiếp theo đã triển khai: TriggerPlanner tĩnh mở rộng

- [x] Ánh xạ route theo owner document/page/annotation/field; nhận graph name-tree
  và XFA event/script đã có, không parse/decode/AST thêm hoặc chạy sự kiện.
- [x] Dùng raw IR công khai của latest xref đã xác minh cho bookmark First/Next/
  Parent, destination links và input proposals AcroForm; giữ hash/source IDs.
- [x] Phân biệt DAG/cycle, duplicate Root evidence nhất quán với tham chiếu mâu
  thuẫn, root/owner/backend/repaired provenance và quota chung có prefix rõ.
- [x] Fixture graph/native/raw/worker kiểm các tuyến mới, source refs, I/O-denial
  và primary/code/v8 parity; [hợp đồng event](../../docs/trigger_plans.md).
- [ ] XFA DOM selectors, destination/widget/runtime feasibility, corpus thật,
  emulator/Reader/CAPE/reingestion và nghiệm thu toàn bộ event families còn mở.
