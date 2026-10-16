# Kế Hoạch Tổng Thể Xây Dựng Hệ Thống Trích Xuất Đặc Trưng & Bằng Chứng PDF Toàn Diện (Static & Dynamic PDF Feature Extractor)

## 1. Tầm Nhìn, Mục Tiêu & Giá Trị Đóng Góp Cho Cộng Đồng

Hệ thống hướng tới việc xây dựng một bộ khung trích xuất bằng chứng và sinh đặc trưng PDF mã nguồn mở chất lượng cao, giải quyết trực tiếp khoảng trống giữa các công cụ quét từ khóa bề nông và các hệ thống phân tích động nặng nề. Thay vì giới hạn ở vài chục trường đếm cố định như [PDFiD](https://www.google.com/search?q=https%3A%2F%2Fblog.didierstevens.com%2Fprograms%2Fpdf-tools%2F) hay phụ thuộc vào một thư viện đọc duy nhất dễ bỏ sót cấu trúc dị biệt như nghiên cứu [Extract Me If You Can](https://www.google.com/search?q=https%3A%2F%2Fwww.cs.ucr.edu%2F%7Eheng%2Fpubs%2Fpdfmalware_ndss16.pdf) đã chỉ ra, dự án đặt trọng tâm vào việc **thu thập tối đa mọi đặc trưng tĩnh và động có thể quan sát được kèm theo ngữ cảnh nguồn gốc và trạng thái độ phủ**.

### Ba trụ cột đóng góp cốt lõi cho cộng đồng bảo mật và học máy

- **Kiến trúc hướng bằng chứng và trạng thái quan sát (Evidence-First & Coverage-Aware):** Mọi đặc trưng sinh ra đều liên kết ngược về object ID, số thế hệ (generation number), byte offset, chuỗi filter và parser thực hiện, đồng thời phân biệt minh bạch giữa không tồn tại đặc trưng (`absent_within_scope`) với lỗi giải mã hoặc giới hạn công cụ (`partial`, `decode_error`, `unsupported`, `encrypted`, `timeout`).
- **Đối chiếu đa cơ chế phân tích và bảo toàn bất đồng (Differential Multi-Parser Analysis):** Kết hợp nhiều parser độc lập cùng bộ quét cú pháp thô để phát hiện kỹ thuật che giấu tên, xung đột bảng tham chiếu chéo (`xref`), cập nhật tăng dần (incremental updates) và giữ lại toàn bộ sự khác biệt giữa các engine làm tín hiệu phát hiện mã độc.
- **Chu trình khép kín giữa phân tích tĩnh, mô hình chuẩn và kích hoạt động hướng sự kiện (Closed-Loop Static-to-Dynamic Pipeline):** Sử dụng danh mục máy đọc được từ [Arlington PDF Model](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpdf-association%2Farlington-pdf-model) dựa trên đặc tả [ISO 32000-2](https://www.google.com/search?q=https%3A%2F%2Fpdfa.org%2Fresource%2Fiso-32000-2%2F) để mở rộng độ phủ tĩnh, sau đó dùng chính đồ thị cấu trúc thu được để sinh kịch bản kích hoạt cho tầng giả lập JavaScript và tầng Reader thật trong [CAPEv2](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fkevoreilly%2Fcapev2), rồi đưa các hiện vật giải mã lúc chạy quay ngược về tầng phân tích tĩnh.

## 2. Kiến Trúc Tổng Thể & Cấu Trúc Dự Án

### Luồng xử lý khép kín 8 bước

1. **Tiếp nhận & Phân tích Byte thô (Raw Byte & Layout Profiling):** Tính toán phân bố byte, entropy theo cửa sổ trượt, byte n-grams, cấu trúc header/EOF và phát hiện vùng dữ liệu nằm ngoài phạm vi đối tượng chuẩn (carving vùng ẩn trước `%PDF-` hoặc sau `%%EOF`).
2. **Phân tích Tĩnh Đa Parser (Multi-Engine Static Parsing):** Chạy song song trên bản gốc tuyệt đối (không ghi đè bằng bản `repair`) qua ba nhánh độc lập gồm họ [QPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fqpdf%2Fqpdf) ([pikepdf](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpikepdf%2Fpikepdf)), họ [MuPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FArtifexSoftware%2Fmupdf) ([PyMuPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpymupdf%2Fpymupdf)) và nhánh phân tích cú pháp thô phục vụ điều tra theo hướng [pdf-parser.py](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDidierStevens%2FDidierStevensSuite%2Fblob%2Fmaster%2Fpdf-parser.py).
3. **Giải mã Stream Đa tầng & Đệ quy Hiện vật (Multi-Layer Stream Decoding & Recursive Carving):** Giải nén từng bước theo chuỗi filter, ghi nhận trạng thái riêng cho từng filter và tự động định tuyến đệ quy nếu nội dung sau giải nén là PDF lồng nhau, luồng đối tượng (`/ObjStm`), XFA, script, font, ảnh hoặc file đính kèm.
4. **Xây dựng Đồ thị Cấu trúc & Kiểm chứng Arlington (Object Graph & Specification Mapping):** Dựng đồ thị tham chiếu đối tượng (Object Reference Graph), đối chiếu mọi dictionary/array/key với [Arlington PDF Model](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpdf-association%2Farlington-pdf-model), bảo toàn toàn bộ các key lạ ngoài chuẩn và đánh dấu rõ những node suy dựng (`synthetic`) khi thiếu tham chiếu đích.
5. **Phân tích Ngữ nghĩa Mã nguồn & Nội dung Hiển thị (Semantic Script & Visual Analysis):** Trích xuất AST, chuỗi ghép, lời gọi API và suy luận trừu tượng (abstract interpretation) theo hướng [SAFE-PDF](https://www.google.com/search?q=https%3A%2F%2Farxiv.org%2Fabs%2F1810.12490) đối với JavaScript/XFA; đồng thời kết xuất trang để trích xuất văn bản, tọa độ, lớp ẩn, OCR, mã QR và độ lệch giữa văn bản hiển thị với đích URI.
6. **Lập Kịch bản Kích hoạt & Giả lập JavaScript có Giám sát (Event-Driven JS Emulation & Forced Execution):** Từ danh sách `/OpenAction`, `/AA`, sự kiện biểu mẫu và chuỗi `/Next`, sinh kịch bản sự kiện để chạy trong môi trường mô phỏng API Acrobat kết hợp khám phá đa nhánh theo hướng [JSForce](https://www.google.com/search?q=https%3A%2F%2Farxiv.org%2Fabs%2F1701.07860) (gắn nhãn tách biệt nhánh bị ép chạy).
7. **Thực thi trên Reader Thật trong Môi trường Giám sát (Sandboxed Native Reader Execution):** Mở mẫu gốc trong máy ảo Windows quản lý bởi [CAPEv2](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fkevoreilly%2Fcapev2) kèm [Sysmon](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fsysinternals%2Fdownloads%2Fsysmon) và mạng giả lập [INetSim](https://www.google.com/search?q=https%3A%2F%2Fwww.inetsim.org%2F), tự động tương tác theo kịch bản đã sinh để bắt cả hành vi script lẫn khai thác bộ giải mã native (như lỗ hổng JBIG2 trong [FORCEDENTRY](https://www.google.com/search?q=https%3A%2F%2Fprojectzero.google%2F2021%2F12%2Fa-deep-dive-into-nso-zero-click.html)), sau đó đẩy toàn bộ payload/script sinh mới về Bước 2 và Bước 5.
8. **Tổng hợp Đặc trưng, Độ bao phủ & Xuất bản (Feature Synthesis & Standardized Export):** Kết xuất ba khối dữ liệu liên kết chặt chẽ gồm Kho bằng chứng (`Evidence Store`), Vector/Đồ thị đặc trưng (`Feature Store`) và Báo cáo nguồn gốc & độ phủ (`Provenance & Coverage Report`).

### Cấu trúc thư mục mã nguồn mở chuẩn hóa

```text
pdf-evidence-extractor/
├── configs/
│   ├── extraction_profiles.yaml      # Cấu hình chế độ: fast-static, deep-static, full-hybrid
│   ├── resource_limits.yaml          # Giới hạn RAM, timeout, độ sâu đệ quy, tỷ lệ giải nén
│   └── arlington_mapping.yaml        # Cấu hình ánh xạ phiên bản chuẩn PDF 1.0 - 2.0
├── schemas/
│   ├── evidence_store.schema.json    # Schema hiện vật thô, offset, lịch sử phiên bản object
│   ├── feature_record.schema.json    # Schema đặc trưng kèm trạng thái quan sát và liên kết bằng chứng
│   └── coverage_report.schema.json   # Schema báo cáo độ phủ, lỗi giải mã và xung đột parser
├── src/
│   ├── core/
│   │   ├── orchestrator.py           # Điều phối pipeline, cô lập lỗi theo từng object/stream
│   │   ├── provenance.py             # Quản lý định danh bằng chứng (evidence_id) và truy vết nguồn
│   │   └── resource_guard.py         # Giám sát timeout, bộ nhớ và chống bom giải nén
│   ├── parsers/
│   │   ├── qpdf_adapter.py           # Adapter trích xuất qua pikepdf / qpdf
│   │   ├── mupdf_adapter.py          # Adapter trích xuất qua PyMuPDF / mutool
│   │   ├── raw_forensic_parser.py    # Bộ quét token/byte thô, xref, trailer, vùng ngoài EOF
│   │   └── differential_merger.py    # Đối chiếu kết quả và sinh đặc trưng bất đồng giữa các parser
│   ├── decoders/
│   │   ├── filter_matrix.py          # Giải nén từng tầng (Flate, LZW, ASCII85, ASCIIHex, RunLength...)
│   │   ├── media_decoders.py         # Phân tích cấu trúc JBIG2, JPEG2000, CCITTFax, Font nhúng
│   │   └── recursive_carver.py       # Định tuyến đệ quy cho file đính kèm, PDF lồng nhau, XFA
│   ├── semantics/
│   │   ├── arlington_validator.py    # Kiểm tra đối tượng/trường theo Arlington PDF Model
│   │   ├── object_graph.py           # Dựng Object Reference Graph, đường đi tới Action, chu trình
│   │   ├── pdfobj_ir.py              # Biểu diễn trung gian đối tượng (tham khảo PDFObj IR)
│   │   ├── js_static_analyzer.py     # Trích xuất AST, lời gọi API, chuỗi ghép, suy luận trừu tượng
│   │   └── visual_page_analyzer.py   # Render trang, OCR, QR, tọa độ, phát hiện lệch liên kết & ảnh byte
│   ├── dynamic/
│   │   ├── trigger_planner.py        # Sinh kịch bản tương tác từ cấu trúc PDF đã trích xuất
│   │   ├── js_sandbox_emulator.py    # Giả lập API Acrobat có giám sát & hỗ trợ ép nhánh (forced execution)
│   │   ├── cape_runner.py            # Tích hợp CAPEv2, Sysmon, INetSim với Adobe Reader thật
│   │   └── artifact_reingestor.py    # Đưa script/file/memory dump thu được quay lại pipeline tĩnh
│   └── exporters/
│       ├── tabular_exporter.py       # Xuất Parquet/JSONL có kèm cột trạng thái độ phủ
│       └── graph_exporter.py         # Xuất đồ thị chuẩn NetworkX / PyTorch Geometric / DGL
├── tests/
│   ├── unit/                         # Kiểm thử từng decoder, parser và bộ xử lý lỗi partial
│   ├── adversarial_corpus/           # Các mẫu hỏng xref, lỗi Flate, che giấu tên, đa phiên bản
│   └── benchmark_runner.py           # Đo độ phủ bằng chứng, thời gian/RAM và kiểm tra rò rỉ split
├── docker/
│   ├── Dockerfile.static-worker      # Container cô lập không mạng cho tầng trích xuất tĩnh
│   └── Dockerfile.js-emulator        # Container cô lập cho tầng mô phỏng JavaScript
└── docs/
    ├── architecture.md               # Tài liệu kiến trúc hệ thống
    ├── feature_catalog.md            # Từ điển toàn bộ đặc trưng và ý nghĩa bảo mật
    └── contributing_plugins.md       # Hướng dẫn viết plugin mở rộng parser/decoder cho cộng đồng
```

## 3. Chuẩn Hóa Mô Hình Dữ Liệu & Trạng Thái Quan Sát

Để khắc phục triệt để tình trạng một mô-đun phụ gặp lỗi làm mất kết quả của mô-đun chính hoặc khiến bộ phân loại trả về `Inconclusive` hàng loạt trên các mẫu `partial`, mọi đầu ra đều tuân theo cấu trúc chuẩn hóa 3 lớp.

### Các trạng thái quan sát bắt buộc (`observation_status`)

| Mã trạng thái | Ý nghĩa kỹ thuật | Hướng xử lý ở tầng sinh đặc trưng & phân loại |
| :--- | :--- | :--- |
| `observed` | Đọc, giải mã và trích xuất hoàn chỉnh trong phạm vi thành phần | Sử dụng giá trị trích xuất làm bằng chứng dương tính hoặc định lượng trực tiếp |
| `absent_within_scope` | Đã duyệt toàn bộ phạm vi liên quan, không có lỗi giải mã và xác nhận không tồn tại thành phần | Ghi nhận là bằng chứng âm tính đáng tin cậy (ví dụ: thực sự không có `/JavaScript` trong các object đọc được) |
| `partial` | Trích xuất được một phần trước khi gặp lỗi cục bộ (ví dụ: 1 stream Flate lỗi nhưng 15 stream khác giải mã thành công) | Giữ nguyên toàn bộ đặc trưng đã thu được kèm cờ `is_partial = true` và số lượng phần tử bị lỗi |
| `decode_error` | Đối tượng hoặc stream tồn tại nhưng dữ liệu hỏng hoặc sai định dạng giải nén | Không gán giá trị `0`; sinh đặc trưng bất thường cấu trúc (`malformed_stream_count`) và giữ byte thô trước giải mã |
| `unsupported` | Phát hiện filter, bộ mã hóa hoặc cấu trúc hợp lệ nhưng công cụ chưa có decoder tương ứng | Đánh dấu giới hạn công cụ, lưu tên filter/cấu trúc để thống kê độ phủ và ưu tiên bổ sung decoder |
| `encrypted` | Thành phần bị khóa bởi cơ chế mã hóa PDF không giải được bằng mật khẩu rỗng hoặc khóa hiện có | Ghi nhận cấu hình `/Encrypt`, thuật toán, độ dài khóa và đánh dấu các stream/string bị che khuất |
| `timeout` / `resource_limit` | Quá trình giải nén, duyệt đồ thị hoặc phân tích động chạm ngưỡng RAM/thời gian/độ sâu đệ quy | Lưu checkpoint tại thời điểm dừng, giữ toàn bộ bằng chứng đã thu trước đó và bật cờ cảnh báo cạn kiệt tài nguyên |
| `not_run` | Mô-đun không được kích hoạt theo cấu hình chạy hiện tại (ví dụ: chạy ở chế độ `fast-static` nên tắt VM động) | Phân biệt rõ với `absent_within_scope` để mô hình học máy xử lý như giá trị khuyết có chủ đích |

### Cấu trúc bản ghi đặc trưng mẫu (JSON Schema chuẩn)

```json
{
  "sample_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "extraction_profile": "full-hybrid",
  "feature_record": {
    "feature_name": "action_to_js_chain_depth",
    "feature_group": "structural_graph",
    "value": 3,
    "observation_status": "partial",
    "coverage_ratio": 0.85,
    "is_synthetic_repaired": false,
    "execution_source": "static_multi_parser",
    "evidence_refs": [
      {
        "evidence_id": "ev_obj_12_gen_0_rev_2",
        "object_id": "12 0 R",
        "update_revision": 2,
        "byte_offset_start": 4096,
        "byte_offset_end": 4312,
        "parser_agreement": ["qpdf", "raw_forensic"],
        "parser_missed": ["mupdf"]
      }
    ],
    "limitations": [
      "stream_obj_19_flate_truncated_at_offset_18420"
    ],
    "backend_versions": {
      "qpdf": "11.9.1",
      "mupdf": "1.24.0",
      "raw_forensic": "0.1.0"
    }
  }
}
```

## 4. Danh Mục Toàn Diện 14 Nhóm Đặc Trưng Cần Trích Xuất

Thay vì giới hạn ở danh sách từ khóa cố định, hệ thống duyệt toàn bộ cây đối tượng, thu thập mọi cặp `key/value` (kể cả các trường tự đặt không nằm trong chuẩn) và tổng hợp thành 14 nhóm đặc trưng đa chiều:

| STT | Nhóm đặc trưng | Dữ liệu bằng chứng cần giữ lại | Đặc trưng sinh ra phục vụ phân tích & phân loại |
| :--- | :--- | :--- | :--- |
| **1** | **Byte thô & Bố cục file** | Toàn bộ byte gốc, vị trí `%PDF-`, vị trí tất cả `%%EOF`, các vùng byte không thuộc object nào, dữ liệu trước header và sau EOF cuối | Kích thước file, phân bố 256 giá trị byte, byte n-grams, đường cong entropy theo cửa sổ trượt, độ dài và entropy vùng dữ liệu thừa trước header/sau EOF, mật độ chuỗi ASCII/UTF-16 khả đọc |
| **2** | **Cú pháp & Token PDF** | Mọi token nguyên bản và giá trị sau chuẩn hóa, literal strings `(...)`, hex strings `<...>`, tên `/Name` trước và sau khi giải mã `#xx` | Tỷ lệ tên bị mã hóa hex (`#xx`), số lượng key trùng lặp trong cùng dictionary, độ sâu lồng nhau tối đa của array/dictionary, tỷ lệ ký tự trắng hoặc bình luận `%` chèn bất thường giữa các từ khóa cú pháp |
| **3** | **Đối tượng (Objects)** | Danh sách tất cả indirect objects, direct objects, object streams (`/ObjStm`), số thế hệ (generation), byte offset và kích thước từng object | Tổng số object theo từng kiểu (`Boolean`, `Numeric`, `String`, `Name`, `Array`, `Dictionary`, `Stream`, `Null`), phân bố kích thước object, số lượng object trùng ID, tỷ lệ object nằm trong `/ObjStm` |
| **4** | **Xref & Lịch sử cập nhật** | Toàn bộ các bảng `xref` truyền thống, `XRef` streams, chuỗi trailer, con trỏ `/Prev` và trạng thái thay đổi của từng object qua các lần lưu | Số lần cập nhật tăng dần (incremental updates), số object bị ghi đè hoặc xóa qua các phiên bản, độ lệch giữa offset trong bảng `xref` với vị trí thực tế của object trong file, hiện tượng lai ghép `xref` table và `XRef` stream |
| **5** | **Đồ thị cấu trúc (Object Graph)** | Mọi cạnh tham chiếu trực tiếp và gián tiếp từ `/Root` (Catalog), `/Info`, `/Encrypt` tới từng node lá; danh sách tham chiếu đứt gãy và node mồ côi | Bậc vào/ra (in/out-degree), độ sâu đường đi ngắn nhất từ `/Catalog` hoặc `/Pages` tới `/Action` và `/JavaScript`, số chu trình tham chiếu, số lượng object không được tham chiếu (unreferenced objects), số tham chiếu trỏ tới đích không tồn tại (dangling references) |
| **6** | **Stream & Ma trận Filter** | Byte gốc trước giải mã, chuỗi `/Filter` và `/DecodeParms`, dữ liệu trung gian sau từng tầng filter, thông báo lỗi hoặc vị trí bị cắt cụt | Ma trận tần suất từng loại filter và chuỗi kết hợp filter, tỷ lệ nén sau từng bước, chênh lệch giữa `/Length` khai báo và độ dài thực tế, số lượng stream rỗng sau giải mã so với số lượng stream lỗi (`decode_error`) hoặc chưa hỗ trợ (`unsupported`) |
| **7** | **Action & Sự kiện kích hoạt** | Toàn bộ cấu trúc `/OpenAction`, `/AA` (Additional Actions) ở cấp Document, Page, Annotation, Form Field, Bookmark cùng chuỗi liên kết `/Next` | Đồ thị chuỗi sự kiện kích hoạt (`O`, `C`, `PV`, `PI`, `E`, `X`, `D`, `U`, `Fo`, `Bl`, `K`, `F`, `V`, `C`), loại hành động (`/JavaScript`, `/Launch`, `/URI`, `/GoToR`, `/SubmitForm`, `/ImportData`, `/Rendition`, `/RichMedia`), độ dài chuỗi `/Next` |
| **8** | **JavaScript & XFA** | Toàn bộ mã nguồn script thu từ `/JS`, `/JavaScript`, XFA `<script>`, chuỗi sau khử che giấu, cây cú pháp trừu tượng (AST) và kết quả suy luận tĩnh | Phân bố loại node AST, độ sâu AST, entropy chuỗi ký tự trong mã, số phép ghép chuỗi/ep kiểu, danh sách lời gọi API Acrobat (`app.viewerVersion`, `util.printf`, `Collab.collectEmailInfo`, `exportDataObject`), hàm sinh mã động (`eval`, `unescape`, `Function`) và điều kiện rẽ nhánh kiểm tra môi trường |
| **9** | **File nhúng & Hiện vật đệ quy** | Toàn bộ `/EmbeddedFiles`, `/Filespec`, PDF lồng nhau, luồng OLE/Flash/Archive kèm mã băm SHA-256 và liên kết tới object chứa chúng | Số lượng hiện vật con theo định dạng thực tế (magic bytes) so với phần mở rộng tên file hoặc `/Subtype` khai báo, toàn bộ tập đặc trưng đệ quy của từng file con và độ sâu lồng nhau tối đa |
| **10** | **Font, Ảnh & Multimedia** | Dữ liệu nhúng của `/FontFile`, `/FontFile2`, `/FontFile3`, `/XObject` kiểu `/Image` (đặc biệt JBIG2, JPEG2000, CCITTFax), 3D và RichMedia | Kích thước và cấu trúc bảng font (CFF/TrueType), số lượng phân đoạn (segments) và cờ điều khiển bất thường trong luồng JBIG2 (như kỹ thuật tạo cổng logic trong [FORCEDENTRY](https://www.google.com/search?q=https%3A%2F%2Fprojectzero.google%2F2021%2F12%2Fa-deep-dive-into-nso-zero-click.html)), thông số chiều rộng/chiều cao/số bit màu dị thường |
| **11** | **Nội dung trang & Hiển thị** | Toán tử luồng nội dung trang (content stream operators), văn bản trích xuất kèm bounding box, ảnh render từng trang, kết quả OCR và giải mã QR | Tỷ lệ trang không có text nhưng có một ảnh phủ kín trang, mật độ văn bản ẩn (chữ trắng trên nền trắng, cỡ chữ 0, nằm ngoài `/MediaBox` hoặc `/CropBox`), số lượng mã QR/URL, khoảng cách ngữ nghĩa giữa anchor text/hình ảnh hiển thị với đích `/URI` thực tế |
| **12** | **Metadata, Mã hóa & Chữ ký** | Toàn bộ trường trong `/Info`, gói XML `/Metadata` (XMP), cấu hình `/Encrypt`, từ điển `/Sig`, `/ByteRange` và dữ liệu cập nhật sau phạm vi ký | Sự bất nhất giữa `/Info` và XMP (tác giả, công cụ tạo, mốc thời gian tạo/sửa), phiên bản thuật toán mã hóa, tính hợp lệ của `/ByteRange` chữ ký số, dung lượng và loại đối tượng được chèn thêm sau vùng byte đã ký |
| **13** | **Hành vi động & Telemetry** | Nhật ký sự kiện đã kích hoạt, mã JS sinh thêm lúc chạy, trace lời gọi API/tham số, cây tiến trình, file thả xuống, registry, PCAP/DNS, memory dump và crash dump | Số lượng mã script mới giải mã lúc chạy (runtime-generated code), chuỗi API gọi theo thời gian, hành vi tạo tiến trình con hoặc ghi file thực thi, truy vấn DNS/HTTP phát sinh, ngoại lệ bộ nhớ (access violation, heap corruption) và sự khác biệt giữa nhánh chạy tự nhiên với nhánh ép thực thi |
| **14** | **Đối chiếu Parser & Độ phủ** | Bảng so sánh kết quả giữa [QPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fqpdf%2Fqpdf), [MuPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FArtifexSoftware%2Fmupdf) và bộ phân tích cú pháp thô; danh sách vi phạm quy tắc [Arlington PDF Model](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpdf-association%2Farlington-pdf-model) | Số lượng object chỉ xuất hiện ở một parser mà ẩn ở parser khác, xung đột phiên bản object được chọn giữa các engine, số lỗi vi phạm kiểu dữ liệu/trường bắt buộc theo chuẩn Arlington, tỷ lệ byte và stream được giải mã thành công trên toàn file |

## 5. Kế Hoạch Triển Khai Chi Tiết Theo 6 Giai Đoạn (16 Tuần)

### Giai đoạn 1: Chuẩn hóa Schema Bằng chứng, Trạng thái Partial & Cô lập Lỗi (Tuần 1 – Tuần 2)

- **Mục tiêu:** Giải quyết dứt điểm lỗi mất đặc trưng khi một backend phụ gặp sự cố và giúp tầng phân loại phân biệt rõ giữa dữ liệu thiếu với bằng chứng âm tính.
- **Công việc cụ thể:**
  - Thiết kế và kiểm thử bộ JSON Schema cho `Evidence Store`, `Feature Store` và `Coverage Report`.
  - Xây dựng `Orchestrator` chạy từng mô-đun trích xuất trong worker cô lập với bộ canh giữ tài nguyên (`ResourceGuard`: giới hạn thời gian mỗi mẫu, giới hạn RAM, giới hạn kích thước giải nén tối đa mỗi stream).
  - Cài đặt cơ chế gom kết quả `partial`: khi một stream hoặc một parser phụ báo lỗi, hệ thống giữ nguyên toàn bộ các đặc trưng chính đã trích xuất được, ghi nhận mã lỗi vào mảng `limitations` và cập nhật trạng thái quan sát chính xác cho từng nhóm đặc trưng.
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - Chạy lại tập 21/21 mẫu PDF Validation từng bị `partial`: 100% đặc trưng từ nhánh chính được bảo toàn đầy đủ, không còn hiện tượng lỗi cục bộ làm sập toàn bộ tiến trình trích xuất của mẫu.

### Giai đoạn 2: Xây dựng Tầng Parser Đa Cơ Chế, Giải Mã Đa Tầng & Đệ Quy Hiện Vật (Tuần 3 – Tuần 5)

- **Mục tiêu:** Mở rộng tối đa khả năng đọc cấu trúc PDF dị biệt, hỏng một phần và giải nén sâu mọi lớp nội dung lồng nhau mà không làm biến dạng bằng chứng gốc.
- **Công việc cụ thể:**
  - Tích hợp 3 nhánh đọc độc lập trên file gốc (tuyệt đối không chạy lệnh `repair` ghi đè file trước khi trích xuất): nhánh 1 dùng [pikepdf](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpikepdf%2Fpikepdf) (dựa trên [QPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fqpdf%2Fqpdf)), nhánh 2 dùng [PyMuPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpymupdf%2Fpymupdf) (dựa trên [MuPDF](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FArtifexSoftware%2Fmupdf)), nhánh 3 là bộ `raw_forensic_parser` quét trực tiếp byte/token, bảng `xref`, chuỗi trailer và các vùng dữ liệu mồ côi theo hướng [pdf-parser.py](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FDidierStevens%2FDidierStevensSuite%2Fblob%2Fmaster%2Fpdf-parser.py).
  - Xây dựng `DifferentialMerger` đối chiếu danh sách object, stream và giá trị key giữa 3 nhánh để sinh nhóm đặc trưng bất đồng parser (ví dụ: parser A thấy `/JavaScript`, parser B bỏ qua do lỗi cú pháp có chủ đích).
  - Xây dựng `FilterMatrix` hỗ trợ giải mã tuần tự từng lớp filter (`FlateDecode`, `LZWDecode`, `ASCII85Decode`, `ASCIIHexDecode`, `RunLengthDecode`, `CCITTFaxDecode`, `JBIG2Decode`, `JPXDecode`, `Crypt`), lưu lại cả dữ liệu giải mã được một phần khi luồng nén bị cắt giữa chừng.
  - Xây dựng `RecursiveCarver` nhận diện magic bytes của dữ liệu sau giải nén để đệ quy phân tích nếu bên trong chứa PDF con, file nén, script, font hoặc ảnh (có kiểm soát độ sâu đệ quy và bảng băm chống lặp vòng).
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - Thu thêm bằng chứng xác minh được trên tập mẫu thiếu tham chiếu (`dangling references`), lỗi luồng Flate và mẫu dùng tên che giấu `#xx`; phân biệt chính xác `unsupported`, `decode_error`, `encrypted` với stream rỗng thực sự.

### Giai đoạn 3: Tích hợp Danh mục Arlington, Đồ thị Ngữ nghĩa & Phân tích Tĩnh JavaScript (Tuần 6 – Tuần 8)

- **Mục tiêu:** Chuyển từ đếm từ khóa rời rạc sang biểu diễn ngữ nghĩa, quan hệ cấu trúc và bản chất hành vi của mã kịch bản.
- **Công việc cụ thể:**
  - Nạp bộ dữ liệu TSV từ [Arlington PDF Model](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fpdf-association%2Farlington-pdf-model) để tự động kiểm tra mọi object/dictionary/array, vừa sinh đặc trưng chuẩn hóa cho các trường đã định nghĩa trong [ISO 32000-2](https://www.google.com/search?q=https%3A%2F%2Fpdfa.org%2Fresource%2Fiso-32000-2%2F), vừa trích xuất toàn bộ các key lạ ngoài danh mục chuẩn.
  - Xây dựng `ObjectGraph` và biểu diễn trung gian lấy cảm hứng từ [Analyzing PDFs like Binaries (PDFObj IR / Poir)](https://www.google.com/search?q=https%3A%2F%2Farxiv.org%2Fabs%2F2506.17162), trong đó tách biệt rõ đồ thị tham chiếu tĩnh với luồng thực thi và gắn cờ `is_synthetic = true` cho mọi node `null` được chèn vào khi khuyết tham chiếu đích.
  - Xây dựng bộ phân tích tĩnh JavaScript & XFA: trích xuất cây AST, chuẩn hóa tên biến, khử che giấu các phép nối chuỗi cơ bản, trích xuất đồ thị lời gọi API và tích hợp tầng suy luận trừu tượng (abstract interpretation) theo hướng [SAFE-PDF](https://www.google.com/search?q=https%3A%2F%2Farxiv.org%2Fabs%2F1810.12490) kèm độ bất định của mô hình.
  - Xây dựng mô-đun phân tích hiển thị và hình ảnh: tách riêng nhánh tạo ảnh ánh xạ byte theo từng khối/object (tránh co ép toàn bộ file lớn vào một ảnh nhỏ làm mất vùng payload) và nhánh render trang thực tế để trích xuất văn bản, OCR, mã QR và sự sai khác giữa nội dung hiển thị với liên kết đích.
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - 100% đặc trưng đồ thị và AST truy xuất ngược được về `evidence_id` gốc; phân biệt rõ hai file cùng có `/JavaScript` nhưng khác nhau về đường dẫn kích hoạt và hành vi API.

### Giai đoạn 4: Phân tích Động Hai Tầng & Sinh Kịch bản Kích hoạt Tự động (Tuần 9 – Tuần 12)

- **Mục tiêu:** Khám phá các đoạn mã tự giải mã lúc chạy, hành vi phụ thuộc tương tác người dùng và các đòn khai thác bộ giải mã native.
- **Công việc cụ thể:**
  - Xây dựng `TriggerPlanner` đọc trực tiếp kết quả từ Giai đoạn 3 để lập danh sách sự kiện cần kích hoạt cho từng PDF: mở tài liệu, nhảy tới từng trang có `/AA` hoặc annotation, kích hoạt bookmark/liên kết, điền dữ liệu giả vào các trường AcroForm/XFA và đóng tài liệu.
  - Triển khai tầng 1 — **Giả lập JavaScript có giám sát:** Mô hình hóa các đối tượng cốt lõi của Acrobat DOM (`app`, `doc`, `util`, `Collab`, `event`, `this`), ghi lại toàn bộ chuỗi truyền vào `eval`/`unescape`, tham số gọi API và tích hợp chế độ khám phá đa nhánh tham khảo [JSForce](https://www.google.com/search?q=https%3A%2F%2Farxiv.org%2Fabs%2F1701.07860) (lưu tách biệt trace tự nhiên và trace ép nhánh).
  - Triển khai tầng 2 — **Reader thật trong VM có giám sát:** Tích hợp với [CAPEv2](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fkevoreilly%2Fcapev2) chạy Adobe Reader trên Windows VM sạch (snapshot tự động), thu thập telemetry qua [Sysmon](https://www.google.com/search?q=https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fsysinternals%2Fdownloads%2Fsysmon), API hooks, memory dump, crash dump và định tuyến mạng qua [INetSim](https://www.google.com/search?q=https%3A%2F%2Fwww.inetsim.org%2F).
  - Xây dựng `ArtifactReingestor` tự động lấy mọi script sinh thêm, vùng nhớ giải mã hoặc file thả xuống trong quá trình chạy để đưa quay lại tầng phân tích tĩnh (Giai đoạn 2 và 3), giữ nguyên liên kết với lần chạy và sự kiện đã sinh ra chúng.
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - Mỗi lượt chạy động xuất ra danh sách đầy đủ các sự kiện đã thử, sự kiện thành công, sự kiện bị Reader chặn và toàn bộ thông tin cấu hình môi trường (phiên bản Reader, OS, trạng thái mạng giả lập).

### Giai đoạn 5: Kiểm chứng Độ phủ, Chống Rò rỉ Dữ liệu & Đánh giá Toàn diện (Tuần 13 – Tuần 14)

- **Mục tiêu:** Đo lường chính xác chất lượng trích xuất và giá trị gia tăng của từng nhóm đặc trưng trên tập dữ liệu thực tế mà không rơi vào bẫy thiên lệch đánh giá.
- **Công việc cụ thể:**
  - Thiết lập quy trình kiểm thử nghiêm ngặt trên các split P0/P1/P2 cố định, gom toàn bộ các bản sửa chữa (`repaired`), biến thể tấn công hoặc file sinh ra từ cùng một PDF gốc vào chung một nhóm (group split theo phả hệ mẫu) để ngăn rò rỉ dữ liệu giữa tập huấn luyện và tập kiểm thử.
  - Chạy nhánh phân tích động trên cả tập mẫu lành tính và độc hại có cấu trúc tương đương để mô hình hạ nguồn không học nhầm dấu hiệu "có dữ liệu từ sandbox" thành nhãn độc hại.
  - Đo lường bộ chỉ số chất lượng trích xuất: lượng bằng chứng mới thu thêm theo từng nhóm, tỷ lệ giải mã thành công trên từng loại filter, tỷ lệ sự kiện kích hoạt thành công, thời gian xử lý trung vị/P99, mức tiêu thụ RAM, tỷ lệ giảm `Inconclusive` và độ nhạy phát hiện (Recall) tại ngưỡng báo nhầm (FPR) cố định.
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - Hoàn thành báo cáo định lượng chứng minh độ phủ bằng chứng tăng rõ rệt trên nhóm mẫu khó (che giấu mã, hỏng cấu trúc, lừa đảo qua QR/liên kết không chứa JS) mà không đánh đổi bằng việc loại bỏ mẫu lỗi khỏi tập đánh giá.

### Giai đoạn 6: Đóng gói Mã nguồn mở, Tài liệu hóa & Phát hành Cộng đồng (Tuần 15 – Tuần 16)

- **Mục tiêu:** Biến hệ thống thành một công cụ chuẩn mực, dễ cài đặt, dễ mở rộng và sẵn sàng để cộng đồng nghiên cứu tái sử dụng.
- **Công việc cụ thể:**
  - Thiết kế giao diện Plugin (`BaseParserPlugin`, `BaseDecoderPlugin`, `BaseFeaturePlugin`) giúp các nhà nghiên cứu khác dễ dàng đóng góp thêm bộ giải mã hoặc nhóm đặc trưng mới mà không cần sửa core.
  - Đóng gói công cụ dưới dạng CLI, thư viện Python và bộ Docker Compose (tách biệt worker tĩnh không mạng và cụm điều phối sandbox động) để đảm bảo an toàn khi phân tích mẫu độc hại.
  - Xuất bản bộ tài liệu kỹ thuật gồm: Từ điển đặc trưng chi tiết (`Feature Catalog`), Schema bằng chứng chuẩn và bộ mẫu kiểm thử đối kháng (Adversarial PDF Test Suite) phục vụ cộng đồng kiểm chuẩn.
- **Tiêu chí nghiệm thu (Exit Criteria):**
  - Người dùng mới có thể chạy toàn bộ pipeline tĩnh + giả lập JS chỉ bằng một lệnh Docker hoặc CLI và nhận về đầy đủ 3 khối đầu ra chuẩn hóa.

## 6. Quản Trị Rủi Ro Kỹ Thuật & Nguyên Tắc Bảo Toàn Chất Lượng

| Rủi ro kỹ thuật | Tác động nếu không kiểm soát | Giải pháp thiết kế trong hệ thống |
| :--- | :--- | :--- |
| **Bom giải nén (Decompression Bomb) & Chu trình vô hạn** | Làm treo worker hoặc tràn bộ nhớ khi gặp luồng nén tỷ lệ cực lớn hoặc tham chiếu vòng tròn `/Prev`, `/Next`, `/Kids` | Áp đặt ngưỡng đọc theo luồng (streaming byte cap), kiểm tra tỷ lệ giãn nở tức thời và duy trì tập hợp `visited_object_ids` trên mọi thuật toán duyệt đồ thị và đệ quy |
| **Mã độc khai thác chính parser hoặc bộ render tĩnh** | Thỏa hiệp máy chủ phân tích thông qua lỗ hổng tràn bộ đệm trong thư viện C/C++ đọc PDF, font hoặc ảnh | Chạy mọi tiến trình parser và render trong container hoặc sandbox không có quyền mạng, hệ thống file chỉ đọc (read-only rootfs) và hủy worker ngay sau mỗi batch nhỏ |
| **Nhiễu từ nhánh thực thi bị ép chạy (Forced Execution)** | Nhầm lẫn giữa hành vi chắc chắn xảy ra và hành vi tiềm năng trong các nhánh chết hoặc nhánh bị ép điều kiện | Tách riêng không gian tên đặc trưng (`dynamic_natural_*` và `dynamic_forced_*`), đồng thời ghi rõ điều kiện rẽ nhánh đã bị ghi đè trong `Evidence Store` |
| **Ảo tưởng khôi phục dữ liệu từ công cụ tự sửa lỗi** | Coi các đối tượng `null` hoặc bảng `xref` do công cụ tự tái tạo là dữ liệu gốc của tác giả file PDF | Chỉ chạy trích xuất chính trên byte gốc; mọi cấu trúc do bước phục hồi tạo ra đều phải mang cờ `is_synthetic_repaired = true` và không được trộn lẫn với bằng chứng quan sát trực tiếp |
| **Giới hạn của phản hồi mạng giả lập trong LAB** | Mẫu mã độc dừng hoạt động vì phản hồi từ [INetSim](https://www.google.com/search?q=https%3A%2F%2Fwww.inetsim.org%2F) không khớp chữ ký máy chủ điều khiển (C2) thật | Ghi nhận trạng thái `network_simulated_response` trong giới hạn lần chạy, kết hợp đẩy phần mã trước điểm dừng sang nhánh phân tích tĩnh AST và ép nhánh để thu nốt logic phía sau |
