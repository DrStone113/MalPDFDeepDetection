# Hướng dẫn Triển khai Production (ONNX Runtime & Hugging Face Spaces)

Tài liệu này lưu trữ đầy đủ kiến trúc đóng gói `production/`, quy trình chuyển đổi mô hình sang **ONNX Runtime**, hướng dẫn từng bước triển khai lên **Hugging Face Spaces** (`DrStone113/malpdfdetection`), triển khai máy chủ nội bộ (Local / Docker), kiểm định trên **REMnux LAB**, và sổ tay xử lý toàn bộ các lỗi thường gặp khi vận hành thực tế.

---

## 1. Kiến trúc Thư mục `production/` (Zero-PyTorch Runtime)

Thư mục `production/` được thiết kế độc lập để chạy toàn bộ hệ thống phát hiện đa phương thức (**PDF-TransGraph v2 23D** + **PDFMultiLabelThreatNet v2 8 nhãn**), giải thích nhân quả XAI, tẩy độc nhị phân tại chỗ (**In-Place Binary CDR** với `pikepdf`) và cổng kiểm duyệt thư điện tử (`.eml`) hoàn toàn trên **ONNX Runtime** mà không cần cài đặt `torch` hay `torch_geometric` nặng nề trên môi trường đích.

```text
production/
├── __init__.py
├── app.py                              # Điểm khởi chạy kép: tương thích Hugging Face (Gradio ZeroGPU / CPU Basic) & Uvicorn độc lập
├── web_service.py                      # FastAPI router & giao diện tiếng Việt (/ui, /api/scan, /api/disarm, /api/xai/ablate, /api/gateway/inspect-eml)
├── onnx_engine.py                      # Động cơ suy luận ONNXMalPDFScannerEngine (23D Graph + AST + 38D Tabular + Batched Occlusion XAI)
├── onnx_taxonomy.py                    # Bộ phân loại 8 nhóm hành vi độc hại ONNXThreatTaxonomyClassifier (52D + 23D Graph)
├── Dockerfile                          # Cấu hình container siêu nhẹ dựa trên python:3.11-slim + libqpdf-dev
├── requirements.txt                    # Danh sách thư viện gọn nhẹ (onnxruntime, fastapi, uvicorn, pikepdf, PyMuPDF, pypdf, esprima)
├── README.md                           # Tóm tắt nhanh thư mục production
├── configs/
│   ├── onnx_manifest.json              # Bảng kiểm định SHA-256, sai lệch logit (< 2e-5) và tốc độ benchmark
│   ├── tabular_scaler.json             # Tham số chuẩn hóa Z-score (mean, scale) của 38 đặc trưng tĩnh
│   └── multilabel_threat_contract.json # Ngưỡng tối ưu và ánh xạ MITRE ATT&CK của 8 đầu dự đoán đa nhãn
└── models/
    ├── pdf_transgraph_v2.onnx          # Mô hình phát hiện nhị phân đa phương thức (Opset 17, ~3.18 MB)
    └── multilabel_threat_net_v2.onnx   # Mô hình phân loại đa nhãn 8 hành vi độc hại (Opset 17, ~0.83 MB)
```

---

## 2. Xuất Mô hình từ PyTorch sang ONNX Runtime

Khi huấn luyện lại hoặc cập nhật trọng số `.pt` trong `artifacts/`, chạy kịch bản sau từ thư mục gốc `C:\Project\MalPDFDeepDetection`:

```powershell
cd C:\Project\MalPDFDeepDetection
.\.venv\Scripts\python.exe scripts\deploy\export_onnx_models.py
```

Kịch bản `scripts/deploy/export_onnx_models.py` thực hiện tự động:
1. Bọc kiến trúc đồ thị dị thể vào `ONNXHeteroGraphTransformer` và `ONNXRelationAwareMessagePassing` (thay thế các hàm gom nút động bằng phép nhân ma trận mặt nạ lô `torch.matmul(mask_f, x)` và mặt nạ cạnh `edge_mask` hỗ trợ `dynamic_axes` cho `num_nodes`, `num_edges`, `batch_size`).
2. Xuất `production/models/pdf_transgraph_v2.onnx` và `production/models/multilabel_threat_net_v2.onnx` ở chuẩn **ONNX Opset 17**.
3. Kiểm định độ khớp số học trực tiếp với PyTorch (`max_abs_logit_diff = 4.8e-07` cho `PDF-TransGraph v2` và `1.55e-05` cho `PDFMultiLabelThreatNet v2`) và ghi biên bản vào `production/configs/onnx_manifest.json`.

---

## 3. Bốn Phương thức Triển khai Hệ thống

### Cách 1: Triển khai lên Hugging Face Spaces với `Gradio SDK` (Hỗ trợ cả `ZeroGPU` và `CPU Basic`)

Khi tạo Space trên Hugging Face với tùy chọn **SDK: Gradio** (kể cả khi bật phần cứng miễn phí **ZeroGPU**), nền tảng Hugging Face áp đặt hai cơ chế kiểm tra nghiêm ngặt lúc khởi động:
- Quét tìm ít nhất một hàm được gắn decorator `@spaces.GPU` và được liên kết vào thành phần giao diện Gradio. Nếu thiếu, container sẽ báo lỗi `No @spaces.GPU function detected during startup` và tự tắt (`Shutting down`) ngay lập tức.
- Yêu cầu ứng dụng phải khởi chạy thông qua chu trình `demo.launch()` của Gradio trên cổng `7860`.

**Cơ chế xử lý trong `production/app.py`:**
- Định nghĩa hàm `@spaces.GPU def zerogpu_accelerator_check(...)` ở cấp module và gắn vào nút kiểm tra của `gr.Blocks()`.
- Khởi chạy `demo.launch(server_name="0.0.0.0", server_port=7860, prevent_thread_lock=True, ssr_mode=False)` để lấy đối tượng FastAPI nội bộ `demo.server_app` của Gradio.
- Chèn toàn bộ các route của `production_router` (`/`, `/ui`, `/api/scan`, `/api/disarm`, `/api/xai/ablate`, `/api/gateway/inspect-eml`, `/favicon.ico`, `/env-config.js`) lên đầu danh sách định tuyến (`gradio_app.router.routes[0:0] = list(production_router.routes)`) rồi khóa luồng bằng `demo.block_thread()`.
- Nhờ vậy, ứng dụng vừa vượt qua 100% kiểm tra khởi động của **ZeroGPU**, vừa hiển thị trực tiếp giao diện FastAPI Custom UI tiếng Việt tại trang chủ `/` của Space.

**Cấu hình phần đầu tệp `README.md` trên repo Hugging Face Space (chế độ Gradio SDK):**
```yaml
---
title: MalPDF DeepDetection
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 5.49.1
app_file: app.py
pinned: false
short_description: He thong AI phat hien va làm sach ma doc PDF da phuong thuc
---
```

---

### Cách 2: Triển khai lên Hugging Face Spaces với `Docker SDK` (`CPU Basic` — Khuyên dùng cho ONNX Runtime)

Vì `ONNX Runtime` trong `production/` đã đạt tốc độ suy luận **`3.46 ms – 3.51 ms` mỗi mẫu ngay trên CPU**, việc dùng **Docker SDK + CPU Basic** giúp container nhẹ hơn ~3 GB (không cần nạp PyTorch/CUDA/Gradio), khởi động tức thì và không bị giới hạn hạn ngạch hàng đợi (queue quota) của ZeroGPU.

**Cấu hình phần đầu tệp `README.md` trên repo Hugging Face Space (chế độ Docker SDK):**
```yaml
---
title: MalPDF DeepDetection
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
short_description: He thong AI phat hien va làm sach ma doc PDF da phuong thuc
---
```
Khi dùng chế độ này, hãy sao chép thêm tệp `production/Dockerfile` vào thư mục gốc của repo Hugging Face Space. Khi container chạy `python app.py` trong môi trường không cài `gradio`, `app.py` sẽ tự động chuyển sang nhánh chạy trực tiếp `uvicorn.run(standalone_app, host="0.0.0.0", port=7860)`.

---

### Cách 3: Chạy Trực tiếp tại Máy Chủ Nội bộ (Local Windows DEV hoặc Linux Server)

```powershell
cd C:\Project\MalPDFDeepDetection

# Cách 3A: Chạy bằng Uvicorn trực tiếp từ thư mục production
.\.venv\Scripts\uvicorn.exe web_service:app --app-dir production --host 127.0.0.1 --port 7860

# Cách 3B: Chạy qua entrypoint app.py
.\.venv\Scripts\python.exe production\app.py
```
Sau khi khởi chạy, mở trình duyệt tại địa chỉ: `http://127.0.0.1:7860` (hoặc `http://127.0.0.1:7860/ui`).

---

### Cách 4: Đóng gói Docker Container Độc lập trên Máy Chủ Bất kỳ

```powershell
cd C:\Project\MalPDFDeepDetection
docker build -f production/Dockerfile -t malpdf-onnx-prod:latest .
docker run --rm -p 7860:7860 malpdf-onnx-prod:latest
```

---

## 4. Quy trình Từng bước Đẩy Code lên Hugging Face Spaces (`DrStone113/malpdfdetection`)

### Bước 1: Thiết lập Xác thực (SSH Key hoặc Hugging Face CLI)

- **Qua SSH Key:**
  1. Kiểm tra hoặc tạo khóa SSH trên máy: `ssh-keygen -t ed25519 -C "your_email@example.com"`
  2. Sao chép nội dung tệp `~/.ssh/id_ed25519.pub` và dán vào trang cài đặt khóa của Hugging Face: `https://huggingface.co/settings/keys`.
- **Qua Hugging Face CLI (`hf`):**
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"
  hf auth login
  ```

### Bước 2: Clone kho chứa Hugging Face Space về thư mục song song

Đặt thư mục repo Space (`C:\Project\malpdfdetection`) nằm cạnh thư mục dự án gốc (`C:\Project\MalPDFDeepDetection`):

```powershell
cd C:\Project
git clone git@hf.co:spaces/DrStone113/malpdfdetection
# Hoặc nếu dùng HTTPS + Access Token:
git clone https://huggingface.co/spaces/DrStone113/malpdfdetection
```

### Bước 3: Chạy kịch bản đóng gói tự động `prepare_hf_space.py`

Kịch bản `scripts/deploy/prepare_hf_space.py` sẽ tự động kiểm tra/xuất mô hình `.onnx`, xóa thư mục `artifacts/` cũ dư thừa, sao chép sạch bộ mã `production/` (`app.py`, `web_service.py`, `onnx_engine.py`, `onnx_taxonomy.py`, `requirements.txt`, `configs/`, `models/`), sao chép gói trích xuất `src/malpdf/`, và cấu hình Git LFS trong `.gitattributes`.

> **CẢNH BÁO QUAN TRỌNG VỀ THƯ MỤC LÀM VIỆC (WORKING DIRECTORY):**
> Môi trường ảo `.venv` và kịch bản `scripts\deploy\prepare_hf_space.py` nằm trong `C:\Project\MalPDFDeepDetection`. Nếu bạn đang đứng ở `PS C:\Project\malpdfdetection>` mà gõ `.\.venv\Scripts\python.exe ...` thì PowerShell sẽ báo lỗi không tìm thấy đường dẫn. Hãy dùng một trong hai cách dưới đây:

- **Cách A (Khuyên dùng — Đứng tại thư mục dự án gốc `C:\Project\MalPDFDeepDetection`):**
  ```powershell
  cd C:\Project\MalPDFDeepDetection
  .\.venv\Scripts\python.exe scripts\deploy\prepare_hf_space.py --target-dir ..\malpdfdetection
  ```

- **Cách B (Nếu đang đứng sẵn trong thư mục `C:\Project\malpdfdetection`):**
  ```powershell
  cd C:\Project\malpdfdetection
  ..\MalPDFDeepDetection\.venv\Scripts\python.exe ..\MalPDFDeepDetection\scripts\deploy\prepare_hf_space.py --target-dir .
  ```

### Bước 4: Commit với Git LFS và Push lên Hugging Face Space

Vì các tệp trọng số nhị phân (`.onnx`, `.pt`) bị Hugging Face chặn nếu đẩy bằng Git thường, bắt buộc đảm bảo `git lfs` đã được kích hoạt trước khi commit:

```powershell
cd C:\Project\malpdfdetection
git lfs install
git add -A
git status
git commit -m "Deploy ONNX Runtime production engine and fix ZeroGPU startup"
git push
```

Sau khi lệnh `git push` hoàn tất, mở `https://huggingface.co/spaces/DrStone113/malpdfdetection` để theo dõi quá trình `Building` → `Running`.

---

## 5. Sổ tay Khắc phục Sự cố Triển khai (Troubleshooting Playbook)

| STT | Triệu chứng / Thông báo lỗi | Nguyên nhân gốc rễ (Root Cause) | Cách khắc phục triệt để |
| --- | --- | --- | --- |
| **1** | `No @spaces.GPU function detected during startup` kèm theo `INFO: Shutting down` ngay sau khi khởi động trên Hugging Face. | Space đang cấu hình phần cứng **ZeroGPU** (`sdk: gradio`), nhưng `app.py` chỉ chạy `uvicorn.run(fastapi_app)` thuần mà không khởi tạo Gradio `demo.launch()` và không có hàm nào gắn decorator `@spaces.GPU` liên kết vào Gradio Blocks. | Dùng `production/app.py` mới (đã tích hợp `@spaces.GPU def zerogpu_accelerator_check` gắn vào `gr.Blocks`, gọi `demo.launch(prevent_thread_lock=True)` và chèn `production_router.routes` lên đầu `demo.server_app`), hoặc đổi phần cứng trong Settings của Space từ `ZeroGPU` sang `CPU Basic`. |
| **2** | `.\.venv\Scripts\python.exe: The term '.\.venv\Scripts\python.exe' is not recognized...` trên PowerShell. | Cửa sổ PowerShell đang đứng ở thư mục đích (`C:\Project\malpdfdetection`) nơi không có thư mục `.venv`. | Chạy `cd C:\Project\MalPDFDeepDetection` trước khi gọi `.\.venv\Scripts\python.exe`, hoặc gọi đường dẫn tương đối `..\MalPDFDeepDetection\.venv\Scripts\python.exe`. |
| **3** | `UserWarning: enable_nested_tensor is True, but self.use_nested_tensor is False because encoder_layer.norm_first was True` tại `ast_transformer.py:44`. | PyTorch `nn.TransformerEncoder` mặc định bật `enable_nested_tensor=True` nhưng tính năng này tự tắt khi dùng `norm_first=True` (Pre-LN). | Đã thêm `enable_nested_tensor=False` tường minh trong `src/malpdf/models/ast_transformer.py` và chuyển hoàn toàn sang `ONNX Runtime` trong `production/` (không nạp `torch` khi suy luận). |
| **4** | `GET /favicon.ico HTTP/1.1 404 Not Found` và `GET /env-config.js HTTP/1.1 404 Not Found` trong Container logs. | Trình duyệt và lớp vỏ iframe của Hugging Face Spaces tự động truy vấn `/favicon.ico` và `/env-config.js` khi mở ứng dụng. | Đã bổ sung 2 endpoint `GET /favicon.ico` (trả về biểu tượng SVG) và `GET /env-config.js` (trả về `window.__ENV__ = {};`) trong `production/web_service.py`. |
| **5** | Git push bị từ chối với lỗi `remote: error: File models/pdf_transgraph_v2.onnx is binary / offending file`. | Hugging Face từ chối các tệp nhị phân lớn hơn ngưỡng cho phép nếu không được quản lý bởi Git LFS. | Chạy `git lfs install`; script `prepare_hf_space.py` đã tự động ghi `*.onnx filter=lfs diff=lfs merge=lfs -text` vào `.gitattributes`. Nếu đã lỡ commit trước khi bật LFS, chạy `git lfs migrate import --include="*.onnx,*.pt" --everything` rồi push lại. |
| **6** | Nhiều người dùng truy cập Space cùng lúc thấy lịch sử quét của nhau. | Trạng thái lịch sử quét nếu lưu chung toàn cục sẽ bị chia sẻ giữa các phiên truy cập. | `production/web_service.py` đã cô lập hoàn toàn lịch sử theo khóa phiên `X-MalPDF-Client-ID` riêng biệt của từng trình duyệt và bảo vệ kho cách ly bằng `scan_id` ngẫu nhiên 128-bit. |

---

## 6. Cơ chế An toàn khi Tải Tệp PDF Độc hại lên Giao diện Web

1. **Trên máy tính người dùng (Client Browser):**
   - Khi người dùng chọn tệp PDF qua hộp thoại `<input type="file">` hoặc kéo-thả vào trang web, trình duyệt chỉ đọc tệp dưới dạng luồng byte thô (`Blob` / `File`) để đóng gói vào gói tin `HTTP POST multipart/form-data`.
   - Trình duyệt **tuyệt đối không mở hay kết xuất (render)** tệp PDF đó, nên không một đoạn mã JavaScript hay lỗ hổng trình đọc nào trong PDF có thể kích hoạt trên máy người dùng (miễn là người dùng không tự nhấp đúp mở tệp đó bằng Adobe Reader/Foxit trên máy cá nhân).
2. **Trên máy chủ xử lý (Server / Hugging Face Container):**
   - Toàn bộ quá trình quét (`/api/scan`) và tẩy độc (`/api/disarm`) xử lý hoàn toàn trên bộ đệm byte trong RAM (`io.BytesIO(raw_bytes)`) bằng bộ phân tích tĩnh hữu hạn (`Bounded Static Extractor`, giới hạn giải nén `16 MB`/stream) và `ONNX Runtime`.
   - Máy chủ **không bao giờ gọi lệnh hệ thống hay thực thi JavaScript** bên trong PDF. Tệp cách ly chỉ được lưu tạm thời với tên băm vô hại trong `/tmp/malpdf_quarantine` (hoặc tự động xoay vòng tối đa 32 bản ghi trong bộ nhớ) để phục vụ thao tác tải về bản đã làm sạch (`CDR`).
