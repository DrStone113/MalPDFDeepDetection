# MalPDF DeepDetection — Thư mục Triển khai Production (ONNX Runtime)

Thư mục `production/` đóng gói toàn bộ hệ thống quét PDF đa phương thức (**PDF-TransGraph v2 23D** + **PDFMultiLabelThreatNet v2 8 nhãn**), giải thích XAI, làm sạch tệp tại chỗ (**In-Place CDR với `pikepdf`**) và cổng kiểm duyệt Email (`.eml`) chạy hoàn toàn trên **ONNX Runtime** tốc độ cao, không phụ thuộc PyTorch nặng khi chạy độc lập.

> 📖 **Tài liệu hướng dẫn triển khai đầy đủ (Step-by-step & Xử lý lỗi):** Xem tại [`docs/deployment_huggingface_and_onnx.md`](../docs/deployment_huggingface_and_onnx.md).

## 1. Cấu trúc thư mục

- `models/pdf_transgraph_v2.onnx`: Mô hình nhị phân đa phương thức (Hetero-HGT 23D + AST RoPE Transformer + Tabular ResNet 38 chiều, Opset 17).
- `models/multilabel_threat_net_v2.onnx`: Mô hình phân loại đa nhãn 8 nhóm hành vi độc hại (52 đặc trưng cấu trúc/AST + đồ thị 23D, Opset 17).
- `configs/onnx_manifest.json`: Bảng đối chiếu SHA-256, sai số logit so với PyTorch (`< 2e-5`) và số liệu đo tốc độ thực tế.
- `configs/tabular_scaler.json` & `configs/multilabel_threat_contract.json`: Bộ chuẩn hóa Z-score và ngưỡng quyết định của 8 đầu dự đoán.
- `onnx_engine.py`: Bộ máy suy luận `ONNXMalPDFScannerEngine` (tích hợp tính toán XAI theo lô trên ONNX Runtime và cắt bỏ đối tượng đối chứng bằng `pikepdf`).
- `onnx_taxonomy.py`: Bộ phân loại hành vi nguy hiểm 8 nhãn `ONNXThreatTaxonomyClassifier`.
- `web_service.py`: Dịch vụ FastAPI (`production_router` & `app`) cung cấp giao diện tiếng Việt thân thiện cùng đầy đủ API `/api/scan`, `/api/disarm`, `/api/xai/ablate`, `/api/gateway/inspect-eml`, `/favicon.ico`, `/env-config.js`.
- `app.py`: Điểm khởi chạy tương thích đồng thời với **Hugging Face Spaces (ZeroGPU & CPU Basic)** và máy chủ Uvicorn độc lập.
- `Dockerfile` & `requirements.txt`: Cấu hình đóng gói container siêu gọn chỉ dùng `onnxruntime`.

## 2. Hiệu năng ONNX Runtime so với PyTorch CPU

- **Trên Windows DEV (Median 2 mô hình):** giảm từ **`14.24 ms`** (PyTorch CPU) xuống **`3.51 ms`** (ONNX Runtime CPU) — **nhanh gấp `4.06x`**.
- **Trên REMnux LAB Linux 6.8 (582 mẫu thực tế — 291 Test + 291 Val):** giảm từ **`9.40 ms`** xuống **`3.46 ms`** (nhanh gấp **`2.72x`**; riêng `PDFTransGraph` nhanh gấp **`3.22x`**, đạt **`453.4 mẫu/giây`**).
- **Độ khớp số học (Numerical Parity):** `100%` trùng khớp phán quyết trên toàn bộ `291/291` mẫu Test và `289/289` mẫu Val (`max_abs_prob_diff = 2.50e-07`).

## 3. Chạy thử trực tiếp tại máy (Local)

```powershell
cd C:\Project\MalPDFDeepDetection

# Xuất lại mô hình ONNX (nếu cập nhật trọng số .pt mới)
.\.venv\Scripts\python.exe scripts\deploy\export_onnx_models.py

# Khởi chạy dịch vụ Production ONNX tại cổng 7860
.\.venv\Scripts\uvicorn.exe web_service:app --app-dir production --host 127.0.0.1 --port 7860
```

## 4. Đóng gói & Đẩy lên Hugging Face Spaces (`DrStone113/malpdfdetection`)

`production/app.py` đã khắc phục triệt để lỗi `No @spaces.GPU function detected during startup` trên hạ tầng **ZeroGPU** thông qua decorator `@spaces.GPU` cấp module kết hợp chu trình `demo.launch(prevent_thread_lock=True, ssr_mode=False)` chuẩn của Gradio và gắn `production_router.routes` lên đầu `demo.server_app`, đồng thời xử lý triệt để các đường dẫn `/favicon.ico`, `/env-config.js` và cảnh báo `TransformerEncoder`.

### Cách A: Chạy lệnh từ thư mục gốc `C:\Project\MalPDFDeepDetection` (Khuyên dùng)

```powershell
cd C:\Project\MalPDFDeepDetection
.\.venv\Scripts\python.exe scripts\deploy\prepare_hf_space.py --target-dir ..\malpdfdetection

cd ..\malpdfdetection
git lfs install
git add -A
git commit -m "Deploy ONNX Runtime production engine and fix ZeroGPU startup"
git push
```

### Cách B: Nếu đang đứng trong thư mục `C:\Project\malpdfdetection`

> Lưu ý: Không gọi trực tiếp `.\.venv\Scripts\python.exe` khi đang đứng ở `C:\Project\malpdfdetection` vì `.venv` nằm ở `C:\Project\MalPDFDeepDetection`.

```powershell
cd C:\Project\malpdfdetection
..\MalPDFDeepDetection\.venv\Scripts\python.exe ..\MalPDFDeepDetection\scripts\deploy\prepare_hf_space.py --target-dir .
git lfs install
git add -A
git commit -m "Deploy ONNX Runtime production engine and fix ZeroGPU startup"
git push
```
