# MalPDF DeepDetection — Thư mục Triển khai Production (ONNX Runtime)

Thư mục `production/` đóng gói dịch vụ kiểm tra PDF (**PDF-TransGraph v3.2b** + **PDFMultiLabelThreatNet v2** 8 nhãn), giải thích XAI, làm sạch tệp tại chỗ với `pikepdf` (CDR) và cổng kiểm tra Email (`.eml`) chạy trên ONNX Runtime.

> Tài liệu hướng dẫn triển khai và xử lý sự cố: [`docs/deployment_huggingface_and_onnx.md`](../docs/deployment_huggingface_and_onnx.md).

## 1. Cấu trúc thư mục

- `models/pdf_transgraph_v3.onnx`: Mô hình nhị phân chính **PDF-TransGraph v3.2b** (`Opset 17`, 23 chiều đặc trưng nút HGT và 29 đặc trưng cấu trúc/tệp).
- `models/multilabel_threat_net_v2.onnx`: Mô hình phân loại đa nhãn 8 nhóm hành vi (`Opset 17`, 52 đặc trưng bảng/từ khóa và đồ thị 23 chiều).
- `configs/transgraph_v3_contract.json`: Khóa toàn vẹn mô hình v3.2b (SHA-256 chuẩn hóa `LF`, `temperature = 0.8884`, `decision_threshold = 0.0573`, danh sách 29 đặc trưng).
- `configs/onnx_manifest.json`: Bảng đối chiếu SHA-256 mô hình/hợp đồng, sai số logit so với PyTorch và số liệu suy luận thực tế.
- `configs/tabular_scaler.json` & `configs/multilabel_threat_contract.json`: Bộ chuẩn hóa Z-score và ngưỡng của 8 đầu dự đoán.
- `onnx_engine.py`: Bộ máy suy luận `ONNXMalPDFScannerEngine` (tính XAI occlusion trên ONNX Runtime và cắt bỏ khóa kích hoạt đối chứng bằng `pikepdf`).
- `onnx_taxonomy.py`: Bộ phân loại hành vi 8 nhãn `ONNXThreatTaxonomyClassifier`.
- `web_service.py`: Dịch vụ FastAPI (`production_router` và `app`) phục vụ giao diện web và API `/api/scan`, `/api/disarm`, `/api/xai/ablate`, `/api/gateway/inspect-eml`, `/favicon.ico`, `/env-config.js`.
- `app.py`: Điểm khởi chạy tương thích với **Hugging Face Spaces (ZeroGPU & CPU)** và Uvicorn độc lập.
- `Dockerfile` & `requirements.txt`: Cấu hình đóng gói container chỉ dùng `onnxruntime`.

## 2. Hiệu năng & Độ khớp ONNX Runtime (`v3.2b`)

- **So với PyTorch CPU:** thời gian suy luận trung vị giảm từ `4.455 ms` xuống `1.452 ms` (nhanh hơn `3.07x`).
- **Độ khớp số học (27 mẫu Phase 2 & fixture thật):** sai lệch logit tối đa `1.43e-6`, trùng khớp phán quyết trên toàn bộ mẫu kiểm tra.

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
