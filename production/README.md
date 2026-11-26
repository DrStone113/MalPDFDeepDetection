# MalPDF DeepDetection — Thư mục Triển khai Production (ONNX Runtime)

Thư mục `production/` đóng gói dịch vụ kiểm tra PDF (**PDF-TransGraph v4** + **PDFMultiLabelThreatNet v4** 8 nhãn + **Mondrian Conformal v4**), giải thích XAI 3 nhánh, làm sạch tệp tại chỗ với `pikepdf` (CDR) và cổng kiểm tra Email (`.eml`) chạy hoàn toàn trên ONNX Runtime (không phụ thuộc `torch`).

> Tài liệu hướng dẫn triển khai và xử lý sự cố: [`docs/deployment_huggingface_and_onnx.md`](../docs/deployment_huggingface_and_onnx.md).

## 1. Cấu trúc thư mục

- `models/pdf_transgraph_v4.onnx`: Mô hình nhị phân chính **PDF-TransGraph v4** (`Opset 17`, đồ thị DAG Shortest-Path Graphormer 23 chiều, biểu diễn chuỗi kích hoạt `ActionSubgraphIR` 24 chiều và 29 đặc trưng cấu trúc/tệp).
- `models/multilabel_threat_net_v4.onnx`: Mô hình phân loại đa nhãn **PDFMultiLabelThreatNet v4** (`Opset 17`, đồng bộ thế hệ với `v4` qua đồ thị DAG 23 chiều, `ActionSubgraphIR` 24 chiều, 29 đặc trưng Regime-B `log1p`-RobustScaled và 16 chỉ báo phụ bị chặn log).
- `configs/transgraph_v4_contract.json` & `configs/conformal_calibration_v4.json`: Khóa toàn vẹn mô hình v4 và hiệu chuẩn Mondrian Conformal v4 (SHA-256 chuẩn hóa `LF`, nhiệt độ hiệu chuẩn `Val_Calib`, ngưỡng quyết định và phân vị không tương thích theo lớp).
- `configs/onnx_manifest.json`: Bảng đối chiếu SHA-256 mô hình/hợp đồng, sai số logit so với PyTorch (`< 1e-5`) và số liệu suy luận thực tế.
- `configs/multilabel_threat_v4_contract.json` & `configs/tabular_scaler.json`: Hợp đồng chuẩn hóa log-Robust, nhiệt độ hiệu chuẩn từng đầu và ngưỡng kiểm soát FPR của 8 đầu dự đoán `v4`.
- `onnx_engine.py`: Bộ máy suy luận `ONNXMalPDFScannerEngine` (trích xuất DAG/Action-IR thuần NumPy không cần PyTorch, tính XAI occlusion trên ONNX Runtime và cắt bỏ khóa kích hoạt đối chứng bằng `pikepdf`).
- `onnx_taxonomy.py`: Bộ phân loại hành vi 8 nhãn `ONNXThreatTaxonomyClassifier`.
- `web_service.py`: Dịch vụ FastAPI (`production_router` và `app`) phục vụ giao diện web và API `/api/scan`, `/api/disarm`, `/api/xai/ablate`, `/api/gateway/inspect-eml`, `/favicon.ico`, `/env-config.js`.
- `app.py`: Điểm khởi chạy tương thích với **Hugging Face Spaces (ZeroGPU & CPU)** và Uvicorn độc lập.
- `Dockerfile` & `requirements.txt`: Cấu hình đóng gói container chỉ dùng `onnxruntime`.

## 2. Độ khớp ONNX Runtime (`PDF-TransGraph v4`)

- **Kiến trúc nhánh phẳng (`0` nút điều khiển rẽ nhánh `If`/`Loop`/`Scan`):** toàn bộ luồng đồ thị DAG, ma trận đường đi ngắn nhất và `ActionSubgraphIR` chạy thuần trên toán tử ma trận Opset 17.
- **Độ khớp số học (27 mẫu Phase 2, fixture thật & đồ thị rỗng):** sai lệch logit tối đa `< 1e-5`, trùng khớp phán quyết và trạng thái Mondrian Conformal với PyTorch.

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
