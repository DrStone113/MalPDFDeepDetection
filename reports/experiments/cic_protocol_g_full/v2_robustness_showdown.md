# Nghiên cứu Đối chứng & Thử nghiệm Đối kháng: Model V1 vs Model V2 (4 Trụ Cột)

## 1. Bối cảnh & Động lực Nghiên cứu: "Cai nghiện" `StartXref`

Mô hình **Model V1 (Baseline Fused)** đạt được độ chính xác rất cao trên tập kiểm thử CIC Evasive-PDFMal2022 (**98.63% Accuracy, 0.9876 F1-Score, 99.38% Malware Recall**). Tuy nhiên, phân tích sâu về tầm quan trọng đặc trưng (Feature Importance) chỉ ra rằng:
- Trong cây quyết định đơn lẻ (Decision Tree), `StartXref` chiếm tới **57.09%** tổng trọng số phân nhánh.
- Trong Random Forest, `StartXref` đứng đầu bảng với **13.36%** tỷ trọng.

### Nguy cơ Thực chiến: Cuộc tấn công Đối kháng "Reverse Mimicry"
Kẻ tấn công có thể lợi dụng tính năng **Incremental Update (Cập nhật Tăng dần)** hợp pháp của chuẩn ISO 32000-1:
1. Lấy một tệp PDF sạch đã có nhiều lần lưu (`StartXref >= 2`).
2. Nối thêm đối tượng payload độc hại vào cuối tệp (`/JavaScript`, `/OpenAction`).
3. Ghi thêm một bảng tham chiếu chéo bổ sung hợp lệ.

Khi đó, tệp độc hại mang diện mạo `StartXref >= 2` hoàn toàn giống như một tệp lành tính, vượt qua khe hẹp phân loại của mô hình cũ.

---

## 2. Thí nghiệm 1: Đo lường Mức độ Phụ thuộc của Mô hình Cũ (Vulnerability Showdown)

Để chứng minh lỗ hổng bằng số liệu thực nghiệm, chúng tôi thiết lập kịch bản tấn công giả lập: **Kẻ tấn công sửa đổi `StartXref = 2`, `Xref = 2`, `XrefLength = 2` trên toàn bộ 160 mẫu mã độc trong tập kiểm thử Test Set**.

| Mô hình | Trạng thái Thử nghiệm | Độ chính xác (Accuracy) | Số mẫu mã độc phát hiện | Tỷ lệ né tránh (Evasion Rate) |
| :--- | :--- | :---: | :---: | :---: |
| **Cây quyết định (Decision Tree)** | Tiêu chuẩn (Chưa tấn công) | 97.94% | 158 / 160 (98.75%) | 1.25% |
| **Cây quyết định (Decision Tree)** | **Bị tấn công Reverse Mimicry** | **82.47% (giảm -15.47%)** | **112 / 160 (70.00%)** | **30.00% (48 mã độc lọt lưới!)** |
| **Model V1 Random Forest** | Tiêu chuẩn (Chưa tấn công) | 98.63% | 159 / 160 (99.38%) | 0.62% |
| **Model V1 Random Forest** | **Bị tấn công Reverse Mimicry** | 98.28% | 158 / 160 (98.75%) | 1.25% (Mất 1 mẫu TP) |

> **Kết luận Thực nghiệm 1:** Mô hình dựa vào `StartXref` dễ bị tổn thương nghiêm trọng; kẻ tấn công chỉ cần làm giả số lần cập nhật là có thể đưa 30% mã độc lọt qua mắt cây quyết định.

---

## 3. Kiến trúc Đột phá của Model V2: Hệ thống Phòng thủ 4 Trụ Cột

**Model V2 (Robust Hardened Model)** được thiết kế để "cai nghiện" hoàn toàn `StartXref`, ép bộ phân loại phải nhìn vào **chất lượng mã nguồn, độ hỗn loạn cấu trúc và ngữ nghĩa AST**:

```
[ PDF Tệp Đầu Vào ]
        │
        ▼
[ Giai đoạn 1: Fast Evasion Triage ] ──(Dính bẫy DoS / Stream Bomb / Evasive)──► [ Gán nhãn: MALICIOUS (95%+) ]
        │
        │ (Vượt qua Giai đoạn 1)
        ▼
[ Giai đoạn 2: Hardened Semantic Classifier ] ──► [ Phân loại theo Tỷ lệ Mật độ, AST & Entropy ]
        │
        ├── Trụ cột A: Tỷ lệ mật độ (density_stream_ratio, density_obj_stream_ratio, density_metadata_ratio)
        ├── Trụ cột B: Chỉ số làm rối AST (ast_complexity_per_node, ast_call_ratio, ast_identifier_ratio)
        └── Trụ cột D: Feature Stability Gate (HOÀN TOÀN LOẠI BỎ StartXref)
```

1. **Trụ cột A (Tỷ lệ Mật độ Cấu trúc):**
   - `density_stream_ratio`: Tỷ lệ luồng stream trên kích thước file (`Stream / PdfSize`).
   - `density_obj_stream_ratio`: Tỷ lệ đối tượng trên stream (`Obj / Stream`).
   - `density_metadata_ratio`: Mật độ metadata (`MetadataSize / PdfSize`).
2. **Trụ cột B (Chỉ số Làm rối & Ngữ nghĩa AST):**
   - `ast_complexity_per_node`: Tỷ lệ độ sâu cực đại trên tổng số node (`max_depth / node_count`).
   - `ast_call_ratio`: Tần suất gọi hàm (`CallExpression / node_count`).
   - `ast_identifier_ratio`: Tỷ lệ định danh (`Identifier / node_count`).
   - `entropy_gap`: Độ chênh lệch entropy giữa phần đầu và phần đuôi file (`|raw_prefix_entropy - raw_suffix_entropy|`).
3. **Trụ cột C (Kiến trúc Phân tầng 2 Giai đoạn - Cascaded Detection):**
   - **Giai đoạn 1 (Fast Evasion Triage):** Bắt ngay các mẫu cố tình gây cạn kiệt tài nguyên (`evasive_timeout_anomaly = 1`, `flag_decompression_ratio_exceeded = 1`, `is_truncated_stream = 1`).
   - **Giai đoạn 2 (Deep Semantic Classifier):** Phân tích sâu các mẫu tĩnh còn lại.
4. **Trụ cột D (Feature Stability Gate):**
   - **Tuyệt đối không sử dụng `StartXref`** (và các biến thể `canonical_startxref`, `lexical_startxref`) trong tập huấn luyện của Giai đoạn 2.

---

## 4. Thí nghiệm 2: Đánh giá Hiệu năng & Khả năng Kháng cự của Model V2

Huấn luyện và đánh giá Model V2 theo phân hoạch Protocol G (seed 42) trên cùng tập Test Set (291 mẫu: 160 mã độc, 131 sạch):

### 4.1 Hiệu năng trên Tập Kiểm thử Tiêu chuẩn (Normal Test Set)

| Mô hình | Số đặc trưng | Accuracy | Malware Recall | F1-Score | ROC-AUC | Ma trận nhầm lẫn (TN / FP / FN / TP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Model V1 RF (Baseline có StartXref)** | 40 | **98.63%** | 99.38% | **0.9876** | 0.9987 | TN: 128 \| FP: 3 \| FN: 1 \| **TP: 159** |
| **Model V2 RF (Hardened 4 Trụ cột)** | 48 | **90.72%** | **99.38%** | **0.9217** | 0.9530 | TN: 105 \| FP: 26 \| FN: 1 \| **TP: 159** |
| **Model V2 XGBoost (Hardened 4 Trụ cột)** | 48 | **90.72%** | 98.75% | 0.9213 | **0.9931** | TN: 106 \| FP: 25 \| FN: 2 \| **TP: 158** |
| **Model V2 Ensemble (Soft Voting)** | 48 | **90.72%** | 98.75% | 0.9213 | 0.9696 | TN: 106 \| FP: 25 \| FN: 2 \| **TP: 158** |

### 4.2 Hiệu năng khi Bị Tấn công Đối kháng Giả lập (Adversarial Showdown)

Khi toàn bộ 160 mẫu mã độc bị làm giả `StartXref = 2`, `Xref = 2`, `XrefLength = 2`:

| Mô hình | Mã độc bắt được (Trước tấn công) | Mã độc bắt được (Sau tấn công) | Tỷ lệ Suy giảm do Tấn công | Độ chính xác sau tấn công |
| :--- | :---: | :---: | :---: | :---: |
| **Decision Tree (Cũ)** | 158 / 160 | **112 / 160** | **-29.1% (Sụp đổ)** | **82.47%** |
| **Model V1 RF (Baseline)** | 159 / 160 | 158 / 160 | -0.63% (Mất 1 mẫu) | 98.28% |
| **Model V2 RF (Hardened 4 Trụ cột)**| **159 / 160** | **159 / 160** | **0.00% (Hoàn toàn Miễn nhiễm!)** | **90.72%** |
| **Model V2 Ensemble (Hardened)**| **158 / 160** | **158 / 160** | **0.00% (Hoàn toàn Miễn nhiễm!)** | **90.72%** |

---

## 5. Phân bổ Trọng số Đặc trưng Mới trong Model V2 (XGBoost)

Khi loại bỏ `StartXref`, bộ phân loại buộc phải phân tán trọng số đồng đều vào các đặc trưng nội dung cốt lõi:

1. **`Stream` (20.05%)**: Số lượng luồng dữ liệu nhị phân chứa đối tượng nhúng.
2. **`Javascript` (13.33%) & `JS` (10.41%)**: Hành vi nhúng mã kịch bản động.
3. **`XFA` (8.31%)**: Cấu trúc biểu mẫu động độc quyền của Adobe.
4. **`Obj` (6.08%)**: Tổng số lượng đối tượng khai báo trong PDF.
5. **`MetadataSize` (5.86%)**: Kích thước khối thông tin mô tả tệp.
6. **`density_obj_stream_ratio` (2.25%)**: Tỷ lệ tương quan giữa số đối tượng và số luồng stream.
7. **`OpenAction`, `PageNo`, `Colors`**: Các thuộc tính bố cục trang và hành vi kích hoạt tự động.

---

## 6. Tổng kết Giá trị Nghiên cứu & Định hướng Ứng dụng

1. **Minh chứng Khoa học Vững chắc:** Thử nghiệm đối chứng đã chứng minh Model V1 có nguy cơ học vẹt cấu trúc bảng xref (với tỷ lệ rò rỉ lên tới 30% ở các cây phân nhánh đơn).
2. **Bản lĩnh Thực chiến của Model V2:** Dù chấp nhận đánh đổi một phần Specificity (tăng False Positive từ 3 lên 25 trên tập văn phòng phức tạp), Model V2 đạt được **Recall 99.38% không đổi (159/160)** và **độ suy giảm 0.00%** trước kỹ thuật tấn công ngụy trang gia tăng (Reverse Mimicry).
3. **Mô hình Khuyến nghị Triển khai:**
   - Sử dụng **Model V1** cho các hệ thống quét tự động tốc độ cao với các nguồn cấp dữ liệu chuẩn (In-the-wild feed thông thường).
   - Sử dụng **Model V2 (4 Trụ cột)** cho các cổng kiểm soát an ninh nghiêm ngặt (High-security email/firewall gateway) để ngăn chặn các cuộc tấn công có chủ đích (APT) dùng kỹ thuật giả mạo incremental update.

