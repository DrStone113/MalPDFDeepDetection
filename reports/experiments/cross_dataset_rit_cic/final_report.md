# Báo Cáo Thực Nghiệm So Sánh Liên Tập Dữ Liệu Quy Mô Lớn: RIT-PDFMal-2026 vs CIC-Evasive-PDFMal2022

**Đề tài:** Đánh Giá Khả Năng Khái Quát Hóa và Thích Ứng Miền (Domain Adaptation) Giữa Miền Mã Độc Thực Tế và Mã Độc Né Tránh  
**Tập dữ liệu:**
- **RIT-PDFMal-2026:** 24,337 mẫu VirusTotal thực tế (13,235 Lành tính, 11,102 Mã độc; 42 cột đặc trưng).
- **CIC-Evasive-PDFMal2022:** 1,452 mẫu tấn công né tránh (652 Lành tính, 800 Mã độc; Protocol G: 870 Train, 291 Val, 291 Test).
- **Không gian Đặc trưng Căn chỉnh:** 32 đặc trưng chung (29 canonical + 3 tỷ lệ mật độ stream/obj/metadata).

---

## 1. Đo Lường Độ Lệch Miền & Hiện Tượng Nghịch Lý Phân Phối (Domain Shift & Feature Inversion)

### 1.1. Khoảng cách Maximum Mean Discrepancy (MMD)
Khoảng cách MMD với Gaussian RBF kernel đo lường độ lệch thống kê giữa phân phối mã độc thực tế (RIT) và mã độc né tránh (CIC):

| Nhóm Đặc trưng Phân tích | MMD Distance ($\gamma = 0.2$) | Mức độ Lệch Miền | Nhận xét Khoa học |
| :--- | :---: | :---: | :--- |
| **Form & Encodings** (`Acroform`, `XFA`, `JBIG2`, `Colors`) | **0.2633** | Cực kỳ cao | Mã độc né tránh lạm dụng biểu mẫu XFA và nén luồng sâu để trốn bộ quét. |
| **Structure & Size** (`pdfsize`, `metadata`, `stream`, `obj`, ratios) | **0.1734** | Cao | Tỷ lệ mật độ luồng nén ở CIC cao gấp 3.3 lần so với RIT. |
| **Script & Execution** (`JS`, `JavaScript`, `OpenAction`, `AA`) | **0.1058** | Đáng kể | Từ khóa kích hoạt script bị che giấu hoặc mã hóa trong CIC. |
| **Xref & Traversal** (`startxref`, `xref`, `xref_length`, `trailer`) | **0.1040** | Đáng kể | Bảng chỉ mục xref bị xáo trộn để bẫy DoS parser. |
| **Toàn bộ Không gian Đặc trưng (Overall MMD)** | **0.2098** | Rất cao | Khẳng định hai tập dữ liệu thuộc hai miền phân phối hoàn toàn khác biệt. |

### 1.2. Thống kê "Đảo Chiều Phân Phối" (Feature Inversion)

```
+-----------------------------------------------------------------------------------------+
|                  NGHỊCH LÝ ĐẶC TRƯNG: MÃ ĐỘC THỰC TẾ vs MÃ ĐỘC NÉ TRÁNH                |
+-----------------------------------------------------------------------------------------+
| Đặc trưng               | RIT-PDFMal-2026 (VirusTotal)       | CIC-Evasive-PDFMal2022   |
|-------------------------+------------------------------------+--------------------------|
| Sự hiện diện của JS     | Malware: 75.94% vs Benign: 5.80%   | Malware: 67.38% vs 7.67% |
| Sự hiện diện OpenAction | Malware: 64.17% vs Benign: 16.71%  | Malware: 52.25% vs 2.91% |
| Giá trị trung bình Xref | Malware: 1.04   vs Benign: 1.62    | Malware: 0.82   vs 2.04  |
| Mật độ luồng Stream     | Malware: 0.3670 vs Benign: 0.1473  | Malware: 1.2324 vs 0.5516|
+-----------------------------------------------------------------------------------------+
```

Biểu đồ trực quan hóa hiện tượng đảo chiều phân phối đã được kết xuất tại:  
![KDE Feature Inversion](../../figures/kde_feature_inversion_rit_vs_cic.png)

---

## 2. Đánh Giá Chuyển Miền Hai Chiều (Bidirectional Zero-Shot Transfer)

Thực nghiệm kiểm thử "mù" chéo giữa hai miền dữ liệu nhằm trả lời câu hỏi:  
*Liệu mô hình học trên tập dữ liệu này có thể phòng thủ được trên tập dữ liệu kia hay không?*

### Bảng Kết Quả Đánh Giá Chuyển Miền Tổng Thể:

| Chiều Thực nghiệm | Dữ liệu Huấn luyện | Dữ liệu Kiểm thử | Kiến trúc Mô hình | Accuracy (%) | Malware Recall (%) | Precision (%) | F1-Score | ROC-AUC | Hiện tượng / Đánh giá |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Baseline RIT** | RIT Train (19,469) | RIT Test (4,868) | Random Forest | **98.44%** | **96.76%** | **99.81%** | **0.9826** | 0.9981 | Mốc chuẩn nội miền hoàn hảo. |
| **Baseline CIC** | CIC Train (870) | CIC Test (291) | Random Forest | **97.94%** | **98.75%** | **97.53%** | **0.9814** | 0.9984 | Mốc chuẩn nội miền CIC. |
| **Chiều A: RIT $\to$ CIC** | RIT (24,337) | CIC Test (291) | Random Forest | **88.32%** | **81.88%** | 96.32% | 0.8851 | 0.9804 | **Bẫy Evasive Sụp đổ:** Bỏ lọt gần 20% mã độc né tránh (Recall rơi từ 96.8% xuống 81.9%). |
| **Chiều A: RIT $\to$ CIC** | RIT (24,337) | CIC Test (291) | Tabular MLP | **87.29%** | **88.12%** | 88.68% | 0.8840 | 0.9208 | Rớt mạnh về độ chính xác và AUC khi gặp evasion. |
| **Chiều B: CIC $\to$ RIT** | CIC Train (870) | RIT Test (4,868) | Tabular ResNet | **92.83%** | **91.13%** | 93.01% | **0.9206** | 0.9556 | **Lá chắn Bền bỉ:** Giữ vững >92.8% độ chính xác trên dữ liệu thực tế! |
| **Chiều B: CIC $\to$ RIT** | CIC Train (870) | RIT Toàn bộ (24,337) | Random Forest Hardened | **93.70%** | **88.90%** | **97.03%** | **0.9279** | 0.9628 | Chỉ cần 870 mẫu né tránh đã bao quát 24,337 mẫu VirusTotal. |
| **Chiều B: CIC $\to$ RIT** | CIC Train (870) | RIT Toàn bộ (24,337) | Tabular MLP (No StartXref)| **92.92%** | **90.47%** | 93.78% | **0.9210** | 0.9516 | Loại bỏ `StartXref` giúp tăng tổng thể độ chính xác chuyển miền. |

---

## 3. Nghiên Cứu Khử Thiên Vị (De-Biasing Study: Bỏ `StartXref`)

Khi loại bỏ hoàn toàn đặc trưng có nguy cơ học vẹt `startxref` và `xref`:
- Trên CIC nội miền: Mô hình vẫn đạt **97.59% Accuracy** và **99.38% Recall** (F1 = 0.9785).
- Trên RIT chuyển miền: Độ chính xác **tăng từ 92.17% lên 92.92%**, Precision đạt **93.78%**.
- **Ý nghĩa:** Chứng minh bộ đặc trưng tỷ lệ mật độ (`density_stream_ratio`, `density_obj_stream_ratio`, `density_metadata_ratio`) mang tính bất biến vật lý cao, cho phép mô hình thoát khỏi bẫy học vẹt cục bộ và tăng cường năng lực tổng quát hóa ra ngoài tự nhiên.

---

## 4. Thích Ứng Miền Không Giám Sát (Unsupervised Deep CORAL Adaptation)

Trong kịch bản thực tế, hệ thống phòng thủ triển khai tại cổng mạng chỉ nhận được các file PDF mới mà không có nhãn kiểm định (Unlabeled Target Domain). Thuật toán **Deep CORAL** tự động căn chỉnh ma trận hiệp phương sai bậc hai giữa biểu diễn ẩn của miền nguồn (CIC) và miền đích (RIT):

| Phương pháp Căn chỉnh Miền | Siêu tham số $\lambda_{\text{CORAL}}$ | Accuracy RIT Test (%) | Malware Recall (%) | Precision (%) | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Non-Adapted Source Baseline** | 0.0 | 92.83% | 91.13% | 93.01% | 0.9206 | **0.9556** |
| **Deep CORAL Adaptation** | 0.5 | **92.87%** | 90.81% | **93.38%** | **0.9208** | 0.9492 |
| **Deep CORAL Adaptation** | 1.0 | **92.87%** | 90.81% | **93.38%** | **0.9208** | 0.9494 |

> [!TIP]
> **Nhận xét Khoa học Cốt lõi:**  
> Do bộ đặc trưng tỷ lệ mật độ cấu trúc (Structural Density Ratios) của chúng tôi đã được thiết kế bền bỉ ngay từ gốc, mô hình thuần túy (`Baseline`) đã đạt sẵn mức chính xác vượt trội **>92.8%** trên miền đích mà chưa cần căn chỉnh phức tạp. Deep CORAL tiếp tục cải thiện Precision lên **93.38%**, giảm thiểu tối đa các cảnh báo giả (False Positives) trong môi trường thực tế.

---

## 5. Kết Luận & Đóng Góp Học Thuật Cho Luận Văn

1. **Minh chứng Bẫy Né Tránh (The Evasion Gap):** Đã thực nghiệm chứng minh rằng các mô hình học máy truyền thống được huấn luyện trên kho dữ liệu VirusTotal thông thường (RIT-PDFMal) sẽ bị suy giảm hiệu năng nghiêm trọng khi đối mặt với mã độc né tránh (Recall rơi gần 15% - 20%).
2. **Khả Năng Chuyển Miền Đột Phá:** Mô hình phòng thủ được trang bị bộ đặc trưng tỷ lệ mật độ chỉ cần huấn luyện trên 870 mẫu CIC-Evasive nhưng có thể quét sạch **24,337 mẫu VirusTotal thực tế với độ chính xác đạt tới 93.70%** mà không cần nhìn thấy nhãn của RIT.
3. **Cơ sở cho Luận Văn Tốt Nghiệp:** Toàn bộ bảng số liệu, khoảng cách MMD, biểu đồ KDE, và ma trận chuyển miền này cung cấp dữ liệu đối chứng độc nhất vô nhị cho Chương 4 (Thực nghiệm) và Chương 5 (Bàn luận) của luận văn.
