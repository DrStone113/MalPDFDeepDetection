# BUG-005 — Kết quả dựng sẵn và dữ liệu thiếu bị biến thành bằng chứng

| Mục | Chi tiết |
| --- | --- |
| Ngày | 2026-11-02 |
| Trạng thái | MITIGATED; phân loại ML và huấn luyện còn chờ dữ liệu đầy đủ |
| Mức độ | HIGH |
| Phân loại | ML_DATA_INTEGRITY / EVIDENCE_INTEGRITY |
| Thành phần | Scanner, gateway, CDR, giao diện, huấn luyện PDF-TransGraph, script vẽ XAI |

## Triệu chứng và tái hiện

- Scanner khởi tạo trọng số ngẫu nhiên khi thiếu checkpoint và vẫn trả phán quyết.
- Thiếu scaler bị thay bằng phép chuẩn hóa identity; địa chỉ byte, attention và chứng nhận an toàn có giá trị mặc định không được đo.
- API tạo email mẫu, tự dựng PDF fixture và đưa chúng vào lịch sử phiên chạy thật.
- Script vẽ XAI dùng `torch.randint` cho AST, `torch.randn` cho đặc trưng bảng và chuỗi tấn công viết sẵn.
- Bảng số có 1.452 SHA riêng biệt nhưng cache chỉ có 1.314 đồ thị. 138 mẫu thiếu gồm 85 train, 27 validation, 26 test. Ba loader huấn luyện/đánh giá đã thay chúng bằng một node toàn số 0.
- CDR mặc định sai lệch ảnh bằng 0 khi chưa so sánh; chỉ so độ dài văn bản. Hành động JavaScript trực tiếp trong annotation `/A/Next` có thể sót lại.

## Nguyên nhân gốc — 5 Whys

1. Kết quả trông đầy đủ vì mã tự điền chỗ thiếu.
2. Luồng demo và đo đạc dùng chung API, lịch sử và nhãn hiển thị.
3. Các trường dữ liệu chưa có trạng thái unavailable rõ ràng.
4. Huấn luyện không yêu cầu đủ đồ thị thật cho mọi SHA trong mẫu số.
5. Thiếu hợp đồng nối nguồn trích xuất, checkpoint và từng kết luận được hiển thị.

Đặc trưng raw scanner còn khác công thức, thứ tự AST và nguồn đồ thị của loader huấn luyện. Chỉ có checkpoint không chứng minh hợp đồng đầu vào đã khớp. Không được tiếp tục suy luận bằng cách điền số 0 hay tính proxy thay cho các cột chưa đo.

## Sửa và giới hạn hiện tại

- Gỡ API fixture/demo/email mô phỏng và bộ sinh PDF khỏi runtime. Fixture trên đĩa chỉ dùng trong kiểm thử.
- Từ chối checkpoint/scaler thiếu hoặc hỏng. Scanner trả `prediction_available=false`, xác suất null và `UNAVAILABLE` cho đến khi hợp đồng đặc trưng được xác minh.
- Gateway trả `HELD_FOR_REVIEW` cho đầu vào chưa phân loại; không cho qua dưới nhãn clean.
- Chặn cả ba loader khi thiếu đồ thị; script vẽ XAI chỉ nhận đặc trưng đo được của SHA được yêu cầu.
- CDR mở byte gốc bằng pikepdf; duyệt cả dictionary/array trực tiếp và gián tiếp có giới hạn, xác minh lại khóa hành động sau khi lưu. So sánh nội dung giải mã, tài nguyên và văn bản chính xác.
- Phép so ảnh ghi RGB mean absolute error và tỷ lệ thành phần màu bằng nhau; trang chưa đo nhận null, không gọi MAE là Delta E.
- Giao diện bỏ chatbot giả, tiến trình theo timer và các kết luận CVSS/khai thác/ISO/an toàn tuyệt đối không có bằng chứng.

## Bất biến chống hồi quy

1. Thiếu bằng chứng là null/unavailable, không phải điểm 0, benign hay tỷ lệ hoàn hảo.
2. Không tạo trọng số, PDF, email, attention hoặc chuỗi tấn công để lấp kết quả thật.
3. Mọi mẫu trong tập huấn luyện phải có đồ thị quan sát được; không âm thầm bỏ mẫu hoặc thay bằng node giả.
4. Phán quyết unavailable không được gateway xem là đã kiểm tra an toàn.
5. Trang, Contents, Resources và văn bản phải được đối chiếu; trạng thái hoàn tất CDR không phải bảo đảm loại bỏ mọi nguy cơ.
6. Không sửa số liệu thí nghiệm cũ để khớp kết quả mới; ghi nhận điều chỉnh phương pháp bằng lần chạy mới.

## Kiểm thử và chạy thật

`tests/test_runtime_evidence.py` tái hiện checkpoint/scaler thiếu, offset/hex không quan sát, metrics chưa đo, cạnh không tồn tại, chặn phán quyết, gateway giữ để xem xét và thiếu đồ thị. Các bài CDR dùng tài liệu trên đĩa với các khẳng định dung lượng trên 80%, số trang bằng nhau và văn bản khớp; có bài hành động trực tiếp `/A/Next`.

`scripts/audit_runtime_data.py` tạo thư mục bất biến có `locked_methodology.json` và `metrics.json`, đo CDR trên fixture đã duyệt và kiểm tra độ phủ cache số. Đây không phải đánh giá malware thực tế. Dữ liệu raw chỉ được xử lý trong REMnux sau cổng người vận hành `lab run`.


## Dữ liệu thật sau job tiếp tục — 2026-11-02

Đã thu và xác minh đủ 1.452 bundle của job `dfafd888f7a948a87ffac2e0b68ab702fd60dd1dc9bc630fa6cdbe4496e4a06f`, giữ nguyên SHA/nhãn/split. Dataset mới có 1.377 đồ thị quan sát được và 75 mẫu chưa có đồ thị; 171.055 kích thước node đều null, không có kích thước hợp lệ. Không đổi null thành 0 để khớp đầu vào 19 chiều hoặc thay các mẫu thiếu bằng node giả. Dữ liệu vẫn được gắn model_input_ready=false; chưa train hay đánh giá classifier mới. Cache và số liệu lịch sử được giữ nguyên với giới hạn đã công bố. [Báo cáo sau chạy](../../reports/progress/runtime_data_recovery_postrun_2026-11-02.md).
