# Hoàn thành kế hoạch cải thiện web MalPDF

Đo và kiểm thử trên Windows DEV ngày 2026-11-20. FastAPI/PyTorch ở cổng 8765 và entrypoint FastAPI/ONNX ở cổng 8766. Các phép đo hiệu năng dưới đây thuộc PyTorch DEV.

## Đã triển khai

- Quét hiện kết quả khi API trả về. Luồng làm sạch bám ID của lượt quét, chống bấm lặp, đối soát kết quả nếu mất phản hồi và có nút tải lại riêng cho preview. Kết quả tải xuống dùng đúng ID đã xác nhận và hỗ trợ tên tệp Unicode.
- Khóa vùng PyTorch dùng trạng thái chung khi giải thích, ngăn tranh chấp giữa quét và quét lại trong CDR. Hai backend chỉ công bố CDR sau khi bước quét lại trả về và lưu kiểm tra cùng audit. Hồ sơ tại [BUG-015](../../docs/bugs/BUG-015-web-cdr-job-scope-and-concurrent-xai.md).
- Hai entrypoint dùng CSS Tailwind build sẵn. Vis Network 10.1.5 được phục vụ từ cùng origin, tải khi mở sơ đồ. Markdown tải ở lượt chat đầu. Canvas trang nền vẽ lại khi resize thay vì chạy mỗi khung.
- Audit của dashboard bỏ ảnh lặp, giữ số liệu và giao API preview tải theo trang. Cache preview RAM gắn với lượt quét, số trang và hash bản sạch. Tối đa bốn mục và mỗi mục tối đa hai triệu ký tự ảnh; đổi lượt quét sẽ giải phóng cache và huỷ fetch còn chờ. API trả `no-store`; mặc định API audit giữ tương thích cho caller hiện tại.
- Hiệu ứng chuyển tab ở nút điều hướng, tránh dựng lại hiệu ứng cho cả panel. Chế độ so sánh nhớ trên trình duyệt. Chọn chế độ song song xóa tuỳ chọn đã lưu. Tay kéo cập nhật tối đa một lần mỗi khung và dùng được bằng bàn phím.

## Kết quả đo

Cùng fixture đã rà soát, phiên bản Chromium và máy với [baseline](web_p0_baseline_2026-11-20.md). Mỗi bản có 6 lượt cho mỗi cấu hình, lượt đầu dành cho trace và 5 lượt còn lại cho bảng. Số thời gian là median, trừ hàng đánh dấu p75. CPU 4× là mô phỏng trên máy desktop. Bản cuối chờ thêm tối đa 1,2 giây khi chưa nhận event LCP để giảm mẫu không quan sát được trong cache ấm. Dữ liệu phục vụ mang SHA-256 `39f37b1f0049be82a3c1c90bb84c3aa6ca22c05cb228574eb86c1ae13bbae5e7`.

| Chỉ số | Desktop trước → sau | Màn hình hẹp, CPU 4× trước → sau |
| --- | ---: | ---: |
| LCP tải lạnh (ms) | 648 → 304 | 1900 → 420 |
| Hiện kết quả quét (ms) | 1437,4 → 157,5 | 1683,2 → 490,6 |
| Event Timing click mở sơ đồ, p75 (ms) | 88 → 128 | 448 → 152 |
| Click làm sạch → ảnh sạch hiển thị (ms) | 860,1 → 396,8 | 1724,2 → 493,8 |
| Preview trang kế (ms) | 159,5 → 156,5 | 342,8 → 254,1 |
| Body JSON audit CDR (byte) | 439.895 → 7.563 | 439.895 → 7.563 |

Thử nghiệm tải Vis Network theo tab nhưng qua CDN mất 1.582,5 ms desktop và 1.704,2 ms ở CPU 4× tính đến khi có canvas (p75). Bản phục vụ asset cục bộ lần lượt là 198,2 ms và 632 ms. Baseline cũ chưa đo mốc canvas nên phép so sánh này chỉ dùng hai bản thử. Một số Event Timing click desktop tăng khoảng 32–40 ms, dù kết quả quét và preview xuất hiện sớm hơn. Số đo trên người dùng thực và phép đo mạng mobile thực chưa có. Kết quả UI đo gộp các thay đổi chức năng và asset.

## Quyết định cho các mục có điều kiện

- Lượt mở trang dùng document sẵn có, TTFB tải lạnh trung vị cuối 3,3–3,5 ms trên loopback. Hướng giữ HTML với asset theo tính năng phù hợp hơn cho kết quả hiện tại. Điều kiện thử Streaming SSR, Partial Hydration và Speculation Rules chưa đạt vì tab vẫn ở trong một document và không có công việc SSR chặn shell.
- Event Timing ở cấu hình CPU 4× cải thiện khi tách khởi tạo đồ thị, bỏ công việc nền và giảm cưỡng bức layout. Giữ cập nhật DOM trực tiếp và hiệu ứng điều hướng CSS. Signals, FLIP và View Transitions có điểm mở lại nếu trace mới chỉ ra phần DOM hoặc chuyển cảnh cụ thể.
- Đọc chi tiết lịch sử cuối mất trung vị 93,1 ms desktop và 113,6 ms ở CPU 4× tính từ bắt đầu thao tác, gồm chi phí tự động bấm. Giữ dữ liệu lịch sử mới từ server và chặn response đến sai thứ tự. Dùng SWR lịch sử khi có bằng chứng lặp lại việc chờ mạng và cơ chế đánh dấu dữ liệu cũ phù hợp. Tách tiếp ảnh preview khỏi JSON khi đo mạng thực chứng minh JSON hoặc giải mã chi phối.
- Lưu đúng một tuỳ chọn hiển thị. Đồng bộ nhiều thiết bị cần yêu cầu sản phẩm và phạm vi dữ liệu riêng. Các kết luận an toàn vẫn do server tạo.

## Bằng chứng và phạm vi xác minh

- Benchmark Chromium bản cuối hoàn thành 12/12 luồng và đối chiếu SHA-256 bản PDF tải xuống. Hai kịch bản [hồi quy trình duyệt](../../scripts/verify_web_job_state.cjs) qua DEV và ONNX cục bộ, gồm CSS và graph asset, mất phản hồi sau CDR, lỗi preview, lượt quét hết hiệu lực, Unicode, storage bị từ chối và bàn phím. Lượt quét của tiến trình DEV đã dừng trả 404 sau khi khởi động lại.
- Kiểm thử tập trung CDR, Web và runtime evidence: 56 passed trên phiên bản trước bước chuyển asset sơ đồ về cùng origin. Toàn bộ pytest trên phiên bản cuối: **2140 passed, 183 failed, 33 skipped**. Đối chiếu theo tên ca với baseline Windows trước kế hoạch, đúng cùng 183 ca thất bại và không phát sinh ca lỗi mới. Log ở `artifacts/web-improvement-pytest-20261120.log`.
- Wheel build thành công và gói đủ template, CSS, thư viện sơ đồ, giấy phép. Gate nội dung cây làm việc và `git diff --check` qua. Ảnh chụp Chromium 1365 px và 390 px xác nhận hiển thị sandbox trước/sau. Bộ dò Impeccable trên file chưa đọc được CSS qua đường dẫn API, nên kiểm tra màu của bộ dò chưa đầy đủ. Trình duyệt thật tải CSS HTTP 200 trên cả hai entrypoint.
- Trace và JSON cục bộ ở `artifacts/web-p0-final-20261120/`. Lượt thử CDN ở `artifacts/web-p0-improved-20261120/`. Cách chạy lại ở [báo cáo baseline](web_p0_baseline_2026-11-20.md), kịch bản [benchmark](../../scripts/benchmark_web_p0.cjs) và [hướng dẫn asset](../../docs/agent_architecture_and_environments.md).
- REMnux SSH timeout. Môi trường ONNX đã kiểm tra là instance cục bộ. Bản kiểm chứng để thử ở cổng 8765; tiến trình cổng 8088 khởi động trước thay đổi và cần được khởi động lại để nạp route mới.
