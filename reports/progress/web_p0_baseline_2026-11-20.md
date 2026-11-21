# Baseline P0 của web MalPDF

Đo ngày 2026-11-20 trên instance DEV riêng ở `127.0.0.1:8765`, có thay đổi UI/CDR đang làm trên nền `bf13a6e73d9141d62b833c896bbac45d6c77700f`. Chromium headless 156.0.8078.4, Windows, Intel Core i5-14400F. Backend dùng CPU, tải được trọng số PDF-TransGraph v2 (23D), pikepdf 10.17.0. HTML trả về khớp SHA-256 của template đang làm (`00517cba5ca3892641b151424e3f688c02f34e1b46f133c6b1619ac0d526f597`).

## Kết quả

Mỗi cấu hình chạy 6 lượt. Lượt đầu có Performance trace và được giữ riêng. Bảng dùng 5 lượt còn lại cho mỗi cấu hình, trình bày median / p75 gần nhất theo thứ hạng. Mỗi lượt tạo browser context mới cho cache lạnh và reload cùng context cho cache ấm. Backend dùng cùng tiến trình trong toàn bộ lượt đo. Mạng không throttle; CPU 4× chỉ tác động lên Chromium. Cấu hình màn hình hẹp đồng thời thay đổi viewport và CPU nên chênh lệch so với desktop gồm cả hai yếu tố.

| Chỉ số lab (ms) | Desktop 1365 × 900 | Màn hình hẹp 390 × 844, CPU 4× |
| --- | ---: | ---: |
| LCP tải lạnh | 648 / 1112 | 1900 / 2004 |
| LCP tải ấm | 128 / 128 | 588 / 588 |
| TTFB tải lạnh | 2,9 / 3,1 | 3,8 / 5,1 |
| Quét backend báo | 66,2 / 66,3 | 66,5 / 68,3 |
| Chọn fixture → kết quả quét hiện | 1437,4 / 1441,8 | 1683,2 / 1704,6 |
| Click mở sơ đồ lần đầu, Event Timing | 88 / 88 | 440 / 448 |
| Mở sơ đồ → có số nút | 171,2 / 175,1 | 780,7 / 823,0 |
| Click Làm sạch, Event Timing | 96 / 96 | 120 / 120 |
| CDR backend báo, trước quét lại | 166,0 / 166,2 | 164,2 / 164,5 |
| Quét lại bản sạch backend báo | 63,8 / 64,2 | 67,8 / 69,2 |
| Bắt đầu thao tác CDR → đọc hết response | 777,0 / 777,5 | 1521,0 / 1522,1 |
| Bắt đầu thao tác CDR → preview bản sạch hiện và decode được | 860,1 / 863,7 | 1724,2 / 1756,7 |
| Sang trang sau → preview hiện và decode được | 159,5 / 168,2 | 342,8 / 349,7 |

Event Timing là duration của entry `click` từ Chromium trong phiên lab. Các mốc thao tác → kết quả còn gồm chi phí Playwright, ví dụ cuộn tới nút và chờ nút có thể bấm. Thời gian backend lấy từ các trường API của từng giai đoạn. INP thực tế p75 và CLS thực tế để `null`. Probe chỉ lưu tổng layout shift ngoài tương tác trong khoảng tải trang, vì vậy trường này không được dùng như CLS chính thức.

**Payload.** HTML giải mã 286.994 B, tổng truyền document 287.294 B theo Navigation Timing ở cả hai cấu hình. JSON scan khoảng 44.296 B, audit CDR 439.895 B, preview trang đầu trước CDR 326.820 B, cặp preview trang đầu sau CDR 653.513 B và cặp preview trang 2 là 818.241 B. Số B của API là độ dài body JSON đọc ở client.

**Độ tin cậy trên fixture.** 12/12 lượt chạy hoàn tất quét từ giao diện, mở sơ đồ, CDR, đổi trang và tải bản đã làm sạch. Bản tải khớp SHA-256 audit, giữ 2 trang, có chữ và đạt các cờ toàn vẹn của API. Không ghi nhận JavaScript page error hoặc request bị lỗi mạng trong probe. Kết quả phục vụ baseline trên một fixture đã rà soát. PDF của người dùng, tài liệu dài và lỗi đổi job khi request chưa xong vẫn cần bài riêng.

## Thứ tự tối ưu sau khi có baseline

1. Bỏ thời gian chờ hiệu ứng bắt buộc sau khi đã có kết quả quét. Mã hiện chờ tối thiểu 950 ms rồi giữ trạng thái hoàn tất 180 ms khi không bật reduced motion. Đo lại thời gian hiện kết quả và giữ phản hồi pending khi backend còn xử lý. [Mã scan UI](../../src/malpdf/web/templates/index.html#L2092)
2. Tách thử một thay đổi để giảm độ trễ mở sơ đồ. Trace CPU 4× ghi nhận callback ngay sau đổi tab khoảng 93 ms và các lượt layout lên tới khoảng 116 ms trong một trace. Đo riêng phản hồi tab, lần vẽ sơ đồ đầu và lần mở lại. [Mã đổi tab](../../src/malpdf/web/templates/index.html#L1982)
3. Đo riêng chi phí khởi tạo CDN và ảnh preview. Trace CPU 4× ghi một lượt thực thi Tailwind khoảng 195 ms và vis-network khoảng 166 ms. Thử CSS build sẵn hoặc tải sơ đồ theo tab độc lập để phân biệt lợi ích. Với CDR, đo riêng server dựng PNG, phản hồi JSON, decode và render trước khi đổi hợp đồng API.

## Chạy lại và giới hạn

Chạy ở thư mục gốc. Dùng bản Playwright và Chromium tương ứng nếu cần so sánh trực tiếp.

```powershell
# Terminal 1
$env:MALPDF_QUARANTINE_DIR = 'artifacts/web-p0-quarantine'
.venv/Scripts/python.exe scripts/malpdf_web.py --port 8765

# Terminal 2
# Có thể đặt MALPDF_PLAYWRIGHT_MODULE và MALPDF_CHROMIUM_EXE để chọn runtime cục bộ.
node scripts/benchmark_web_p0.cjs artifacts/web-p0-baseline-rerun 6
```

Đầu ra của lượt đo nằm trong `artifacts/web-p0-baseline-20261120/`, gồm measurements JSON và trace đầu của từng cấu hình. Bản production đang triển khai, trình duyệt khác, mobile thật, kéo slider liên tục và lịch sử chưa được đo. Mã production có entrypoint riêng và cache template theo tiến trình. Dashboard cổng 8088 vẫn chạy tiến trình cũ tại thời điểm kiểm tra. Kết quả của instance 8765 chỉ áp dụng cho bản DEV được đo.
