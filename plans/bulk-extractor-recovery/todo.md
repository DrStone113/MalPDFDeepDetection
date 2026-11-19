# Checklist bulk extractor

- [x] T01 Khóa baseline và xác nhận manifest, dependency và hash
- [x] T02 Dừng writer treo đã xác minh và kiểm hash lại
- [x] T03 Tạo bộ đối chiếu canonical JSON và Markov
- [x] T04 Snapshot Arlington có tổng kiểm và round trip
- [x] T05 Bootstrap Linux và áp dụng resource limits một lần
- [x] T06 IPC không chặn và thu hồi cây worker, giữ checkpoint qua lỗi frame
- [x] T07 Tái sử dụng raw token counts
- [x] T08 Rút gọn quality gate và kiểm chứng các trường hợp từ chối
- [ ] T09 Giải phóng bundle sớm và giới hạn Markov buffer
- [ ] T10 Telemetry tiến độ và stall
- [x] T11 Kiểm chứng checkpoint và tách baseline 0–7 khỏi tập kế thừa 0–6
- [x] T12 Khóa output, công bố theo giao dịch và kiểm thử phục hồi khi thay chunk 7
- [x] T13 Kiểm thử Windows, review và đóng gói commit sạch
- [x] T14 Cài gateway rồi runner và kiểm thử Linux
- [x] T15 Chốt cấu hình kế thừa và xác minh đúng một candidate trong hàng đợi
- [ ] T16 Pilot 128 mẫu đối chiếu với output đã lưu
- [ ] T17 Resume có giới hạn theo phiên và bàn giao lab run
- [ ] T18 Readback đầy đủ output cuối
- [ ] T19 Kiểm kê và cách ly dữ liệu cũ đủ điều kiện
- [ ] T20 Đồng bộ bug registry, milestone và research log

Candidate `9297f95` đã được đóng gói từ working tree sạch. Windows có 102 test tập trung đạt, 12 skip chỉ chạy Linux và 237/237 kiểm tra synthetic đạt. Full suite có 183 lỗi ở candidate, 187 lỗi ở baseline `ee646d7`, và `new_failures = 0` khi đối chiếu định danh test. REMnux có 387 test liên quan đạt, một skip vì tệp baseline trong `plans/` nằm ngoài allowlist release.

T16 đã chạy đủ 128 mẫu và dừng ở đối chiếu: 112 khớp, 13 phục hồi có bằng chứng, 3 lệch `excluded_feature_count`. T17 đã qua kiểm thử resume với ngân sách rút ngắn và vẫn chờ pilot đạt để chạy corpus. Đợt pilot đã ghi cảnh báo stall và peak RSS mẫu của cây tiến trình. T09 còn chờ xác minh parity và có số đo bộ nhớ trên workload tương ứng. T10 còn các kiểm tra telemetry theo kế hoạch.

[Kết quả kiểm chứng và job để bàn giao](../../reports/progress/bulk_extractor_recovery_2026-11-19.md)
