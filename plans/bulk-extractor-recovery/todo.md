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
- [ ] T13 Kiểm thử Windows, review và đóng gói commit sạch
- [ ] T14 Cài gateway rồi runner và kiểm thử Linux
- [ ] T15 Kế thừa job, queue candidate
- [ ] T16 Pilot 128 mẫu đối chiếu với output đã lưu
- [ ] T17 Resume có giới hạn theo phiên và bàn giao lab run
- [ ] T18 Readback đầy đủ output cuối
- [ ] T19 Kiểm kê và cách ly dữ liệu cũ đủ điều kiện
- [ ] T20 Đồng bộ bug registry, milestone và research log

Kiểm chứng bản sửa review: Windows 102 passed / 12 Linux-only skipped.
REMnux 147 passed / 1 skipped (tệp baseline trong `plans/` nằm ngoài allowlist release).
