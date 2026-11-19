# Khôi phục và tối ưu bulk extractor

Tiếp tục 41.727 PDF từ chunk 8, giữ toàn bộ stage `deep-static`, giới hạn LAB và bản ghi có thể đối chiếu. Tám chunk baseline được giữ chỉ đọc. Xem `baseline.json` để đối chiếu identity và hash.

Ngày 19/11/2026, PID 3984 và hai tiến trình con 4009, 24057 được xác minh qua start ticks và PID FD rồi dừng trên REMnux. Kiểm tra sau dừng không còn ba PID; cả tám checkpoint, 40 artifact và job/claim gốc vẫn khớp SHA-256.

- Linux bulk dùng subprocess riêng, cấu hình có giới hạn, snapshot Arlington dùng chung và IPC đọc không chặn. Giữ wall 45s, CPU 35s, RAM 1.536 MiB, 5 workers và chunk 500. Stall 4s chỉ ghi chẩn đoán.
- Xử lý bundle từng mẫu, giữ thứ tự và batch RWSE. Kiểm SHA byte gốc khi tính Markov và giới hạn bộ nhớ buffer. Quality gate phải có kết quả trùng với baseline.
- Chốt chunk sau readback dưới khóa output độc quyền. Kiểm tám chunk cũ và ledger trước khi resume. Mỗi phiên dừng nhận việc sau 85.800s, giữ trần 86.400s và giữ job tiếp tục được khi hết ngân sách.
- Dùng `.venv-windows-dev` cho kiểm tra Windows. Commit trên Windows rồi cài gateway trước runner, cùng helper hash. Queue một candidate bằng kênh staging LAB.
- Pilot candidate dùng 128 mẫu có baseline trên đĩa. So toàn bộ record và Markov. Sai khác chưa được xác minh chặn bulk. Sau pilot đạt, operator tiếp tục từ chunk 8 bằng `lab run` offline, theo nhiều phiên nếu cần.
- Readback toàn bộ corpus, cập nhật báo cáo và chỉ cách ly các thư mục cũ không làm mất bằng chứng; không xóa vĩnh viễn.
