# Khôi phục và tối ưu bulk extractor

Tiếp tục corpus 41.727 PDF từ chunk 7, giữ toàn bộ stage `deep-static`, giới hạn LAB và bản ghi có thể đối chiếu. Dùng cả tám chunk gốc làm baseline cho pilot. Chỉ kế thừa chunk 0–6 (3.500 mẫu) cho corpus chính. Sau khi pilot đạt, xử lý lại chunk 7 vì có 60 ca cleanup chưa xác minh, rồi chạy các chunk còn lại (tổng cộng 38.227 PDF). Chunk 7 gốc được giữ trong thư mục lưu trữ định danh bởi hash checkpoint. Xem `baseline.json` để đối chiếu identity và hash.

Ngày 19/11/2026, PID 3984 và hai tiến trình con 4009, 24057 được xác minh qua start ticks và PID FD rồi dừng trên REMnux. Kiểm tra sau dừng không còn ba PID; cả tám checkpoint, 40 artifact và job/claim gốc vẫn khớp SHA-256.

- Linux bulk dùng subprocess riêng, cấu hình có giới hạn, snapshot Arlington dùng chung và IPC đọc không chặn. Giữ wall 45s, CPU 35s, RAM 1.536 MiB, 5 workers và chunk 500. Stall 4s chỉ ghi chẩn đoán.
- Xử lý bundle từng mẫu, giữ thứ tự và batch RWSE. Kiểm SHA byte gốc khi tính Markov và giới hạn bộ nhớ buffer. Quality gate phải có kết quả trùng với baseline.
- Chốt chunk sau readback dưới khóa output độc quyền. Kiểm tám chunk cũ và ledger trước khi resume. Mỗi phiên dừng nhận việc sau 85.800s, giữ trần 86.400s và giữ job tiếp tục được khi hết ngân sách.
- Dùng `.venv-windows-dev` cho kiểm tra Windows. Commit trên Windows rồi cài gateway trước runner, cùng helper hash. Queue một candidate bằng kênh staging LAB.
- Pilot candidate dùng 128 mẫu có baseline trên đĩa. So toàn bộ record và Markov. Sai khác chưa được xác minh chặn bulk. Sau pilot đạt, runner tiếp tục từ chunk 7 trong phiên `lab run` offline.
- Release gate Windows dùng `.venv-windows-dev`: full suite báo cáo riêng cho candidate và `ee646d7`. Candidate cần có tập lỗi mới rỗng và vượt qua `check_local.py` cùng bộ test tập trung.
- Readback toàn bộ corpus, cập nhật báo cáo và chỉ cách ly các thư mục cũ không làm mất bằng chứng; không xóa vĩnh viễn.
