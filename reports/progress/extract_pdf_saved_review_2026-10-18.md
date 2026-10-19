# Cải thiện extractor từ kết quả đang dở 2026-10-18

Lượt này chỉ đọc JSON mẫu, completion journal và báo cáo đã lưu của
`run_20261018T151430292575Z_9f5d9357bf0c`. Không đọc lại PDF nguồn, blob/payload
của corpus, render, thực thi nội dung hoặc upload dữ liệu. Mọi kiểm chứng mã
mới dùng byte và schema tổng hợp lành tính.

Run review/kiểm chứng:
[`run_20261018T153856478383Z_9f5d9357bf0c`](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/run_summary.json).
HEAD `9f5d9357bf0c83a3b3237fd9e433b78ed7ca61ac`, worktree dirty; source hash,
phiên bản và phần cứng được ghi cùng run. Không stage/commit hoặc sửa dữ liệu
nguồn; giữ các thay đổi cục bộ có trước.

## Những gì kết quả hiện tại cho thấy

Journal khớp SHA-256 của 44 JSON đã ghi đủ, trên 1.161 mẫu dự kiến. Có 36 mẫu
Train và 8 Validation; cả 44 mẫu đều có `Label=1`. Đây là prefix hoàn tất theo
thời gian của một lượt bị ngắt, không phải tập cân bằng hay kết quả toàn cohort.
1.117 mẫu chưa có JSON hoàn tất vẫn nằm trong mẫu số dự kiến.

| Trạng thái bundle đã lưu | Số mẫu |
| --- | --- |
| observed | 3 |
| unsupported | 14 |
| resource_limit | 19 |
| decode_error | 2 |
| partial | 6 |

Bốn worker thoát với mã `-9`, không có final-result marker. Worker có RSS lấy
mẫu cao nhất trong nhóm này là 4.490.055.680 byte. SIGKILL và RSS lấy mẫu không
đủ chứng minh OOM hoặc xác định bên gửi signal. Các JSON mẫu cộng lại chiếm
2.187.820.286 byte, chứa 1.108.390 bản ghi kiểm tra Arlington.

Kiểm kê 24.582 binding Arlington theo khóa thô `(model_table,
xref_context_distance, source_refs)` thấy 2.903 nhóm, 21.679 lượt lặp khóa và
một nhóm xuất hiện 722 lần. Có 18 nhóm cùng khóa thô nhưng outcome khác nhau;
không được gộp tất cả bằng khóa này. Chu trình, độ sâu, version và trạng thái
đánh giá phải được xét trước khi tái dùng. Xem
[binding_audit.json](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/binding_audit.json).

Run nguồn có `status=interrupted` nhưng thiếu `coverage_summary.json` và
`output_path`/số hàng hoàn tất trong run summary. Journal/JSON vẫn tồn tại.
Review lưu kết quả riêng, không bổ sung hoặc ghi đè báo cáo lịch sử. Các số đo
worker/backend và limitations gốc nằm trong
[saved_inventory.json](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/saved_inventory.json).

## Các sửa đổi

Arlington dùng memo trong phạm vi một raw document bất biến, có khóa riêng cho
nguồn object, model, revision, version và stream/dictionary context. Chỉ kết
quả hoàn tất mới được lưu. Subtree không có chu trình phải không đụng tổ tiên
đang active và phải vừa độ sâu còn lại. Kết quả phụ thuộc chu trình chỉ tái
dùng khi tập tổ tiên active và độ sâu lúc vào giống hệt. Chu trình hoặc rule
chưa hỗ trợ vẫn là unknown; không biến thành pass hay absence.

Mỗi lần tái dùng có `arlington_binding_reuse`, nguồn raw/parent binding và cạnh
tới binding chuẩn đã đánh giá. Đường liên kết được hash; raw IR và primary
legacy không đổi. `arlington_candidate_checks_*` đếm các phép kiểm tra thực
sự lưu, mỗi đánh giá được chia sẻ chỉ tính một lần; feature
`arlington_reused_schema_bindings` đếm lần tái dùng riêng. Không so sánh thẳng
với multiplicity per-path cũ. Policy bounded giữ cách duyệt cũ.

Raw forensic tách `forensic_xref_offset_invalid` cho offset ngoài file khỏi
`forensic_xref_count_limit` cho hết số block được phép duyệt. Offset hỏng không
còn tự bị gọi là hết tài nguyên; không sửa hoặc tin xref hỏng. Các lý do về
giải nén, chu trình, parser và giới hạn khác vẫn giữ nguyên phạm vi.

Runner ghi số hàng, đường output và coverage trong một `finally` riêng, kể cả
khi đóng iterator/dọn worker bị ngắt. Fixture tái hiện ngắt ở cleanup vẫn lưu
được một hàng đã hoàn tất và resume hàng đó ở lượt sau. Điều này không bảo đảm
ghi báo cáo khi cả tiến trình bị kill hoặc lại bị ngắt giữa lúc ghi báo cáo.

## Kiểm chứng riêng trên dữ liệu tổng hợp

So sánh rule evaluation bật/tắt memo trên cùng raw IR tổng hợp, mỗi cấu hình
một lần. Đo thời gian có bật `tracemalloc`; peak là allocation Python được
trace trong evaluation, không phải RSS của worker hay toàn pipeline.

| Fixture | Phép kiểm tra trước → sau | Thời gian trước → sau | Peak Python allocation trước → sau |
| --- | --- | --- | --- |
| DAG dùng chung nhiều đường | 5.376 → 133 | 0,9867 → 0,0257 giây | 4.901.810 → 159.507 byte |
| Schema thay thế có chu trình | 1.031 → 317 | 0,2146 → 0,0637 giây | 1.017.499 → 386.561 byte |

Tập rule semantics sau khi bỏ ID/multiplicity trùng và root outcomes khớp
reference per-path cho cả hai fixture. DAG vẫn pass; fixture chu trình vẫn
indeterminate. Bản JSON analysis giảm từ 3.604.392 xuống 94.312 byte và từ
712.938 xuống 229.398 byte tương ứng. Xem
[synthetic_rule_performance.json](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/synthetic_rule_performance.json).
Không suy các tỉ lệ này thành tốc độ/RAM của corpus thật hoặc khẳng định đã
giải quyết mọi SIGKILL.

| Kiểm chứng cuối | Kết quả |
| --- | --- |
| Toàn bộ `pytest tests/` | 1.874 passed, 2 warning sklearn single-label ở vision smoke test, 213,80 giây |
| Regression mới | 14 passed, 4,07 giây |
| Schema Draft 2020-12 độc lập | 6 store từ 2 bundle mới hợp lệ; reference ngoài bị chặn |
| Source JSON/journal | 44/44 hash khớp |
| Tokenizer trên 33 file mã đã sửa trong worktree | 0 comment |
| Dependency | `No broken requirements found.` |
| Whitespace | `git diff --check` đạt |

Các test kiểm shared DAG, cyclic alternatives, ancestor/depth guard,
version/xref/stream context, Unknown, unfinished evaluation, bounded behavior,
reuse source/target, xref lỗi và ngắt cleanup/resume. Bằng chứng và hash log tại
[validation_checks.json](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/validation_checks.json).

Môi trường là Python 3.11.17, PyTorch 2.11.0+cpu, 4 CPU khả dụng, khoảng
7,7 GiB RAM và không có CUDA. Package/native versions đầy đủ tại
[runtime_environment.json](../experiments/extraction_saved_review/run_20261018T153856478383Z_9f5d9357bf0c/runtime_environment.json).
Không cài dependency mới.

Chưa đo lại corpus bằng mã mới hoặc huấn luyện/đánh giá mô hình. F1 malicious,
MCC, ECE và Brier là N/A; `Label=1` là malicious. Thay đổi source fingerprint
làm cache của mã cũ không tương thích; kết quả cũ vẫn giữ để đối chiếu. Chỉ
chạy PDF thật khi người dùng xác nhận LAB cô lập và yêu cầu chạy. Lệnh và hợp
đồng hiện tại nằm trong [hướng dẫn VM](../../docs/extraction_vm.md).
