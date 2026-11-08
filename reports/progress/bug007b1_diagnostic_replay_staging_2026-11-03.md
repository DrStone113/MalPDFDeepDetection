# BUG-007B1 — Diagnostic Replay staging — 2026-11-03

**B1 đã triển khai và staging; chưa chạy lại PDF, chưa hoàn tất phân loại nguyên nhân.** B2 audit 465 graph bị cap và B3 quality gate chưa thực hiện. Không huấn luyện.

## Job chờ operator

- Job: `5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0`.
- Kind: `pdf-diagnostic-replay`; mode: `offline`; trạng thái xác minh: `queued`, chưa có claim/result hoặc private case.
- Đúng 74 mẫu: 70 worker failure chưa rõ nguyên nhân và 4 timeout; index 141 không thuộc replay.
- Split giữ nguyên: 45 train, 17 validation, 12 test; nhãn 1: 41, nhãn 0: 33.
- Output riêng: `/var/lib/malpdf/jobs/5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0/`.
- Chỉ có job này trong pending; `lab run` không cần job ID hoặc tham số khác.

Theo [human gate của AGENTS.md](../../docs/agent_workflow_and_gates.md), operator thực hiện trong console REMnux, với các điều kiện cách ly/attestation hiện hữu:

```bash
lab run
```

Agent chưa gọi extractor/parser trên 74 PDF này qua SSH. Việc queue, kiểm tra metadata và checksum không phải lượt replay thực tế. Guest networking không được thay đổi tự động.

## Những gì đã sẵn sàng

`configs/pdf_diagnostic_replay.json` khóa baseline job/result, canonical selection, audit cases, index/SHA/nhãn/split, checksum từng bundle và hash source parser/graph được bảo vệ. Staging đã xác minh cả 74 bundle và đường dẫn/size PDF qua metadata.

Lượt replay dùng đúng giới hạn baseline, chỉ giảm số mẫu xuống 74: 35 s wall / 30 s CPU / 1 GiB / 10 MiB mỗi PDF, 10 outer worker, job wall 7200 s, output 2 GiB. Parser, định nghĩa graph, node cap 200 và các mặc định object/decode/AST giữ nguyên. Không lấy bundle lỗi baseline làm kết quả mới; chỉ cho resume các case/bundle đã được xác minh của cùng job replay.

Diagnostic được lưu trước normalization tại `private_attempts/.../worker.json`; bundle và comparison riêng cho từng ordinal tại `private_bundles/` và `private_cases/`. Kích thước node/feature chưa đo giữ `null`; graph không đo được giữ `null`, tách khỏi projection thực sự đo được có 0 node.

Đã bổ sung bảo toàn diagnostic của outer shard trước khi process thoát: traceback có cấu trúc, phase, elapsed, stdout/stderr giới hạn và exit trước/sau supervisor cleanup. Đọc transport bằng `pread` tại LAB để không thay offset ghi của process đang chạy. Lỗi ghi diagnostic không được ngăn cleanup. Khi outer worker lỗi, post-run analysis vẫn được gọi; `outer_diagnostics.json` liên kết shard với baseline indices được giao, không giả rằng các PDF chưa chạy đã được trích xuất.

Sau lượt chạy, runner tự tạo `analysis/cases.jsonl`, `summary.json`, `report.md`, `outer_diagnostics.json` và manifest checksum. Đủ 74 identity trong denominator; case thiếu/invalid giữ `null`. Traceback an toàn không chứa exception message/source/locals. Stderr thô chỉ ở private LAB artifacts; bản export có byte count/hash và capture flags. Nhóm cùng diagnostic signature chỉ là nhóm điều tra, không phải kết luận cùng nguyên nhân gốc. SIGKILL không được tự gắn OOM hoặc corrupt PDF.

Hợp đồng chi tiết: [diagnostic_replay.md](../../docs/diagnostic_replay.md).

## Kiểm chứng

| Phạm vi | Baseline BUG-007A | B1 cuối | Đối chiếu |
| --- | --- | --- | --- |
| Full Windows | 1990 passed / 200 failed / 24 skipped | 2020 passed / 200 failed / 25 skipped | Khớp đúng 200 failed ID; 0 failed mới |
| REMnux, nhóm worker/extraction/audit/export | 232 passed / 5 failed / 0 skipped | 263 passed / 5 failed / 0 skipped | Khớp đúng 5 failed ID; 0 failed mới |
| Windows tập trung | — | 197 passed / 4 skipped | Gồm các ca bảo vệ diagnostic và workflow |

31 test mới: Windows 30 passed/1 skipped do yêu cầu Linux; REMnux đủ 31 passed. 5 lỗi REMnux gồm 4 assertion/source baseline và 1 assertion Git provenance do package QA độc lập không chứa Git metadata; đây không phải full suite REMnux.

377 file Python qua AST, 0 Python comments. Mutation test đảo điều kiện cấm cache baseline trong bản copy source cô lập đã bị test phát hiện; worktree không thay đổi. Content guard của snapshot sạch qua toàn bộ 416 file. Index guard của repo chính qua; `--worktree` vẫn báo 3 PNG có sẵn trong `UI_Example` ngoài allowlist, được giữ nguyên. Không giảm guard hoặc sửa test baseline.

## Bảo toàn và provenance

- Đã đối chiếu checksum cả 1.452 bundle với audit: 0 thay đổi. Job/result/selection gốc giữ nguyên, gồm hash file selection và hash canonical rows; SHA/nhãn/split giữ nguyên.
- Source commit riêng trên Windows: `107aac7a93b6a465c998ae785251a1477832a7cd`. HEAD/index repo chính giữ nguyên, không commit/push các thay đổi đang có của người dùng.
- Archive SHA-256: `832a959a05702201f323ee4d266d1e5437d1d00c7dea4db1554fa0f6fac182d7`.
- Source manifest SHA-256: `0fdffefc35e3287b21efb53cfd41875a34a0460ce3e0e44ab94e990ea6333fb0`; 416 file qua verify tại LAB. QA package riêng có 422 file, gồm fixture benign đã có.
- `locked_methodology.json` của job có SHA-256 `743db0590bd6c50d0bc22a3432c217e10047d1116d7f6f1a39d1a0097b445043`, ghi đủ manifest, limits và environment. Runtime parser Python 3.11.17; pypdf 6.18.1, PyMuPDF 1.26.7, pikepdf 10.17.0; các thread setting đều 1.
- Hai helper console được cập nhật với backup tại `/var/lib/malpdf/bootstrap-backups/bug007b1_5fb4b0967c68`. Gateway config/proof và SSHD không đổi; restricted gateway có trạng thái chưa verified từ trước và tiếp tục fail closed. Không gọi đây là kiểm chứng gateway production.
- Draft staging `5d49b68594f6...` được đánh dấu blocked/superseded **trước khi có claim hoặc PDF attempt** để bổ sung diagnostic outer worker. Toàn bộ draft được giữ lại; final job là pending duy nhất.

## Điều kiện tiếp tục

B1 còn chờ operator trigger và kết quả thật của 74 mẫu. Sau chạy, cần xác minh checksum/identity, số case và diagnostic, phân loại theo bằng chứng và đối chiếu baseline trước khi đề xuất sửa worker/parser/timeout. B2 và B3 được giữ thành các phần độc lập; chưa đủ điều kiện huấn luyện lại.

Bằng chứng khóa: [validation.json](../experiments/diagnostic_replay/run_20261103_B1_staging_5fb4b0967c68/validation.json), [locked_methodology.json](../experiments/diagnostic_replay/run_20261103_B1_staging_5fb4b0967c68/locked_methodology.json), [manifest.json](../experiments/diagnostic_replay/run_20261103_B1_staging_5fb4b0967c68/manifest.json).
