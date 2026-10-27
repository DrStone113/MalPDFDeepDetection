# Cohort CIC đầy đủ (1 452 mẫu) — bản nháp chờ duyệt

Trạng thái: **đề xuất, chưa duyệt, chưa code**. Tài liệu này không thay đổi
policy, manifest hay bất kỳ tệp nào trên LAB. Không có PDF nào được đọc để soạn
nó; mọi số liệu tham chiếu lấy từ job CIC64 đã chạy (`observed 1 · partial 2 ·
failed 61 · primary 64 · elapsed 732 903 ms`).

## 1. Mục tiêu

- Gần: cohort CIC64 chạy shard ổn định, có coverage trung thực (đang chờ deploy).
- Xa: trích xuất static feature cho toàn bộ corpus CIC (1 452 mẫu) và rút ngắn
  thời gian chạy.

Ràng buộc bất biến không đổi: PDF thật chỉ nằm trên REMnux; Windows không nhận
mẫu, bundle hay văn bản trích xuất; agent không chạy job PDF thật, không `sudo`,
không nhập mật khẩu.

## 2. Vì sao không thể chỉ "nâng 64 lên 1 452"

| Chốt chặn | Vị trí | Hệ quả |
| --- | --- | --- |
| `select_subset(count=32)` chỉ nhận `8 ≤ count ≤ 256`, `count` chẵn | `src/malpdf/experiments/cic_static_benchmark.py:140` | Không thể chọn 1 452; trần cứng là 256 |
| Chỉ lấy `train` + `validation`, `count//2` mỗi nhãn mỗi partition | cùng hàm | 1 452 sẽ cần 363/nhãn/partition; `test` bị loại khỏi thiết kế hiện tại |
| `policy('pdf-static')` cố định `samples=64, workers=5` | `scripts/lab/lab_jobs.py` | `job['limits']` được so **bằng đẳng thức** ở cả Windows và LAB, nên đổi số mẫu là đổi policy/hash |
| `cohort_contract` hard-code `train 32 / validation 32 / test 0` và đòi `samples_per_partition == 32` | `scripts/lab/offline_prepare.py:71` | Chuẩn bị offline sẽ từ chối cohort khác |
| `pdf_worker` đòi `len(rows) == limits['samples']`, `planned == limits['samples']` | `scripts/lab/lab_runner.py`, `lab_jobs.validate_result` | Report sai số mẫu bị `report_invalid` |

Vì policy tham gia hash, **mỗi lần đổi số mẫu là một chuỗi cài đặt 4 bước**
(gateway → transfer → runner → transfer). Đây là chi phí thật cần tính vào thiết
kế, không phải chi tiết thủ tục.

## 3. Đề xuất kỹ thuật

### 3.1 Kind mới thay vì sửa `pdf-static`

Theo tiền lệ `pdf-static-cve`, thêm kind `pdf-static-cic-full` với policy riêng:

```
samples        1452          (đo lại nếu manifest thực tế khác)
workers        5             (không đổi khi chưa có số đo peak_rss mới)
wall_seconds   5400          (đề xuất; xem §4)
output_bytes   2 GiB         (đề xuất; xem §4)
file_*         giữ nguyên 20 s wall / 12 s CPU / 10 MiB / 1 GiB
```

Giữ `pdf-static` (CIC64) nguyên trạng để kết quả cũ vẫn so sánh được và để
rollback chỉ là "dùng lại kind cũ". Không đổi `KINDS` của gateway
syntax/synthetic; kind PDF vẫn chỉ chạy offline ở console.

### 3.2 Hàm chọn cohort mới

`select_corpus(manifest, sources)` trong `cic_static_benchmark.py`:

- lấy **toàn bộ** hàng `cohort == 'cic'`, giữ nguyên `split` gốc;
- thứ tự tất định (`sample_id`) để shard `index % workers` ổn định giữa các lần;
- dùng lại toàn bộ kiểm tra của `select_subset`: `sample_id` duy nhất, nhãn khớp
  giữa split/source, `duplicate_group_id`/`pdf_sha256`/`related_group_id` không
  cắt qua partition, đường dẫn nằm trong `data/raw/cic_pdf`, hash 64 hex;
- **fail-closed** nếu tổng số hàng ≠ 1 452: corpus trôi thì dừng, không lặng lẽ
  chạy thiếu;
- không đọc PDF, chỉ đọc CSV manifest đã ghim sha256.

`cohort_contract` in ra phân bố thật (`train/validation/test` theo nhãn) cùng
seed 42 và sha manifest, để người duyệt thấy chính xác mình đang duyệt gì.

### 3.3 Ranh giới leakage

Trích xuất feature cho **cả** `test` là hợp lệ: đó là đo đạc, không phải fit.
Điều kiện đi kèm, phải ghi trong manifest và trong `reports/research_log.md`:

- mọi fit/tune/threshold vẫn chỉ dùng `train` (fit) và `validation` (chọn);
- `test` chỉ được dùng một lần cho báo cáo cuối, sau khi đóng băng phương pháp;
- không dùng phân bố của `test` để chọn feature, kể cả "chỉ để xem".

Nếu mục tiêu chỉ là train/val, thì 1 452 **không phải** con số đúng; khi đó cần
nêu rõ "toàn corpus để trích xuất" khác "cohort huấn luyện".

## 4. Chi phí và tài nguyên (cần số đo trước khi chốt policy)

- **Thời gian**: 11,45 s/file với 1 worker → 1 452 × 11,45 ÷ 5 ≈ 55 phút nếu
  song song tuyến tính. Thực tế thường kém hơn vì 5 shard cùng load Arlington
  catalog và cùng tranh CPU/RAM. `wall_seconds = 5400` cho ~60% biên.
- **RAM**: mỗi shard giữ `RLIMIT_AS` 2 GiB như lượt chạy đơn (trần địa chỉ, không
  phải RSS), trong khi mỗi parser vẫn bị `file_memory_bytes` 1 GiB. 5 shard trên
  VM 6 GB là mức đã chọn; chưa có `peak_rss_bytes` thật của shard nên **không
  tăng `workers`**. Nếu thấy `resource_limit` trong `status_counts` hoặc VM swap,
  hạ `workers` chứ đừng đoán mò trần địa chỉ.
- **Đĩa**: `output_bytes` phải ≥ tổng bundle thật + biên. Cần đo
  `du -sh /var/lib/malpdf/jobs/<job_cic64>/private_bundles` tại console (chỉ là
  kích thước, không xuất nội dung) rồi nhân lên; `pdf_task` từ chối chạy nếu đĩa
  trống < `output_bytes + 256 MiB`.
- **Thời gian job dài**: 55 phút là cửa sổ rủi ro cao hơn 12 phút. Nếu VM bị
  treo giữa chừng, job đã `claim` sẽ không chạy lại; bundle dở vẫn nằm trong
  `private_bundles/` nhưng không có resume.

## 5. Câu hỏi phải trả lời trước khi duyệt

1. Corpus CIC trên LAB có đúng 1 452 tệp không? (kiểm bằng đếm hàng manifest,
   chỉ metadata, không đọc PDF.)
2. 1 452 đó phân bố thế nào giữa `train`/`validation`/`test` và hai nhãn? Nếu
   `test > 0` thì mục tiêu là "trích xuất toàn corpus", và cần ghi rõ điều đó.
3. Bundle trung bình bao nhiêu byte và `peak_rss_bytes` của một shard là bao
   nhiêu (lấy từ job CIC64)?
4. Có chấp nhận "không resume" cho lượt 55 phút, hay cần thiết kế resume trước?
   (Resume là thay đổi riêng: job id bất biến, `already_claimed`, không ghi đè.)

## 6. Lộ trình đề xuất

| Nấc | Nội dung | Chi phí cài đặt | Mục đích |
| --- | --- | --- | --- |
| 0 | CIC64 shard (đã code, chờ deploy) | 1 chuỗi 4 bước | Chứng minh shard + coverage thật |
| 1 | Đo tại console: `du`, `peak_rss_bytes`, `status_counts`, `lab compare` | không | Chốt số cho policy 1 452 |
| 2 | `pdf-static-cic-full` (1 452) | 1 chuỗi 4 bước nữa | Mục tiêu xa |

Bỏ nấc trung gian 256: nó cũng cần một chuỗi cài đặt riêng mà không trả lời
được câu hỏi nào khác ngoài "chạy lâu hơn có ổn không", trong khi nấc 0 đã đo
được điều đó với 64 mẫu.

## 7. Không nằm trong đợt này

- Không đổi Protocol G, split, nhãn hay seed.
- Không nới guard, không bỏ kiểm tra hash, không cho gateway nhận kind PDF.
- Không tự chạy job thật, không export bundle/ảnh/bảng ra Windows.
- Không sửa `text_failure` cho f-string (việc riêng, cần Python 3.12 để test).
- Không tối ưu tốc độ bằng cách bỏ kiểm tra checksum/`require_extraction_lab`.

## 8. Definition of done

Nấc 0: job CIC64 shard cho `status_counts` khớp tổng `completed`, `lab compare`
với lần chạy đơn báo `identical = 64`, `same_commit = true`, và thời gian giảm
còn khoảng 1/5.

Nấc 2: job 1 452 chạy trọn trong `wall_seconds`, `planned = 1452`,
`sum(status_counts) = completed`, report được `validate_result` chấp nhận, và
mọi kết luận về coverage được viết theo histogram thật, không suy diễn.
