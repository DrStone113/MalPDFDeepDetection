"""Console launcher for the already locked CIC Train/dev job."""

import argparse
import os
from pathlib import Path
import subprocess

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"

ROOT = Path(__file__).resolve().parents[1]
PREPARED_RUN = "run_20261010T172048450685Z_c3c2eeec64a6"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="Validate prepared metadata/model only; never read PDFs or launch a job")
    args = parser.parse_args(argv)
    if args.check:
        from malpdf.experiments.cic_static_benchmark import load_job
        rows, lock, _ = load_job(ROOT, PREPARED_RUN)
        schema = lock['fingerprint'].get('evidence_schema',lock['fingerprint']['code_schema'])
        print(f"Job đã khóa hợp lệ: {PREPARED_RUN}; {len(rows)} mẫu; {schema}")
        print("Chỉ kiểm tra metadata/model; chưa chạy PDF và chưa xác nhận LAB đã ngắt mạng.")
        return 0

    from malpdf.experiments.cic_v8 import v8_attempt_outcome
    outcome = v8_attempt_outcome(ROOT, PREPARED_RUN)
    if outcome is not None:
        print(f"Job đã có lượt chạy: {PREPARED_RUN}")
        print(f"Trạng thái đã lưu: {outcome['status']}")
        if outcome['recorded'] is not None:
            print(f"PDF đã xử lý: {outcome['recorded']}/{outcome['planned']}")
        if outcome['error_code'] == 'insufficient_parser_ram':
            print("Lượt trước dừng vì thiếu RAM cho parser; chưa có kết quả CIC v8.")
        if outcome['report_path']:
            print(f"report_path: {outcome['report_path']}")
        print("Giữ nguyên lượt đã lưu. Launcher không chạy lại job này.")
        try:
            input("Nhấn Enter để đóng cửa sổ: ")
        except (KeyboardInterrupt, EOFError):
            pass
        return 0 if outcome['status'] == 'completed' else 1

    print("CHẠY CIC V8 OFFLINE — 64 MẪU TRAIN/DEV", flush=True)
    print("Dùng console VMware, tài khoản thường; ngắt cả NAT và host-only.")
    print("Tắt shared folders, clipboard và drag-drop theo quy trình LAB đã chọn.")
    print(f"Job: {PREPARED_RUN}")
    try:
        answer = input("Đã làm xong các bước trên: nhấn Enter để chạy; gõ q để hủy: ")
        if answer.strip():
            print("Đã hủy; chưa chạy job.")
            return 0
        result = subprocess.run([
            str(ROOT / ".venv/bin/python"),
            str(ROOT / "scripts/16_benchmark_cic_static.py"),
            "run", "--prepared-run", PREPARED_RUN, "--lab-isolated",
        ], cwd=ROOT, shell=False)
        status = result.returncode
        if status == 0:
            print("\nĐã chạy xong. Đường dẫn báo cáo nằm trong kết quả phía trên.")
        else:
            print(f"\nJob chưa hoàn tất (mã {status}). Xem lỗi phía trên.")
    except OSError as exc:
        print(f"Không khởi động được job: {exc}")
        status = 1
    except (KeyboardInterrupt, EOFError):
        print("\nĐã dừng.")
        status = 130
    try:
        input("Nhấn Enter để đóng cửa sổ: ")
    except (KeyboardInterrupt, EOFError):
        pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
