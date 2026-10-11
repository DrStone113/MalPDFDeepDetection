"""V9 console menu and metadata-only preparation entry point."""

import argparse
import json
import os
from pathlib import Path

for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[name] = "1"

ROOT = Path(__file__).resolve().parents[1]


def _outcome(workflow):
    outcome = workflow.v9_campaign_outcome(ROOT)
    if outcome is None:
        print("V9 chưa dùng lượt benchmark final.")
    else:
        print(f"Trạng thái final đã lưu: {outcome['status']}")
        print(f"report_path: {outcome['report_path']}")
        print("Lượt final đã được giữ nguyên; tạo job khác không cấp thêm lượt.")
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Read prepared metadata/status only")
    parser.add_argument("--action", choices=("prepare", "integration", "seal", "final", "status"))
    parser.add_argument("--prepared-run")
    parser.add_argument("--integration-run")
    parser.add_argument("--validation-run")
    parser.add_argument("--lab-isolated", action="store_true")
    args = parser.parse_args(argv)
    from malpdf.experiments import cic_v9 as workflow
    try:
        if args.check:
            if _outcome(workflow) is None:
                identifier = args.prepared_run or workflow.latest_v9_job(ROOT)
                rows, lock, _ = workflow.load_v9_job(ROOT, identifier)
                print(f"Job V9 đã khóa: {identifier}; loại: {lock['kind']}; {len(rows)} mẫu")
            print("Chỉ đọc metadata/báo cáo; chưa đọc PDF, load pickle hoặc xác nhận LAB.")
            return 0
        action = args.action
        if action is None:
            if _outcome(workflow) is not None:
                return 0
            print("CHẠY CIC V9 OFFLINE — CONSOLE VMWARE")
            print("1. Integration: ba mẫu từng lỗi AttributeError (Enter)")
            print("2. Final: cùng64 mẫu, một lượt đã khóa")
            print("3. Đọc trạng thái đã lưu; q. Đóng")
            choice = input("Chọn mục rồi Enter: ").strip()
            if choice in {"q", "Q"}:
                return 0
            action = {"": "integration", "1": "integration", "2": "final", "3": "status"}.get(choice)
            if action is None:
                print("Mục chưa hợp lệ; chưa chạy job.")
                return 1
            if action != "status":
                print("Dùng tài khoản thường; ngắt NAT và host-only.")
                print("Tắt shared folders, clipboard và drag-drop theo quy trình LAB đã chọn.")
                if input("Đã cô lập LAB: nhấn Enter để chạy; gõ q để hủy: ").strip():
                    print("Đã hủy; chưa chạy job.")
                    return 0
                args.lab_isolated = True
        if action == "status":
            _outcome(workflow)
            return 0
        if action == "prepare":
            result = workflow.prepare_v9(ROOT)
        elif action == "seal":
            integration = args.integration_run or workflow.latest_v9_prerequisite(ROOT,
                workflow.INTEGRATION_STUDY, "integration_evidence.json")
            validation = args.validation_run or workflow.latest_v9_prerequisite(ROOT,
                workflow.VALIDATION_STUDY, "validation_evidence.json")
            result = workflow.seal_v9_final(ROOT, integration, validation)
        else:
            try:
                identifier = args.prepared_run or workflow.latest_v9_job(ROOT, kind=action)
            except ValueError:
                if action == "final":
                    print("Final chưa được khóa. Cần ghi nhận báo cáo integration và tạo khóa cùng fingerprint đã kiểm thử.")
                raise
            runner = workflow.run_v9_integration if action == "integration" else workflow.run_v9_final
            result = runner(ROOT, identifier, lab_attested=args.lab_isolated)
        if result.get("integration_status") is not None:
            status = "ĐẠT" if result["integration_status"] == "passed" else "CHƯA ĐẠT"
            print(f"Kiểm tra integration: {status}.")
            print("Các giá trị passed là kiểm tra pipeline; recall/FPR được đo ở Final.")
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
        print(f"report_path: {result['report_path']}")
        return 0 if result.get("integration_status") != "blocked" else 1
    except (ValueError, OSError, KeyError) as error:
        print(f"V9 chưa hoàn tất: {type(error).__name__}: {error}")
        print("Giữ nguyên báo cáo/lượt đã lưu. Không tự chạy lại benchmark final.")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Đã dừng. Evidence và claim đã có được giữ nguyên.")
        return 130
    finally:
        if args.action is None and not args.check:
            try:
                input("Nhấn Enter để đóng cửa sổ: ")
            except (KeyboardInterrupt, EOFError):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
