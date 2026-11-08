"""Interactive console entry for one explicitly selected, sealed static job."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from malpdf.extraction import jobs
from malpdf.experiments.cic_static_benchmark import clean_code

LAB_ISSUES = {
    "Use a non-root analysis account": "Dùng tài khoản thường tại VMware console.",
    "Use VMware console; SSH session present": "Mở launcher từ VMware console, ngoài phiên SSH.",
    "Disconnect all host/Internet network adapters": "Tự ngắt mọi NIC tới host/Internet trong VMware.",
    "Network isolation state is unknown": "Chưa xác định được trạng thái mạng; kiểm tra cấu hình LAB.",
    "Shared filesystem mounts present": "Tắt shared folders và unmount thư mục chia sẻ.",
    "SSH agent socket present": "Agent cục bộ hợp lệ sẽ được dừng sau khi bạn nhấn Enter và mạng đã ngắt.",
    "Credential presence blocks analysis": "Nếu còn key/token/kho đăng nhập ngoài agent, cần LAB không chứa chúng.",
}


def inspect_launch(root, prepared_run):
    """Read metadata and admission state only; never claim a job or touch PDFs."""
    root = Path(root).absolute()
    lock, limits = jobs.load_job(root, prepared_run)
    issues = []
    if sys.version_info[:2] != (3, 11):
        issues.append("Local LAB requires Python 3.11")
    try:
        clean_code(root)
    except ValueError:
        issues.append("Code must be clean and committed")
    campaign = root / "data/processed/pdf_extraction"
    if any(p.is_symlink() for p in (campaign, *campaign.parents)):
        issues.append("Output boundary contains a symlink")
    else:
        claim = campaign / (prepared_run + ".claim.json")
        if claim.exists() or claim.is_symlink():
            issues.append("Job already claimed; preserve evidence and do not retry")
    try:
        jobs._worker_count(1, limits)
    except ValueError:
        issues.append("Worker CPU/RAM admission failed")
    state = jobs.extraction_lab_state(repository_root=root)
    if state["uid"] == 0:
        issues.append("Use a non-root analysis account")
    for key, reason in (
        ("ssh_session", "Use VMware console; SSH session present"),
        ("connected_interfaces", "Disconnect all host/Internet network adapters"),
        ("unknown_interfaces", "Network isolation state is unknown"),
        ("shared_mounts", "Shared filesystem mounts present"),
        ("agent_forwarding_present", "SSH agent socket present"),
        ("known_credentials_present", "Credential presence blocks analysis"),
    ):
        if state[key]:
            issues.append(reason)
    counts = Counter(row["split"] for row in lock["rows"])
    return {"status": "blocked" if issues else "ready_for_operator_attestation",
            "prepared_run": prepared_run, "metadata_verified": True,
            "partitions": dict(sorted(counts.items())), "rows": len(lock["rows"]),
            "profile": lock["configuration"]["profile"], "blocking_reasons": issues,
            "operator_attested": False, "pdf_bytes_read": False, "execution": "not_run"}


def main(argv=None, *, root=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-run", required=True, help="Explicit sealed job; never selects the latest job")
    parser.add_argument("--check-only", action="store_true", help="Metadata and presence checks only; no prompt or PDF access")
    args = parser.parse_args(argv)
    root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    try:
        report = inspect_launch(root, args.prepared_run)
        if args.check_only:
            print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
            return 2 if report["blocking_reasons"] else 0
        if any(reason not in LAB_ISSUES for reason in report["blocking_reasons"]):
            print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
            print("CHƯA CHẠY: cần xử lý code/job/tài nguyên trước khi cô lập LAB.")
            return 2
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print("CHƯA CHẠY: cần terminal tương tác tại VMware console.")
            return 2
        print("CHẠY EXTRACTOR TĨNH — TRAIN/VALIDATION; TEST NGOÀI PHẠM VI.")
        print(f"Job: {args.prepared_run}; {report['rows']} PDF; {report['profile']}.")
        print("Cửa sổ sẽ chờ để bạn tự tắt mạng trong VMware.")
        print("Xác nhận tại VMware: mọi NIC tới host/Internet đã ngắt; shared folders,")
        print("clipboard và drag/drop đã tắt; LAB không chứa key/token/kho đăng nhập hoặc SSH.")
        print("Đã có snapshot trước phân tích. Không render, chạy JS, Reader hoặc CAPE.")
        print("Enter xác nhận các điều kiện trên, cho phép dừng agent cục bộ đã xác minh và chạy tĩnh một lần.")
        while True:
            for reason in report["blocking_reasons"]:
                print("Đang chờ: " + LAB_ISSUES[reason])
            if input("Chuẩn bị xong: nhấn Enter để kiểm tra và chạy; nhập q để đóng: ") != "":
                print("Đã đóng; chưa chạy PDF.")
                return 0


            report = inspect_launch(root, args.prepared_run)
            if any(reason not in LAB_ISSUES for reason in report["blocking_reasons"]):
                print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
                print("CHƯA CHẠY: code/job/tài nguyên thay đổi; giữ nguyên evidence/claim.")
                return 2
            agent_only = {"SSH agent socket present", "Credential presence blocks analysis"}
            if ("SSH agent socket present" in report["blocking_reasons"]
                    and set(report["blocking_reasons"]) <= agent_only):
                from malpdf.extraction.local_agent import probe_local_agent, clear_stale_agent
                agent = probe_local_agent()
                if agent is not None:
                    try:
                        agent.stop()
                    finally:
                        agent.close()
                    print("Đã dừng agent cục bộ; kiểm tra lại điều kiện LAB.")
                    report = inspect_launch(root, args.prepared_run)
                    if any(reason not in LAB_ISSUES for reason in report["blocking_reasons"]):
                        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
                        return 2
                elif clear_stale_agent():
                    print("Agent đã thoát và socket không còn; đã bỏ hai biến agent cũ của launcher.")
                    report = inspect_launch(root, args.prepared_run)
                    if any(reason not in LAB_ISSUES for reason in report["blocking_reasons"]):
                        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
                        return 2
                else:
                    print("Agent chưa xác minh được và chưa chứng minh được PID/socket đều đã mất; giữ chặn.")
            if not report["blocking_reasons"]:
                break
            print("CHƯA CHẠY: bạn có thể xử lý rồi nhấn Enter ngay trong cửa sổ này.")


        result = jobs.run_job(root, args.prepared_run, lab_attested=True)
        summary = {k: result[k] for k in ("run_id", "status", "rows", "planned", "report_path", "output_path") if k in result}
        print(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
        print("Giữ nguyên evidence/claim. Launcher không tự chạy lại.")
        return 0 if result.get("status") == "completed" else 1
    except (KeyboardInterrupt, EOFError):
        print("Đã dừng. Giữ nguyên evidence/claim nếu job đã bắt đầu; không tự chạy lại.")
        return 130
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:


        print(f"CHƯA HOÀN TẤT ({type(error).__name__}): kiểm tra job/source/model và điều kiện LAB.")
        print("Giữ nguyên evidence/claim nếu đã tạo; không tự chạy lại hoặc bỏ guard.")
        return 1
