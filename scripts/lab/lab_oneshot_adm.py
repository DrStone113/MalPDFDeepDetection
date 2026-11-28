"""Provision the offline one-shot and export bounded LAB observations."""

import argparse
from collections import Counter
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import gzip
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

PINNED_LIB = Path("/usr/local/libexec/malpdf")
TICKET_PATH = Path("/etc/malpdf/oneshot_ticket.json")
MANIFEST_PATH = Path("/etc/malpdf/auto_manifest.json")
RECEIPTS_DIR = Path("/etc/malpdf/oneshot_receipts")
UNIT_PATH = Path("/etc/systemd/system/malpdf-offline-oneshot.service")
WANTS_LINK = Path("/etc/systemd/system/multi-user.target.wants/malpdf-offline-oneshot.service")
ADMIN_PATH = Path("/usr/local/libexec/malpdf-auto/lab_oneshot_adm.py")
RUNNER_PATH = ADMIN_PATH.with_name("lab_offline_oneshot.py")
PINNED_NAMES = (
    "lab_contract.py",
    "lab_readonly.py",
    "lab_side.py",
    "lab_jobs.py",
    "lab_runner.py",
    "check_local.py",
    "lab_guard.py",
)
AUTO_NAMES = ("lab_oneshot_adm.py", "lab_offline_oneshot.py")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ERROR_TOKEN = re.compile(r"[a-z][a-z0-9_]{1,63}(?::[A-Za-z0-9._-]{1,64})?")


def _safe_error_reason(error):
    if type(error) is ValueError and len(error.args) == 1 and isinstance(error.args[0], str):
        token = error.args[0]
        if _SAFE_ERROR_TOKEN.fullmatch(token):
            return token
    if isinstance(error, subprocess.TimeoutExpired):
        return "command_timeout"
    if isinstance(error, subprocess.SubprocessError):
        return "command_failed"
    if isinstance(error, OSError):
        return "io_failed"
    return "internal_error"


def _stdlib_trusted_root_file(path, mode=None):
    cur = Path(path).absolute()
    if cur.resolve() != cur or any(part.is_symlink() for part in (cur, *cur.parents)):
        raise ValueError("pinned_helper_unsafe")
    info = cur.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o022
        or info.st_size > 2 * 1024**2
        or mode is not None
        and stat.S_IMODE(info.st_mode) != mode
    ):
        raise ValueError("pinned_helper_unsafe")
    return cur


def verify_auto_manifest(manifest_path=None, pinned_dir=None, auto_dir=None):
    manifest_file = _stdlib_trusted_root_file(manifest_path or MANIFEST_PATH, 0o600)
    data = json.loads(manifest_file.read_bytes().decode("utf-8", "strict"))
    if not isinstance(data, dict) or set(data) != {"schema_version", "pinned", "auto"} or data["schema_version"] != 1:
        raise ValueError("auto_manifest_invalid")
    pinned_base = Path(pinned_dir or PINNED_LIB)
    auto_base = Path(auto_dir or ADMIN_PATH.parent)
    for section, names, base in (
        ("pinned", PINNED_NAMES, pinned_base),
        ("auto", AUTO_NAMES, auto_base),
    ):
        mapping = data.get(section)
        if not isinstance(mapping, dict) or set(mapping) != set(names):
            raise ValueError("auto_manifest_invalid")
        for name in names:
            expected = mapping[name]
            if not isinstance(expected, str) or not _HEX64.fullmatch(expected):
                raise ValueError("auto_manifest_invalid")
            target = _stdlib_trusted_root_file(base / name)
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise ValueError(f"pinned_helper_mismatch:{name}")
    return data


if (
    sys.platform == "linux"
    and Path(sys.argv[0]).name == "lab_oneshot_adm.py"
    and len(sys.argv) >= 2
    and sys.argv[1] in ("arm", "boot-exec", "receive", "report", "export")
):
    try:
        verify_auto_manifest()
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(json.dumps({"status": "blocked", "reason": _safe_error_reason(error)}, separators=(",", ":")))
        raise SystemExit(2) from None

if sys.platform == "linux":
    for directory in (ADMIN_PATH.parent, PINNED_LIB):
        if directory.is_dir() and str(directory) not in sys.path:
            sys.path.insert(0, str(directory))

from lab_contract import MAX_REPORT, parse_json, text_failure
import lab_jobs as jobs
from lab_offline_oneshot import bounded_command, exclusive_job, forbid_ssh, runner_env
import lab_side as side

PYTHON = "/usr/bin/python3"
SYSTEMCTL = "/usr/bin/systemctl"
MIB = 1024**2
RECEIPT_LIMIT = 65536
BULK = "pdf-static-bulk"
CVE = "pdf-static-cve"
BULK_OUTPUT = "data/processed/bulk_extract"
TERMINAL_STATUSES = {"passed", "partial", "failed", "blocked", "interrupted"}
FAILURE_EXPORT_MODE = "terminal_failure_receipt_only"
FAILURE_UNAVAILABLE_REASON = "profile_output_unavailable"
FAILURE_ONLY_STATUSES = {"failed", "blocked", "interrupted"}
FIREWALL_UNIT_PATH = Path("/etc/systemd/system/malpdf-firewall.service")
FIREWALL_WANTS_LINK = Path("/etc/systemd/system/network-pre.target.wants/malpdf-firewall.service")
NUMERIC_KINDS = {"pdf-static", "pdf-static-cic-full", "pdf-diagnostic-replay"}
PUBLISHER_EXPORTERS = {
    "pdf-benign-ood": "export_benign_ood",
    "pdf-benign-ood-expanded": "export_expanded_benign_ood",
    "pdf-benign-ood-diverse": "export_diverse_benign_ood",
    "pdf-benign-v32-cohort": "export_v32_benign_cohort",
}
EXPORT_CONTRACTS = {
    **dict.fromkeys(jobs.URI_REVIEW_KINDS, 8 * MIB),
    jobs.URI_HEAD_EVAL_KIND: 8 * MIB,
    **dict.fromkeys(PUBLISHER_EXPORTERS.keys() | NUMERIC_KINDS, 64 * MIB),
    **dict.fromkeys(jobs.FINGERPRINT_KINDS | {CVE}, 16 * MIB),
    BULK: 4 * MIB,
}
URI_HEAD_EVAL_COHORT = {
    "samples": 624,
    "cohort_counts": {
        "benign_ood_v1": 83,
        "benign_ood_expanded_v1": 379,
        "uri_safedocs_review": 11,
        "uri_review_v1": 151,
    },
    "uri_contract_sha256": "84bf5da1108ef0061adf28e3cd6acdb18b263c7e99892bb0612ddec84ea5e714",
    "uri_npz_sha256": "497e63c62de27ea1e7df1e6c9ec3e3b72139220cd8631b3e00653e630edc8e97",
    "model_evaluation_in_lab": True,
    "purpose": "air-gapped static PDF URI extraction and PDFURILexicalHead v4 bounded scoring",
}
URI_HEAD_EVAL_STATUSES = {"observed", "password_locked", "ingest_error", "missing", "invalid"}
URI_HEAD_EVAL_TIERS = {"benign", "gated_fusion", "or_gate"}
URI_HEAD_EVAL_VECTORS = {
    "annot_uri",
    "action_uri",
    "action_submitform",
    "action_gotor",
    "action_launch",
    "action_importdata",
    "submit_form",
    "gotor",
    "launch",
    "import_data",
    "javascript_url",
    "flate_text_stream",
    "qr_image",
    "pdf_action",
}
URI_HEAD_EVAL_SUMMARY_KEYS = {
    "count",
    "observed",
    "password_locked",
    "ingest_error",
    "missing_or_invalid",
    "or_gate_count",
    "gated_fusion_count",
    "or_gate_rate",
    "heuristic_phishing_count",
    "max_prob_p50",
    "max_prob_p95",
    "max_prob_p99",
    "max_prob_max",
    "total_scored_urls",
    "total_allowlisted_urls",
    "total_filtered_xml_xmp",
    "vector_counts",
}
URI_HEAD_EVAL_RECORD_KEYS = {
    "index",
    "sha256",
    "cohort",
    "eval_status",
    "max_prob",
    "tier",
    "scored_url_count",
    "allowlisted_url_count",
    "filtered_xml_xmp_count",
    "vector_counts",
    "top_url_vector",
    "heuristic_phishing",
    "password_locked",
}
CYCLE_ID = re.compile(r"[a-f0-9]{32}")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
BOOT_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
TLSH = re.compile(r"(?:T1)?[0-9A-F]{70}")
TICKET_FIELDS = {
    "schema_version",
    "cycle_id",
    "job_id",
    "kind",
    "commit",
    "manifest_sha256",
    "poweroff_on_finish",
    "armed_utc",
}
CVE_FIELDS = {"sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source"}
CVE_NAMES = ("bank_statment.pdf", "link_URI.pdf", "rce_foxit.pdf", "url2_invoice_template.pdf", "xss_popup.pdf")


def _uri_eval_quantile(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return round(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac, 6)


def _recompute_uri_eval_cohort_summary(records):
    by_cohort = {}
    for rec in records:
        by_cohort.setdefault(str(rec["cohort"]), []).append(rec)
    out = {}
    for cohort, items in sorted(by_cohort.items()):
        probs = sorted(float(item["max_prob"]) for item in items if item["eval_status"] == "observed")
        or_cnt = sum(1 for item in items if item["tier"] == "or_gate")
        gf_cnt = sum(1 for item in items if item["tier"] == "gated_fusion")
        heur_cnt = sum(1 for item in items if item["heuristic_phishing"])
        vec_totals = {}
        for item in items:
            for vec, cnt in item["vector_counts"].items():
                vec_totals[str(vec)] = vec_totals.get(str(vec), 0) + int(cnt)
        out[cohort] = {
            "count": len(items),
            "observed": sum(1 for item in items if item["eval_status"] == "observed"),
            "password_locked": sum(1 for item in items if item["eval_status"] == "password_locked"),
            "ingest_error": sum(1 for item in items if item["eval_status"] == "ingest_error"),
            "missing_or_invalid": sum(1 for item in items if item["eval_status"] in {"missing", "invalid"}),
            "or_gate_count": or_cnt,
            "gated_fusion_count": gf_cnt,
            "or_gate_rate": round(or_cnt / max(len(items), 1), 6),
            "heuristic_phishing_count": heur_cnt,
            "max_prob_p50": _uri_eval_quantile(probs, 0.50),
            "max_prob_p95": _uri_eval_quantile(probs, 0.95),
            "max_prob_p99": _uri_eval_quantile(probs, 0.99),
            "max_prob_max": round(probs[-1], 6) if probs else 0.0,
            "total_scored_urls": sum(int(item["scored_url_count"]) for item in items),
            "total_allowlisted_urls": sum(int(item["allowlisted_url_count"]) for item in items),
            "total_filtered_xml_xmp": sum(int(item["filtered_xml_xmp_count"]) for item in items),
            "vector_counts": vec_totals,
        }
    return out


def _exact_json_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_exact_json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_exact_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def json_bytes(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode() + b"\n"
    )


def read_json(path, limit):
    return parse_json(side.bounded_read(jobs.trusted_path(path), limit))


def require_root():
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("linux_root_required")


def root_file(path, mode=None):
    info = jobs.trusted_path(path).stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o022
        or mode is not None
        and stat.S_IMODE(info.st_mode) != mode
    ):
        raise ValueError("unsafe_root_file")
    return path


def fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path, payload, mode):
    jobs.trusted_path(path)
    descriptor, filename = tempfile.mkstemp(prefix=".oneshot-", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, 0)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def admin_lock():
    import fcntl

    path = jobs.trusted_path(TICKET_PATH.with_name(".oneshot.lock"))
    with path.open("ab") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def runner_account():
    import pwd

    cfg = read_json(root_file(jobs.CONFIG), 8192)
    if (
        set(cfg) != {"schema_version", "uid", "data_root", "python"}
        or cfg["schema_version"] != 1
        or type(cfg["uid"]) is not int
        or cfg["uid"] < 1000
        or any(not isinstance(cfg[key], str) or not Path(cfg[key]).is_absolute() for key in ("data_root", "python"))
    ):
        raise ValueError("setup_required")
    account = pwd.getpwuid(cfg["uid"])
    if (
        type(account.pw_uid) is not int
        or account.pw_uid != cfg["uid"]
        or account.pw_uid < 1000
        or type(account.pw_gid) is not int
        or account.pw_gid < 1000
        or not Path(account.pw_dir).is_absolute()
    ):
        raise ValueError("unsafe_runner_account")
    return cfg, account


def as_runner(command, account, *, timeout, limit=RECEIPT_LIMIT, check=True, payload=None):
    if (
        type(account.pw_uid) is not int
        or account.pw_uid < 1000
        or type(account.pw_gid) is not int
        or account.pw_gid < 1000
    ):
        raise ValueError("unsafe_runner_account")
    return bounded_command(
        command,
        limit,
        timeout=timeout,
        payload=payload,
        check=check,
        env=runner_env(account),
        cwd=account.pw_dir,
        user=account.pw_uid,
        group=account.pw_gid,
        extra_groups=[],
        umask=0o077,
        start_new_session=True,
    )


def ticket_value():
    value = read_json(root_file(TICKET_PATH, 0o600), RECEIPT_LIMIT)
    if (
        not isinstance(value, dict)
        or set(value) != TICKET_FIELDS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not CYCLE_ID.fullmatch(value["cycle_id"])
        or not jobs.HEX.fullmatch(value["job_id"])
        or value["kind"] not in jobs.PDF_KINDS
        or not jobs.REV_RE.fullmatch(value["commit"])
        or not jobs.HEX.fullmatch(value["manifest_sha256"])
        or value["poweroff_on_finish"] is not True
        or not isinstance(value["armed_utc"], str)
    ):
        raise ValueError("ticket_invalid")
    return value


def read_receipt(job_id):
    if not jobs.HEX.fullmatch(job_id):
        raise ValueError("job_mismatch")
    raw = side.bounded_read(root_file(RECEIPTS_DIR / f"{job_id}.json", 0o600), RECEIPT_LIMIT)
    value = parse_json(raw)
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("job_id") != job_id:
        raise ValueError("oneshot_receipt_invalid")
    return raw


def unit_contents():
    # The target's implicit After= would order the service against its explicit After=.
    return f"""[Unit]
Description=Run the authorized MalPDF static LAB job once
DefaultDependencies=no
After=multi-user.target systemd-user-sessions.service
Before=shutdown.target
Conflicts=shutdown.target
ConditionPathExists={TICKET_PATH.as_posix()}

[Service]
Type=oneshot
TimeoutStartSec=infinity
ExecStart={PYTHON} -I -B {ADMIN_PATH.as_posix()} boot-exec

[Install]
WantedBy=multi-user.target
""".encode("ascii")


def current_boot_id():
    if sys.platform != "linux":
        return "00000000-0000-0000-0000-000000000000"
    with BOOT_ID_PATH.open("r", encoding="ascii") as stream:
        value = stream.read(64).strip().lower()
    if not BOOT_ID.fullmatch(value):
        raise ValueError("boot_id_unavailable")
    return value


def _attempts_receipt_path(job_id):
    if not jobs.HEX.fullmatch(job_id):
        raise ValueError("job_mismatch")
    return RECEIPTS_DIR / f"{job_id}.attempts.json"


def _read_verified_attempts(job, cycle_id):
    path = _attempts_receipt_path(job["job_id"])
    if not os.path.lexists(path):
        return {}
    doc = parse_json(side.bounded_read(root_file(path, 0o600), RECEIPT_LIMIT))
    if (
        not isinstance(doc, dict)
        or set(doc) != {"schema_version", "cycle_id", "job_id", "commit", "verified_attempts"}
        or type(doc["schema_version"]) is not int
        or doc["schema_version"] != 1
        or doc["cycle_id"] != cycle_id
        or doc["job_id"] != job["job_id"]
        or doc["commit"] != job["commit"]
        or not isinstance(doc["verified_attempts"], dict)
        or len(doc["verified_attempts"]) > 512
    ):
        raise ValueError("bulk_attempt_receipt_invalid")
    verified = {}
    for attempt_id, entry in doc["verified_attempts"].items():
        if (
            not isinstance(attempt_id, str)
            or not CYCLE_ID.fullmatch(attempt_id)
            or not isinstance(entry, dict)
            or set(entry) != {"boot_id", "cleanup_sha256"}
            or not isinstance(entry["boot_id"], str)
            or not BOOT_ID.fullmatch(entry["boot_id"])
            or not isinstance(entry["cleanup_sha256"], str)
            or not _HEX64.fullmatch(entry["cleanup_sha256"])
        ):
            raise ValueError("bulk_attempt_receipt_invalid")
        verified[attempt_id] = dict(entry)
    return verified


def _prior_boot_verified_digests(job, cycle_id, verified_records=None):
    records = _read_verified_attempts(job, cycle_id) if verified_records is None else verified_records
    boot = current_boot_id()
    return {name: entry["cleanup_sha256"] for name, entry in records.items() if entry["boot_id"] != boot}


def _write_verified_attempts(job, cycle_id, existing, digests):
    boot = current_boot_id()
    merged = {name: dict(entry) for name, entry in existing.items()}
    for name, digest in digests.items():
        if name not in merged or merged[name]["cleanup_sha256"] != digest:
            merged[name] = {"boot_id": boot, "cleanup_sha256": digest}
    directory = _ensure_receipt_dir(RECEIPTS_DIR)
    payload = {
        "schema_version": 1,
        "cycle_id": cycle_id,
        "job_id": job["job_id"],
        "commit": job["commit"],
        "verified_attempts": merged,
    }
    atomic_write(directory / f"{job['job_id']}.attempts.json", json_bytes(payload), 0o600)


def arm(job_id, kind, cycle_id):
    require_root()
    if not CYCLE_ID.fullmatch(cycle_id):
        raise ValueError("cycle_mismatch")
    with admin_lock():
        verify_auto_manifest()
        job = exclusive_job(job_id, kind)
        _, account = runner_account()
        for helper in (ADMIN_PATH, RUNNER_PATH):
            root_file(helper, 0o755)
        as_runner([PYTHON, "-I", "-B", ADMIN_PATH.as_posix(), "_credentials"], account, timeout=15)
        directory = jobs.job_directory(job_id)
        if (directory / "claim.json").exists():
            receipt = parse_json(read_receipt(job_id))
            if kind != BULK:
                raise ValueError("resume_receipt_required")
            prior_boot_verified = _prior_boot_verified_digests(job, cycle_id)
            if (
                receipt["cycle_id"] != cycle_id
                or receipt["job_id"] != job_id
                or receipt["kind"] != kind
                or receipt["commit"] != job["commit"]
                or receipt["outcome"] != "bulk_paused_resumable"
                or classify_job_outcome(
                    job,
                    directory,
                    worker_count(account.pw_uid),
                    prior_boot_verified=prior_boot_verified,
                )[0]
                != "bulk_paused_resumable"
            ):
                raise ValueError("resume_receipt_required")
        ticket = {
            "schema_version": 1,
            "cycle_id": cycle_id,
            "job_id": job_id,
            "kind": kind,
            "commit": job["commit"],
            "manifest_sha256": job["manifest_sha256"],
            "poweroff_on_finish": True,
        }
        if TICKET_PATH.exists():
            previous = ticket_value()
            if any(previous[key] != value for key, value in ticket.items()):
                raise ValueError("ticket_already_armed")
        else:
            if UNIT_PATH.exists() or os.path.lexists(WANTS_LINK):
                raise ValueError("orphaned_oneshot_unit")
            atomic_write(TICKET_PATH, json_bytes({**ticket, "armed_utc": utc_now()}), 0o600)
        atomic_write(UNIT_PATH, unit_contents(), 0o644)
        jobs.trusted_path(WANTS_LINK.parent).mkdir(mode=0o755, exist_ok=True)
        if os.path.lexists(WANTS_LINK):
            if not WANTS_LINK.is_symlink() or WANTS_LINK.readlink() != UNIT_PATH:
                raise ValueError("unexpected_unit_link")
        else:
            WANTS_LINK.symlink_to(UNIT_PATH)
            fsync_dir(WANTS_LINK.parent)
        bounded_command([SYSTEMCTL, "daemon-reload"], 4096, timeout=30)
        return ticket_value()


def remove_arm():
    # Removing the ticket first makes interruption during disarm safe across reboot.
    for path in (TICKET_PATH, WANTS_LINK, UNIT_PATH):
        jobs.trusted_path(path.parent)
        path.unlink(missing_ok=True)
        if path.parent.is_dir():
            fsync_dir(path.parent)


def disarm():
    require_root()
    with admin_lock():
        had_unit_dir = UNIT_PATH.parent.is_dir()
        remove_arm()
        if had_unit_dir:
            bounded_command([SYSTEMCTL, "daemon-reload"], 4096, timeout=30)
    return {"disarmed": True}


def worker_count(uid, proc=Path("/proc")):
    count = 0
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            info = side.bounded_read(entry / "status", RECEIPT_LIMIT)
            owners = re.search(rb"(?m)^Uid:\s+([0-9]+)\s+([0-9]+)\s+[0-9]+\s+[0-9]+\s*$", info)
            if owners is None:
                raise ValueError("worker_identity_unverified")
            if uid not in (int(owners[1]), int(owners[2])):
                continue
            args = side.bounded_read(entry / "cmdline", RECEIPT_LIMIT).split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        is_runner = any(
            arg.rsplit(b"/", 1)[-1] == b"lab_runner.py" and action in (b"pdf-worker", b"pdf-bulk")
            for arg, action in zip(args, args[1:])
        )
        is_bootstrap = any(arg.rsplit(b"/", 1)[-1] == b"profile_bootstrap.py" for arg in args)
        count += int(is_runner or is_bootstrap)
    return count


def _bulk_process_alive(pid, ticks):
    if sys.platform == "linux":
        if jobs.process_identity(pid) == ticks:
            return True
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return False
        return True
    return False


def _validate_process_record(raw):
    record = parse_json(raw)
    if not isinstance(record, dict) or set(record) != {"pid", "pgid", "start_ticks"}:
        raise ValueError("bulk_process_record_invalid")
    pid, ticks = record["pid"], record["start_ticks"]
    if type(pid) is not int or pid <= 1 or type(ticks) is not int or record["pgid"] != pid:
        raise ValueError("bulk_process_record_invalid")
    return pid, ticks


def _bulk_cleanup_digests(job_dir, *, prior_boot_verified=None):
    digests = {}
    try:
        for attempt in attempts_in(job_dir):
            result_path = jobs.trusted_path(attempt / "result.json")
            writer_path = jobs.trusted_path(attempt / "writer.json")
            workers_dir = jobs.trusted_path(attempt / "workers")
            if not result_path.is_file() or not writer_path.is_file() or not workers_dir.is_dir():
                return None
            result_raw = side.bounded_read(result_path, 4096)
            attempt_result = parse_json(result_raw)
            if (
                not isinstance(attempt_result, dict)
                or set(attempt_result) != {"status", "cleanup_verified"}
                or attempt_result["cleanup_verified"] is not True
                or attempt_result["status"] not in ("interrupted", "complete", "failed")
            ):
                return None
            writer_raw = side.bounded_read(writer_path, 1024)
            process_records = [_validate_process_record(writer_raw)]
            worker_raws = []
            for entry in sorted(workers_dir.iterdir()):
                trusted_entry = jobs.trusted_path(entry)
                if trusted_entry.suffix != ".json" or not trusted_entry.is_file():
                    return None
                raw_worker = side.bounded_read(trusted_entry, 1024)
                process_records.append(_validate_process_record(raw_worker))
                worker_raws.append((trusted_entry.name.encode("utf-8"), raw_worker))
            hasher = hashlib.sha256()
            for part in (attempt.name.encode("ascii"), result_raw, writer_raw):
                hasher.update(f"{len(part)}:".encode("ascii") + part)
            for name_bytes, raw_worker in worker_raws:
                for part in (name_bytes, raw_worker):
                    hasher.update(f"{len(part)}:".encode("ascii") + part)
            digest = hasher.hexdigest()
            # Skip killpg(0) only for attempts already proved clean on a prior boot whose cleanup files are unchanged.
            if not (prior_boot_verified is not None and prior_boot_verified.get(attempt.name) == digest):
                for pid, ticks in process_records:
                    if _bulk_process_alive(pid, ticks):
                        return None
            digests[attempt.name] = digest
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return digests


def _bulk_cleanup_verified(job_dir, *, prior_boot_verified=None):
    return _bulk_cleanup_digests(job_dir, prior_boot_verified=prior_boot_verified) is not None


def attempts_in(directory):
    root = jobs.trusted_path(directory / "bulk_attempts")
    if not root.exists():
        return []
    attempts = []
    for entry in root.iterdir():
        if len(attempts) >= 512 or not CYCLE_ID.fullmatch(entry.name) or not jobs.trusted_path(entry).is_dir():
            raise ValueError("bulk_attempt_invalid")
        attempts.append(entry)
    # Directory mtime changes as the pinned runner publishes an attempt's result.
    return sorted(attempts, key=lambda entry: (entry.stat().st_mtime_ns, entry.name))


def classify_job_outcome(job, job_dir, workers_remaining, *, previous_attempts=(), prior_boot_verified=None):
    try:
        if workers_remaining != 0:
            return "unexpected_incomplete", None
        if (job_dir / "result.json").is_file():
            result = jobs.validate_result(read_json(job_dir / "result.json", MAX_REPORT), job)
            if job["kind"] == BULK:
                if not _bulk_cleanup_verified(job_dir, prior_boot_verified=prior_boot_verified) or (
                    result["status"] != "blocked" and not attempts_in(job_dir)
                ):
                    return "unexpected_incomplete", None
            else:
                if any(item["reason"] == "worker_cleanup_incomplete" for item in jobs.pdf_halt_records(job, job_dir)):
                    return "unexpected_incomplete", None
                cleanup_raw_path = job_dir / "private_outer/cleanup.json"
                if job["kind"] == "pdf-diagnostic-replay" and (
                    result["status"] != "blocked" or cleanup_raw_path.exists()
                ):
                    cleanup_path = jobs.trusted_path(cleanup_raw_path)
                    if not cleanup_path.is_file():
                        return "unexpected_incomplete", None
                    cleanup = read_json(cleanup_path, 16384)
                    if (
                        not isinstance(cleanup, dict)
                        or set(cleanup) != {"run_id", "exit_codes"}
                        or cleanup["run_id"] != job["job_id"]
                        or not isinstance(cleanup["exit_codes"], list)
                        or len(cleanup["exit_codes"]) != job["limits"]["workers"]
                        or any(type(code) is not int for code in cleanup["exit_codes"])
                    ):
                        return "unexpected_incomplete", None
            if result["status"] in TERMINAL_STATUSES:
                return "terminal_result", result
        elif job["kind"] == BULK and (job_dir / "claim.json").is_file():
            if not _bulk_cleanup_verified(job_dir, prior_boot_verified=prior_boot_verified):
                return "unexpected_incomplete", None
            result = jobs.read_result(job["job_id"])
            attempts = attempts_in(job_dir)
            if (
                result["status"] == "interrupted"
                and result["reason"] == "already_claimed"
                and attempts
                and attempts[-1].name not in previous_attempts
            ):
                latest = read_json(attempts[-1] / "result.json", 4096)
                if latest["status"] == "interrupted" and latest["cleanup_verified"] is True:
                    return "bulk_paused_resumable", result
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return "unexpected_incomplete", None


def _ensure_receipt_dir(path):
    directory = jobs.trusted_path(path)
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("unsafe_receipt_directory")
    return directory


def boot_exec():
    forbid_ssh()
    require_root()
    with admin_lock():
        verify_auto_manifest()
        ticket = ticket_value()
        job_id, kind = ticket["job_id"], ticket["kind"]
        job = exclusive_job(job_id, kind)
        if any(job[key] != ticket[key] for key in ("commit", "manifest_sha256")):
            raise ValueError("ticket_job_mismatch")
        remove_arm()
        state = jobs.guard_module().lab_state()
        if (
            state["connected_interfaces"] != []
            or state["unknown_interfaces"] != []
            or state["shared_mounts"] != []
            or state["ssh_session"] is not False
        ):
            raise ValueError("offline_isolation_failed")
        exclusive_job(job_id, kind)
        _, account = runner_account()
        directory = jobs.job_directory(job_id)
        previous_attempts = {item.name for item in attempts_in(directory)} if kind == BULK else ()
        verified_attempts = _read_verified_attempts(job, ticket["cycle_id"]) if kind == BULK else {}
        prior_boot_verified = (
            _prior_boot_verified_digests(job, ticket["cycle_id"], verified_attempts) if kind == BULK else None
        )
        pty = {}
        try:
            code, raw = as_runner(
                [PYTHON, "-I", "-B", RUNNER_PATH.as_posix(), "--job-id", job_id, "--kind", kind],
                account,
                timeout=job["limits"]["wall_seconds"] + 150,
                check=False,
            )
            pty = parse_json(raw)
            if not isinstance(pty, dict) or code not in (0, 2):
                pty = {}
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        workers = worker_count(account.pw_uid)
        confirmed = pty.get("confirmed") is True and pty.get("job_id") == job_id and pty.get("kind") == kind
        exit_code = pty.get("exit_code")
        outcome, result = (
            classify_job_outcome(
                job,
                directory,
                workers,
                previous_attempts=previous_attempts,
                prior_boot_verified=prior_boot_verified,
            )
            if confirmed and exit_code == 0 and "reason" not in pty
            else ("unexpected_incomplete", None)
        )
        if kind == BULK and outcome in ("terminal_result", "bulk_paused_resumable"):
            digests = _bulk_cleanup_digests(directory, prior_boot_verified=prior_boot_verified)
            if digests is None:
                outcome, result = ("unexpected_incomplete", None)
            elif digests:
                _write_verified_attempts(job, ticket["cycle_id"], verified_attempts, digests)
        receipt = {
            "schema_version": 1,
            "cycle_id": ticket["cycle_id"],
            "job_id": job_id,
            "kind": kind,
            "commit": job["commit"],
            "outcome": outcome,
            "runner_status": result["status"] if result else None,
            "reason": result["reason"] if result else "unexpected_incomplete",
            "pty_confirmed": confirmed,
            "pty_exit_code": exit_code if type(exit_code) is int else None,
            "workers_remaining": workers,
            "completed_utc": utc_now(),
        }
        directory = _ensure_receipt_dir(RECEIPTS_DIR)
        atomic_write(directory / f"{job_id}.json", json_bytes(receipt), 0o600)
        os.sync()
        if workers == 0:
            bounded_command([SYSTEMCTL, "poweroff"], 4096, timeout=30)
        return receipt


def _is_resumable_bulk_pause(kind, runner):
    return kind == BULK and runner.get("status") == "interrupted" and runner.get("reason") == "already_claimed"


def verify_firewall_pre_network(unit_path=None, wants_link=None):
    unit = _stdlib_trusted_root_file(unit_path or FIREWALL_UNIT_PATH, 0o644)
    text = unit.read_bytes().decode("utf-8", "strict")
    fields = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        if "=" not in stripped:
            raise ValueError("firewall_unit_invalid")
        key, val = stripped.split("=", 1)
        fields[key.strip()] = val.strip()
    before_tokens = set(fields.get("Before", "").split())
    wants_tokens = set(fields.get("Wants", "").split())
    if (
        fields.get("DefaultDependencies") != "no"
        or "network-pre.target" not in before_tokens
        or "systemd-networkd.service" not in before_tokens
        or "network-pre.target" not in wants_tokens
        or fields.get("TimeoutStartSec") != "30"
        or fields.get("ExecStart") != "/usr/local/sbin/malpdf-firewall phase2"
    ):
        raise ValueError("firewall_unit_invalid")
    wants = Path(wants_link or FIREWALL_WANTS_LINK)
    parent = wants.parent.absolute()
    if parent.resolve() != parent or any(part.is_symlink() for part in (parent, *parent.parents)):
        raise ValueError("firewall_unit_invalid")
    pinfo = parent.stat()
    if not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid != 0 or pinfo.st_gid != 0 or pinfo.st_mode & 0o022:
        raise ValueError("firewall_unit_invalid")
    if not wants.is_symlink() or wants.resolve(strict=True) != unit:
        raise ValueError("firewall_unit_invalid")
    return True


def status():
    if sys.platform != "linux":
        raise ValueError("linux_required")
    firewall = None
    host_only = offline_boot = firewall_pre_network = False
    if os.getuid() == 0:
        _, raw = bounded_command(["/usr/local/sbin/malpdf-firewall", "status"], 65536, timeout=15)
        firewall = parse_json(raw)
        try:
            jobs.host_only_network()
            host_only = True
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        try:
            firewall_pre_network = verify_firewall_pre_network()
        except (OSError, ValueError):
            firewall_pre_network = False
        interface = firewall.get("host_only_if", "")
        netplan = next((p for p in ("/usr/sbin/netplan", "/usr/bin/netplan") if Path(p).is_file()), None)
        if netplan and re.fullmatch(r"[A-Za-z0-9_-]+", interface):
            code, raw = bounded_command(
                [netplan, "get", f"ethernets.{interface}.optional"], 4096, timeout=15, check=False
            )
            offline_boot = code == 0 and raw.strip() == b"true"
    return {
        "schema_version": 1,
        "installed": ADMIN_PATH.is_file() and RUNNER_PATH.is_file(),
        "ticket_present": os.path.lexists(TICKET_PATH),
        "unit_present": os.path.lexists(UNIT_PATH),
        "wants_present": os.path.lexists(WANTS_LINK),
        "offline_boot_netplan": offline_boot,
        "pending_job_ids": [job["job_id"] for job in jobs.pending()],
        "firewall": firewall,
        "firewall_pre_network": firewall_pre_network,
        "host_only_network": host_only,
    }


def _hex(value):
    return isinstance(value, str) and jobs.HEX.fullmatch(value) is not None


SUMMARY_COUNTS = ("availability", "status_counts", "features_present", "features_nonnull")
SUMMARY_INDICES = ("missing_indices", "invalid_indices", "cleanup_incomplete_indices")
SUMMARY_INTS = (
    "graphs_with_observed_nodes",
    "observed_graph_nodes",
    "graphs_with_unknown_node_sizes",
    "source_bundle_bytes",
    "uncompressed_export_bytes",
)
SUMMARY_FALSE = ("model_input_ready", "raw_pdf_processing", "classifier_inference_executed")
SUMMARY_KEYS = {
    "schema_version",
    "job_id",
    "planned",
    "partition_coverage",
    "elapsed_seconds",
    *SUMMARY_COUNTS,
    *SUMMARY_INDICES,
    *SUMMARY_INTS,
    *SUMMARY_FALSE,
}


NUMERIC_UNAVAILABLE = frozenset({"decode_error", "unsupported", "encrypted", "timeout", "resource_limit", "not_run"})
NUMERIC_FEATURE_NAMES = frozenset(
    (
        "canonical_AA",
        "canonical_Acroform",
        "canonical_BaseEncoding",
        "canonical_BitsPerComponent",
        "canonical_Colors",
        "canonical_EmbeddedFile",
        "canonical_Encoding",
        "canonical_Encrypt",
        "canonical_JBIG2Decode",
        "canonical_JS",
        "canonical_JavaScript",
        "canonical_Launch",
        "canonical_ObjStm",
        "canonical_OpenAction",
        "canonical_ProcSet",
        "canonical_Registry",
        "canonical_Resources",
        "canonical_RichMedia",
        "canonical_Root",
        "canonical_URI",
        "canonical_XFA",
        "canonical_contains_text",
        "canonical_embedded files",
        "canonical_endobj",
        "canonical_endstream",
        "canonical_images",
        "canonical_isEncrypted",
        "canonical_metadata size",
        "canonical_obj",
        "canonical_page_command",
        "canonical_pages",
        "canonical_pdf_ver",
        "canonical_pdfsize",
        "canonical_server",
        "canonical_startxref",
        "canonical_stream",
        "canonical_title length",
        "canonical_trailer",
        "canonical_www",
        "canonical_xref",
        "canonical_xref length",
        "legacy_AA",
        "legacy_Acroform",
        "legacy_BaseEncoding",
        "legacy_BitsPerComponent",
        "legacy_Colors",
        "legacy_EmbeddedFile",
        "legacy_Encoding",
        "legacy_Encrypt",
        "legacy_JBIG2Decode",
        "legacy_JS",
        "legacy_JavaScript",
        "legacy_Launch",
        "legacy_ObjStm",
        "legacy_OpenAction",
        "legacy_ProcSet",
        "legacy_Registry",
        "legacy_Resources",
        "legacy_RichMedia",
        "legacy_Root",
        "legacy_URI",
        "legacy_XFA",
        "legacy_ast_complete",
        "legacy_ast_computed_members",
        "legacy_ast_loops",
        "legacy_ast_max_depth",
        "legacy_ast_node_count",
        "legacy_call_Collab.collectEmailInfo",
        "legacy_call_Function",
        "legacy_call_String.fromCharCode",
        "legacy_call_app.launchURL",
        "legacy_call_atob",
        "legacy_call_eval",
        "legacy_call_unescape",
        "legacy_call_util.printf",
        "legacy_code_complete",
        "legacy_code_parser_recovered",
        "legacy_contains_text",
        "legacy_embedded files",
        "legacy_endobj",
        "legacy_endstream",
        "legacy_images",
        "legacy_isEncrypted",
        "legacy_metadata size",
        "legacy_obj",
        "legacy_observed_ast_computed_members",
        "legacy_observed_ast_loops",
        "legacy_observed_ast_max_depth",
        "legacy_observed_ast_node_count",
        "legacy_observed_ast_type_ArrayExpression",
        "legacy_observed_ast_type_AssignmentExpression",
        "legacy_observed_ast_type_BinaryExpression",
        "legacy_observed_ast_type_BlockStatement",
        "legacy_observed_ast_type_CallExpression",
        "legacy_observed_ast_type_CatchClause",
        "legacy_observed_ast_type_ConditionalExpression",
        "legacy_observed_ast_type_DoWhileStatement",
        "legacy_observed_ast_type_ExpressionStatement",
        "legacy_observed_ast_type_ForInStatement",
        "legacy_observed_ast_type_ForStatement",
        "legacy_observed_ast_type_FunctionDeclaration",
        "legacy_observed_ast_type_FunctionExpression",
        "legacy_observed_ast_type_Identifier",
        "legacy_observed_ast_type_IfStatement",
        "legacy_observed_ast_type_Literal",
        "legacy_observed_ast_type_MemberExpression",
        "legacy_observed_ast_type_NewExpression",
        "legacy_observed_ast_type_ObjectExpression",
        "legacy_observed_ast_type_ReturnStatement",
        "legacy_observed_ast_type_SequenceExpression",
        "legacy_observed_ast_type_SwitchStatement",
        "legacy_observed_ast_type_ThrowStatement",
        "legacy_observed_ast_type_TryStatement",
        "legacy_observed_ast_type_UnaryExpression",
        "legacy_observed_ast_type_UpdateExpression",
        "legacy_observed_ast_type_VariableDeclaration",
        "legacy_observed_ast_type_VariableDeclarator",
        "legacy_observed_ast_type_WhileStatement",
        "legacy_observed_call_Collab.collectEmailInfo",
        "legacy_observed_call_Function",
        "legacy_observed_call_String.fromCharCode",
        "legacy_observed_call_app.launchURL",
        "legacy_observed_call_atob",
        "legacy_observed_call_eval",
        "legacy_observed_call_unescape",
        "legacy_observed_call_util.printf",
        "legacy_observed_scripts_found",
        "legacy_observed_scripts_parsed",
        "legacy_observed_structure_AA",
        "legacy_observed_structure_AcroForm",
        "legacy_observed_structure_EmbeddedFile",
        "legacy_observed_structure_EmbeddedFiles",
        "legacy_observed_structure_JBIG2Decode",
        "legacy_observed_structure_JS",
        "legacy_observed_structure_JavaScript",
        "legacy_observed_structure_Launch",
        "legacy_observed_structure_OpenAction",
        "legacy_observed_structure_RichMedia",
        "legacy_observed_structure_URI",
        "legacy_observed_structure_XFA",
        "legacy_page_command",
        "legacy_pages",
        "legacy_parser_encrypted",
        "legacy_parser_resource_limit_reached",
        "legacy_parser_structural_complete",
        "legacy_parser_success",
        "legacy_pdf_ver",
        "legacy_pdfsize",
        "legacy_reference_parser_repaired",
        "legacy_script_extraction_complete",
        "legacy_scripts_found",
        "legacy_server",
        "legacy_startxref",
        "legacy_stream",
        "legacy_structure_AA",
        "legacy_structure_AcroForm",
        "legacy_structure_EmbeddedFile",
        "legacy_structure_EmbeddedFiles",
        "legacy_structure_JBIG2Decode",
        "legacy_structure_JS",
        "legacy_structure_JavaScript",
        "legacy_structure_Launch",
        "legacy_structure_OpenAction",
        "legacy_structure_RichMedia",
        "legacy_structure_URI",
        "legacy_structure_XFA",
        "legacy_title length",
        "legacy_trailer",
        "legacy_traversal_complete",
        "legacy_v8_MuPDF_ast_computed_members",
        "legacy_v8_MuPDF_ast_loops",
        "legacy_v8_MuPDF_ast_max_depth",
        "legacy_v8_MuPDF_ast_node_count",
        "legacy_v8_MuPDF_call_Collab.collectEmailInfo",
        "legacy_v8_MuPDF_call_Function",
        "legacy_v8_MuPDF_call_String.fromCharCode",
        "legacy_v8_MuPDF_call_app.launchURL",
        "legacy_v8_MuPDF_call_atob",
        "legacy_v8_MuPDF_call_eval",
        "legacy_v8_MuPDF_call_unescape",
        "legacy_v8_MuPDF_call_util.printf",
        "legacy_v8_MuPDF_scripts_found",
        "legacy_v8_MuPDF_scripts_parsed",
        "legacy_v8_action_GoToE",
        "legacy_v8_action_GoToR",
        "legacy_v8_action_ImportData",
        "legacy_v8_action_JavaScript",
        "legacy_v8_action_Launch",
        "legacy_v8_action_SubmitForm",
        "legacy_v8_action_URI",
        "legacy_v8_embedded_elf",
        "legacy_v8_embedded_jpeg",
        "legacy_v8_embedded_other",
        "legacy_v8_embedded_pdf",
        "legacy_v8_embedded_pe",
        "legacy_v8_embedded_png",
        "legacy_v8_embedded_zip",
        "legacy_v8_pypdf_ast_computed_members",
        "legacy_v8_pypdf_ast_loops",
        "legacy_v8_pypdf_ast_max_depth",
        "legacy_v8_pypdf_ast_node_count",
        "legacy_v8_pypdf_call_Collab.collectEmailInfo",
        "legacy_v8_pypdf_call_Function",
        "legacy_v8_pypdf_call_String.fromCharCode",
        "legacy_v8_pypdf_call_app.launchURL",
        "legacy_v8_pypdf_call_atob",
        "legacy_v8_pypdf_call_eval",
        "legacy_v8_pypdf_call_unescape",
        "legacy_v8_pypdf_call_util.printf",
        "legacy_v8_pypdf_scripts_found",
        "legacy_v8_pypdf_scripts_parsed",
        "legacy_www",
        "legacy_xref",
        "legacy_xref length",
        "lexical_AA",
        "lexical_AcroForm",
        "lexical_Acroform",
        "lexical_BaseEncoding",
        "lexical_BitsPerComponent",
        "lexical_Colors",
        "lexical_EmbeddedFile",
        "lexical_Encoding",
        "lexical_Encrypt",
        "lexical_JBIG2Decode",
        "lexical_JS",
        "lexical_JavaScript",
        "lexical_Launch",
        "lexical_ObjStm",
        "lexical_OpenAction",
        "lexical_ProcSet",
        "lexical_Registry",
        "lexical_Resources",
        "lexical_RichMedia",
        "lexical_Root",
        "lexical_URI",
        "lexical_XFA",
        "lexical_endobj",
        "lexical_endstream",
        "lexical_obj",
        "lexical_page_command",
        "lexical_server",
        "lexical_startxref",
        "lexical_stream",
        "lexical_trailer",
        "lexical_www",
        "lexical_xref",
        *(f"raw_byte_{index:03d}_count" for index in range(256)),
        "raw_entropy",
        "raw_escaped_name_candidates",
        "raw_header_offset",
        "raw_last_eof_offset",
        "raw_prefix_bytes",
        "raw_prefix_entropy",
        "raw_size_bytes",
        "raw_suffix_bytes",
        "raw_suffix_entropy",
    )
)
BULK_CHUNK_SIZE = 500
URI_SEALS = {
    jobs.URI_SAFEDOCS_REVIEW_KIND: {
        "selection_sha256": "2319e56108c75a7dd7d2b619f12685d3ed4199e3fc577edad81c84a5390892a2",
        "ordered_shas_sha256": "7950bceadee4b3642ff129a2b10f7bdf4db4e0759396ee5acbd67deb3714e311",
    },
    jobs.URI_REVIEW_KIND: {
        "selection_sha256": "c9d4e41ee7a852db39a28f23b2898cd9640274815aae9189162b98dd8b996a4c",
        "ordered_shas_sha256": "78a915d1f8b5a3e5974b72fc6072fdf4accdb97e6ec911d8ca62649a85499bc2",
    },
}
URI_COHORTS = {
    jobs.URI_SAFEDOCS_REVIEW_KIND: {
        "samples": 11,
        "bytes": 4520655,
        "roster_sha256": "03000ea32587e813fc68b854cf7a78303a3db153fdd6397e3ddd2433e6103619",
        "source_receipt_sha256": "8a1316aaac3c7a2b9730087824945dc202432e94334c5dcddfdcc09ea61db55a",
        "purpose": "static external-action evidence for SafeDocs URI label review",
        "model_evaluation_in_lab": False,
    },
    jobs.URI_REVIEW_KIND: {
        "samples": 151,
        "bytes": 31578824,
        "selection_sha256": "6cffc5934dca25333242018592afbc174504dc6e0c42b156a0fabe9afc05852d",
        "path_map_sha256": "a54c9a2da029b20a7b8c93ff43d81629676656318e076df14bd4afcf568b5031",
        "purpose": "static external-action evidence for URI label review",
        "model_evaluation_in_lab": False,
    },
}
PUBLISHER_CONTRACTS = {
    "pdf-benign-ood": {
        "manifest_sha256": "d4d31cde0d70ad6347d4fd4fb96afafe7d6b148c14dddc943bfba4a1515f844f",
        "source_counts": {"irs": 29, "rfc": 26, "arxiv": 28},
    },
    "pdf-benign-ood-expanded": {
        "manifest_sha256": "f9fb23c6880d47b03f34d04fe4995542568eba4054d673116466bb72da27ac43",
        "source_counts": {"rfc": 149, "fr": 79, "nasa": 110, "court": 41},
    },
    "pdf-benign-ood-diverse": {
        "manifest_sha256": "971f77b59c55b6e4d9dd68f6e080be84dc72de41cb9e1cbb6eca1f6c661d815b",
        "source_counts": {"arxiv": 160, "irs": 60, "nasa": 75, "nist": 82, "pdfjs": 50, "verapdf": 50},
    },
    "pdf-benign-v32-cohort": {
        "manifest_sha256": "69dd80240abc8cc2c48da6d1cac143e4dbf86d9b9cfaed9bd85cf9d1179b5371",
        "source_counts": {"arxiv": 160, "court": 16, "nasa": 98, "nist": 100, "pdfjs": 300, "verapdf": 300},
    },
}
FINGERPRINT_STATUSES = {
    "measured",
    "tlsh_unavailable",
    "input_unavailable",
    "sha256_mismatch",
    "publisher_sha1_mismatch",
}
HOLDOUT_INPUTS = {
    "references": 21414,
    "candidates": 145,
    "total_bytes": 1375512890,
    "manifest_sha256": "ead65d3f48dec64641bcebb2dfd836ce068c41372c067cec5f52c5d351da2a37",
    "publisher_sha256": "822e9f31295b2b4242febb429758c6be2924a2cd348168a281c25088493078b2",
    "engine_sha256": "3a014424253e9198d96543a4a644f3ea98d35bb8cd5301209809edb71eb0bcfe",
    "output": "holdout_fingerprints.json",
    "model_evaluation": False,
}
POOLED_INPUTS = {
    "samples": 20166,
    "total_bytes": 19257740191,
    "manifest_sha256": "d910bedcfe3415077189f7c64816b48dcc7a7f7b38d05a13366cfe9601a0e499",
    "engine_sha256": "3a014424253e9198d96543a4a644f3ea98d35bb8cd5301209809edb71eb0bcfe",
    "output": "holdout_fingerprints.json",
    "hashes": ["sha256", "sha1", "tlsh"],
    "model_evaluation": False,
}
PUBLISHER_FEATURES = (
    *(
        "lexical_" + name
        for name in (
            "AA",
            "AcroForm",
            "EmbeddedFile",
            "Encrypt",
            "JBIG2Decode",
            "JS",
            "JavaScript",
            "Launch",
            "ObjStm",
            "OpenAction",
            "Resources",
            "RichMedia",
            "Root",
            "URI",
            "XFA",
            "endobj",
            "endstream",
            "obj",
            "page_command",
            "stream",
            "trailer",
            "xref",
            "startxref",
        )
    ),
    "raw_size_bytes",
    "raw_entropy",
    "raw_header_offset",
    "raw_suffix_bytes",
    "raw_suffix_entropy",
    "raw_escaped_name_candidates",
    *("legacy_observed_ast_" + name for name in ("node_count", "max_depth", "loops", "computed_members")),
    *(
        "legacy_observed_ast_type_" + name
        for name in (
            "CallExpression",
            "Identifier",
            "MemberExpression",
            "Literal",
            "BinaryExpression",
            "NewExpression",
            "AssignmentExpression",
            "FunctionExpression",
            "FunctionDeclaration",
            "WhileStatement",
            "ForStatement",
        )
    ),
    *(
        "legacy_observed_call_" + name
        for name in (
            "eval",
            "unescape",
            "String.fromCharCode",
            "util.printf",
            "Collab.collectEmailInfo",
            "app.launchURL",
            "atob",
            "Function",
        )
    ),
    *(
        "legacy_v8_action_" + name
        for name in (
            "GoToE",
            "GoToR",
            "ImportData",
            "JavaScript",
            "Launch",
            "SubmitForm",
            "URI",
        )
    ),
    *("legacy_v8_embedded_" + name for name in ("elf", "jpeg", "other", "pdf", "pe", "png", "zip")),
    "js_per_obj",
    "stream_per_obj",
    "obj_endobj_diff",
    "stream_endstream_diff",
    "ast_call_ratio",
    "ast_identifier_ratio",
    "ast_computed_ratio",
)


def _strict_count_map(mapping, *, allow_slash=False):
    if not isinstance(mapping, dict):
        raise ValueError("export_shape_invalid")
    for key, count in mapping.items():
        if (
            not isinstance(key, str)
            or not 0 < len(key) <= 128
            or (not allow_slash and "/" in key)
            or "\\" in key
            or type(count) is not int
            or count < 0
        ):
            raise ValueError("export_shape_invalid")
    return mapping


def _validate_numeric_summary(summary, job_id, rows, availability):
    expected_partitions = dict(Counter(f"{row['split']}/{row['availability']}" for row in rows))
    if (
        not isinstance(summary, dict)
        or set(summary) != SUMMARY_KEYS
        or type(summary["schema_version"]) is not int
        or summary["schema_version"] != 1
        or summary["job_id"] != job_id
        or type(summary["planned"]) is not int
        or summary["planned"] != len(rows)
        or summary["availability"] != availability
        or _strict_count_map(summary["partition_coverage"], allow_slash=True) != expected_partitions
        or type(summary["elapsed_seconds"]) not in (int, float)
        or not math.isfinite(summary["elapsed_seconds"])
        or summary["elapsed_seconds"] < 0
    ):
        raise ValueError("export_shape_invalid")
    for field in SUMMARY_COUNTS:
        _strict_count_map(summary[field])
        if field in ("features_present", "features_nonnull") and not set(summary[field]) <= NUMERIC_FEATURE_NAMES:
            raise ValueError("export_shape_invalid")
    for field in SUMMARY_INDICES:
        items = summary[field]
        if not isinstance(items, list) or any(type(item) is not int or not 0 <= item < len(rows) for item in items):
            raise ValueError("export_shape_invalid")
    if any(type(summary[field]) is not int or summary[field] < 0 for field in SUMMARY_INTS):
        raise ValueError("export_shape_invalid")
    if any(summary[field] is not False for field in SUMMARY_FALSE):
        raise ValueError("export_shape_invalid")


def _finite_number(value):
    return type(value) in (int, float, bool) and abs(value) <= 1e100 and math.isfinite(value)


def _validate_numeric_projection(value, expected_sha256):
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "sample_sha256",
        "status",
        "features",
        "graph",
        "worker",
        "excluded_feature_count",
    }:
        raise ValueError("numeric_export_shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["sample_sha256"] != expected_sha256
        or not _hex(expected_sha256)
        or not isinstance(value["status"], str)
        or value["status"] not in jobs.PDF_STATUSES
        or type(value["excluded_feature_count"]) is not int
        or value["excluded_feature_count"] < 0
    ):
        raise ValueError("numeric_export_metadata")
    features = value["features"]
    if not isinstance(features, dict) or len(features) > 1024:
        raise ValueError("numeric_export_features")
    for name, item in features.items():
        if (
            name not in NUMERIC_FEATURE_NAMES
            or not isinstance(item, dict)
            or set(item) != {"value", "status", "scope_complete"}
        ):
            raise ValueError("numeric_export_feature_shape")
        status, feat_val, complete = item["status"], item["value"], item["scope_complete"]
        if (
            not isinstance(status, str)
            or status not in jobs.PDF_STATUSES
            or type(complete) is not bool
            or (feat_val is not None and not _finite_number(feat_val))
            or (status in NUMERIC_UNAVAILABLE and feat_val is not None)
            or (status in {"observed", "absent_within_scope"} and feat_val is None)
            or (status == "absent_within_scope" and (feat_val != 0 or not complete))
        ):
            raise ValueError("numeric_export_feature")
    graph = value["graph"]
    if not isinstance(graph, dict) or set(graph) != {
        "node_types",
        "node_sizes_bytes",
        "edge_src",
        "edge_dst",
        "edge_rel",
        "excluded_node_count",
        "excluded_edge_count",
        "observed_attributes_complete",
        "model_input_ready",
    }:
        raise ValueError("numeric_export_graph_shape")
    nodes, sizes = graph["node_types"], graph["node_sizes_bytes"]
    if (
        not isinstance(nodes, list)
        or len(nodes) > 200
        or not isinstance(sizes, list)
        or len(nodes) != len(sizes)
        or any(type(item) is not int or not 0 <= item < 9 for item in nodes)
        or any(
            item is not None and (type(item) not in (int, float) or not _finite_number(item) or item < 0)
            for item in sizes
        )
    ):
        raise ValueError("numeric_export_nodes")
    for key, bound in (("edge_src", len(nodes)), ("edge_dst", len(nodes)), ("edge_rel", 8)):
        items = graph[key]
        if (
            not isinstance(items, list)
            or len(items) > 40000
            or any(type(item) is not int or not 0 <= item < bound for item in items)
        ):
            raise ValueError("numeric_export_edges")
    edge_src, edge_dst, edge_rel = graph["edge_src"], graph["edge_dst"], graph["edge_rel"]
    if (
        len(edge_src) != len(edge_dst)
        or len(edge_src) != len(edge_rel)
        or graph["model_input_ready"] is not False
        or graph["observed_attributes_complete"] is not (bool(sizes) and all(item is not None for item in sizes))
        or any(type(graph[key]) is not int or graph[key] < 0 for key in ("excluded_node_count", "excluded_edge_count"))
    ):
        raise ValueError("numeric_export_graph_metadata")
    worker = value["worker"]
    if not isinstance(worker, dict) or set(worker) != {
        "worker_cleanup_complete",
        "peak_rss_bytes",
        "worker_exit_code",
        "worker_seconds",
    }:
        raise ValueError("numeric_export_worker_shape")
    if worker["worker_cleanup_complete"] is not None and type(worker["worker_cleanup_complete"]) is not bool:
        raise ValueError("numeric_export_worker")
    for key in ("peak_rss_bytes", "worker_exit_code", "worker_seconds"):
        metric = worker[key]
        if metric is not None and (
            type(metric) not in (int, float) or not _finite_number(metric) or (key != "worker_exit_code" and metric < 0)
        ):
            raise ValueError("numeric_export_worker")


def _numeric_rows(rows, job):
    cve = job["kind"] == CVE
    if cve and len(rows) != len(CVE_NAMES):
        raise ValueError("cve_selection_invalid")
    fields = {"index", "sha256", "label", "source_bundle_sha256", "availability", "numeric"}
    fields |= {"sample_id"} if cve else {"split"}
    seen_shas = set()
    for index, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or set(row) != fields
            or type(row["index"]) is not int
            or row["index"] != index
            or not _hex(row["sha256"])
            or row["sha256"] in seen_shas
            or type(row["label"]) is not int
            or row["label"] not in (0, 1)
            or row["availability"] not in ("present", "missing", "invalid")
            or (row["availability"] == "missing" and row["source_bundle_sha256"] is not None)
            or (row["availability"] == "present" and row["source_bundle_sha256"] is None)
            or (row["source_bundle_sha256"] is not None and not _hex(row["source_bundle_sha256"]))
        ):
            raise ValueError("export_row_invalid")
        seen_shas.add(row["sha256"])
        if cve:
            if row["label"] != 1 or row["sample_id"] != f"cve_t4pdf:{CVE_NAMES[index]}":
                raise ValueError("cve_selection_invalid")
        elif row["split"] not in ("train", "validation", "test"):
            raise ValueError("export_row_invalid")
        if row["availability"] == "present":
            _validate_numeric_projection(row["numeric"], row["sha256"])
        elif row["numeric"] is not None:
            raise ValueError("export_row_invalid")


def validate_export(raw, job):
    kind, job_id = job["kind"], job["job_id"]
    if not raw or len(raw) > EXPORT_CONTRACTS[kind] or text_failure(raw, "export.json"):
        raise ValueError("export_bytes_rejected")
    value = parse_json(raw.decode("utf-8", "strict"))
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("job_id") != job_id
        or value.get("kind") != kind
    ):
        raise ValueError("export_identity_invalid")
    common = {"schema_version", "job_id", "kind"}
    if "export_mode" in value:
        if (
            set(value) != common | {"export_mode", "runner", "unavailable_reason"}
            or value["export_mode"] != FAILURE_EXPORT_MODE
            or value["unavailable_reason"] != FAILURE_UNAVAILABLE_REASON
        ):
            raise ValueError("export_shape_invalid")
        jobs.validate_result(value["runner"], job)
        if value["runner"]["status"] not in FAILURE_ONLY_STATUSES or _is_resumable_bulk_pause(kind, value["runner"]):
            raise ValueError("export_shape_invalid")
        return value
    if kind == BULK:
        if (
            set(value) != common | {"plan", "runner", "attempts", "chunks"}
            or not isinstance(value["plan"], dict)
            or not isinstance(value["attempts"], list)
            or not isinstance(value["chunks"], list)
        ):
            raise ValueError("export_shape_invalid")
        plan = value["plan"]
        if (
            set(plan) != {"sha256", "selection_sha256", "planned_denominator"}
            or not _hex(plan["sha256"])
            or not _hex(plan["selection_sha256"])
            or type(plan["planned_denominator"]) is not int
            or plan["planned_denominator"] < 1
        ):
            raise ValueError("export_shape_invalid")
        jobs.validate_result(value["runner"], job)
        if value["runner"]["status"] not in TERMINAL_STATUSES:
            raise ValueError("export_shape_invalid")
        seen_attempts = set()
        for attempt in value["attempts"]:
            if not isinstance(attempt, dict) or set(attempt) != {"attempt_id", "status", "cleanup_verified"}:
                raise ValueError("export_shape_invalid")
            attempt_id = attempt["attempt_id"]
            if (
                not isinstance(attempt_id, str)
                or not CYCLE_ID.fullmatch(attempt_id)
                or attempt_id in seen_attempts
                or type(attempt["cleanup_verified"]) is not bool
                or attempt["status"]
                not in (
                    ("interrupted", "complete", "failed")
                    if attempt["cleanup_verified"]
                    else ("cleanup_unverified", None)
                )
            ):
                raise ValueError("export_shape_invalid")
            seen_attempts.add(attempt_id)
        last_chunk = -1
        planned = plan["planned_denominator"]
        total_chunks = (planned + BULK_CHUNK_SIZE - 1) // BULK_CHUNK_SIZE
        for chunk in value["chunks"]:
            if (
                not isinstance(chunk, dict)
                or set(chunk) != {"chunk_id", "count", "sha256", "provenance"}
                or any(type(chunk[key]) is not int for key in ("chunk_id", "count"))
                or not last_chunk < chunk["chunk_id"] < total_chunks
                or chunk["count"] != min(BULK_CHUNK_SIZE, planned - chunk["chunk_id"] * BULK_CHUNK_SIZE)
                or not _hex(chunk["sha256"])
                or chunk["provenance"] not in ("adopted_baseline", "produced_by_job")
            ):
                raise ValueError("export_shape_invalid")
            last_chunk = chunk["chunk_id"]
    elif kind in NUMERIC_KINDS or kind == CVE:
        extra = {"rows", "selection_sha256", "availability"} if kind == CVE else {"rows", "summary"}
        if set(value) != common | extra or not isinstance(value["rows"], list):
            raise ValueError("export_shape_invalid")
        _numeric_rows(value["rows"], job)
        availability = dict(Counter(row["availability"] for row in value["rows"]))
        if kind == CVE:
            if not _hex(value["selection_sha256"]) or _strict_count_map(value["availability"]) != availability:
                raise ValueError("export_shape_invalid")
        else:
            _validate_numeric_summary(value["summary"], job_id, value["rows"], availability)
    elif kind in jobs.URI_REVIEW_KINDS:
        expected_cohort = URI_COHORTS[kind]
        expected_seal = URI_SEALS[kind]
        if (
            set(value) != common | {"records", "cohort", "selection_sha256", "status_counts"}
            or value["selection_sha256"] != expected_seal["selection_sha256"]
            or not isinstance(value["records"], list)
            or not _exact_json_equal(value["cohort"], expected_cohort)
            or len(value["records"]) != expected_cohort["samples"]
            or any(not isinstance(row, dict) for row in value["records"])
            or _strict_count_map(value["status_counts"]) != dict(Counter(row.get("status") for row in value["records"]))
        ):
            raise ValueError("export_shape_invalid")
        seen_shas = set()
        ordered_shas = []
        for row in value["records"]:
            if (
                set(row)
                != {"sha256", "status", "actions_observed", "actions_without_target", "targets_clipped", "targets"}
                or not _hex(row["sha256"])
                or row["sha256"] in seen_shas
                or row["status"] not in ("missing", "invalid", "observed_targets", "unresolved")
                or type(row["targets_clipped"]) is not bool
                or not isinstance(row["targets"], list)
            ):
                raise ValueError("export_shape_invalid")
            seen_shas.add(row["sha256"])
            ordered_shas.append(row["sha256"])
            status = row["status"]
            actions_observed, actions_without = row["actions_observed"], row["actions_without_target"]
            clipped, targets = row["targets_clipped"], row["targets"]
            if status in ("missing", "invalid"):
                if actions_observed is not None or actions_without is not None or clipped is not False or targets != []:
                    raise ValueError("export_shape_invalid")
            elif status == "unresolved":
                if (
                    type(actions_observed) is not int
                    or actions_observed < 0
                    or type(actions_without) is not int
                    or actions_without != actions_observed
                    or clipped is not False
                    or targets != []
                ):
                    raise ValueError("export_shape_invalid")
            else:
                if (
                    type(actions_observed) is not int
                    or actions_observed < 1
                    or type(actions_without) is not int
                    or not 0 <= actions_without < actions_observed
                    or not 1 <= len(targets) <= 256
                    or len(targets) > actions_observed - actions_without
                    or (clipped and (len(targets) != 256 or actions_observed - actions_without <= 256))
                ):
                    raise ValueError("export_shape_invalid")
            previous_target = None
            for target in targets:
                if (
                    not isinstance(target, dict)
                    or set(target) != {"action", "target_sha256", "placement_observed"}
                    or target["action"] not in ("/URI", "/SubmitForm")
                    or not _hex(target["target_sha256"])
                    or type(target["placement_observed"]) is not bool
                ):
                    raise ValueError("export_shape_invalid")
                key = (target["action"], target["target_sha256"], target["placement_observed"])
                if previous_target is not None and key <= previous_target:
                    raise ValueError("export_shape_invalid")
                previous_target = key
        ordered_digest = hashlib.sha256(json.dumps(ordered_shas, separators=(",", ":")).encode("ascii")).hexdigest()
        if ordered_digest != expected_seal["ordered_shas_sha256"]:
            raise ValueError("export_shape_invalid")
    elif kind == jobs.URI_HEAD_EVAL_KIND:
        expected_cohorts = URI_HEAD_EVAL_COHORT["cohort_counts"]
        if (
            set(value)
            != common
            | {"selection_sha256", "cohort", "runner_status", "eval_status_counts", "cohort_summary", "records"}
            or not _hex(value["selection_sha256"])
            or not _exact_json_equal(value["cohort"], URI_HEAD_EVAL_COHORT)
            or value["runner_status"] not in {"passed", "partial", "failed", "interrupted"}
            or not isinstance(value["records"], list)
            or len(value["records"]) != URI_HEAD_EVAL_COHORT["samples"]
            or not isinstance(value["cohort_summary"], dict)
            or set(value["cohort_summary"]) != set(expected_cohorts)
        ):
            raise ValueError("export_shape_invalid")
        if _strict_count_map(value["eval_status_counts"]) != dict(
            Counter(row.get("eval_status") for row in value["records"] if isinstance(row, dict))
        ):
            raise ValueError("export_shape_invalid")
        seen_cohort_counts = {name: 0 for name in expected_cohorts}
        for idx, row in enumerate(value["records"]):
            if (
                not isinstance(row, dict)
                or set(row) != URI_HEAD_EVAL_RECORD_KEYS
                or row["index"] != idx
                or not _hex(row["sha256"])
                or row["cohort"] not in expected_cohorts
                or row["eval_status"] not in URI_HEAD_EVAL_STATUSES
                or row["tier"] not in URI_HEAD_EVAL_TIERS
                or type(row["max_prob"]) not in (int, float)
                or not math.isfinite(float(row["max_prob"]))
                or not 0.0 <= float(row["max_prob"]) <= 1.0
                or any(
                    type(row[k]) is not int or row[k] < 0
                    for k in ("scored_url_count", "allowlisted_url_count", "filtered_xml_xmp_count")
                )
                or not isinstance(row["vector_counts"], dict)
                or any(
                    not isinstance(vk, str) or vk not in URI_HEAD_EVAL_VECTORS or type(vv) is not int or vv < 0
                    for vk, vv in row["vector_counts"].items()
                )
                or (row["top_url_vector"] is not None and row["top_url_vector"] not in URI_HEAD_EVAL_VECTORS)
                or type(row["heuristic_phishing"]) is not bool
                or type(row["password_locked"]) is not bool
            ):
                raise ValueError("export_shape_invalid")
            seen_cohort_counts[row["cohort"]] += 1
        if seen_cohort_counts != expected_cohorts:
            raise ValueError("export_shape_invalid")
        for c_name, c_stats in value["cohort_summary"].items():
            if (
                not isinstance(c_stats, dict)
                or set(c_stats) != URI_HEAD_EVAL_SUMMARY_KEYS
                or c_stats["count"] != expected_cohorts[c_name]
                or any(
                    type(c_stats[k]) is not int or c_stats[k] < 0
                    for k in (
                        "observed",
                        "password_locked",
                        "ingest_error",
                        "missing_or_invalid",
                        "or_gate_count",
                        "gated_fusion_count",
                        "heuristic_phishing_count",
                        "total_scored_urls",
                        "total_allowlisted_urls",
                        "total_filtered_xml_xmp",
                    )
                )
                or any(
                    type(c_stats[k]) not in (int, float)
                    or not math.isfinite(float(c_stats[k]))
                    or not 0.0 <= float(c_stats[k]) <= 1.0
                    for k in ("or_gate_rate", "max_prob_p50", "max_prob_p95", "max_prob_p99", "max_prob_max")
                )
                or not isinstance(c_stats["vector_counts"], dict)
                or any(
                    not isinstance(vk, str) or vk not in URI_HEAD_EVAL_VECTORS or type(vv) is not int or vv < 0
                    for vk, vv in c_stats["vector_counts"].items()
                )
            ):
                raise ValueError("export_shape_invalid")
        if not _exact_json_equal(value["cohort_summary"], _recompute_uri_eval_cohort_summary(value["records"])):
            raise ValueError("export_shape_invalid")
    elif kind in jobs.FINGERPRINT_KINDS:
        fields = {"inputs", "fingerprints", "fingerprint_status_counts", "new_malware_labels", "runner_summary"}
        holdout = kind == jobs.HOLDOUT_TLSH_KIND
        if holdout:
            fields |= {"candidate_comparison", "publisher_sha1_matches"}
        summary = value.get("runner_summary")
        if (
            set(value) != common | fields
            or not _exact_json_equal(value["inputs"], HOLDOUT_INPUTS if holdout else POOLED_INPUTS)
            or not isinstance(value["fingerprints"], list)
            or len(value["fingerprints"]) != job["limits"]["samples"]
            or type(value["new_malware_labels"]) is not int
            or value["new_malware_labels"] != 0
            or not isinstance(summary, dict)
            or set(summary) != jobs.SUMMARY_FIELDS
            or not jobs.summary_valid(summary)
            or type(summary["planned"]) is not int
            or summary["planned"] != job["limits"]["samples"]
        ):
            raise ValueError("export_shape_invalid")
        fp_by_sha = {}
        for row in value["fingerprints"]:
            if not isinstance(row, dict):
                raise ValueError("export_shape_invalid")
            status = row.get("status")
            required_keys = {"sha256", "status", "tlsh"}
            if not holdout and status in ("measured", "tlsh_unavailable"):
                required_keys = {"sha256", "status", "tlsh", "sha1"}
            if (
                set(row) != required_keys
                or not _hex(row["sha256"])
                or row["sha256"] in fp_by_sha
                or status not in FINGERPRINT_STATUSES
                or (status == "measured") != (row["tlsh"] is not None)
                or row["tlsh"] is not None
                and (not isinstance(row["tlsh"], str) or not TLSH.fullmatch(row["tlsh"]))
                or "sha1" in row
                and (not isinstance(row["sha1"], str) or not re.fullmatch(r"[a-f0-9]{40}", row["sha1"]))
            ):
                raise ValueError("export_shape_invalid")
            fp_by_sha[row["sha256"]] = row
        expected_counts = dict(Counter(row["status"] for row in value["fingerprints"]))
        if _strict_count_map(value["fingerprint_status_counts"]) != expected_counts:
            raise ValueError("export_shape_invalid")
        measured = expected_counts.get("measured", 0)
        missing = expected_counts.get("tlsh_unavailable", 0)
        unavailable = expected_counts.get("input_unavailable", 0)
        mismatches = expected_counts.get("sha256_mismatch", 0) + expected_counts.get("publisher_sha1_mismatch", 0)
        expected_status_counts = {
            name: amount
            for name, amount in (
                ("observed", measured),
                ("partial", missing),
                ("not_run", unavailable),
                ("decode_error", mismatches),
            )
            if amount
        }
        if (
            summary["completed"] != len(value["fingerprints"])
            or summary["observed"] != measured
            or summary["partial"] != missing
            or summary["failed"] != unavailable + mismatches
            or summary["primary_available"] != measured + missing
            or summary["timeout"] != 0
            or summary["status_counts"] != expected_status_counts
        ):
            raise ValueError("export_shape_invalid")
        if holdout:
            matches = value["publisher_sha1_matches"]
            comparison = value["candidate_comparison"]
            if (
                type(matches) is not int
                or not 0 <= matches <= 132
                or not isinstance(comparison, dict)
                or len(comparison) != HOLDOUT_INPUTS["candidates"]
            ):
                raise ValueError("export_shape_invalid")
            if any(not _hex(sha) or sha not in fp_by_sha for sha in comparison):
                raise ValueError("export_shape_invalid")
            ref_rows = [row for sha, row in fp_by_sha.items() if sha not in comparison]
            if (
                job["limits"]["samples"] == HOLDOUT_INPUTS["references"] + HOLDOUT_INPUTS["candidates"]
                and len(ref_rows) != HOLDOUT_INPUTS["references"]
            ):
                raise ValueError("export_shape_invalid")
            measured_refs = sum(1 for row in ref_rows if row["status"] == "measured")
            reference_complete = bool(ref_rows) and measured_refs == len(ref_rows)
            for sha, entry in comparison.items():
                if not isinstance(entry, dict) or set(entry) != {"disposition", "distance"}:
                    raise ValueError("export_shape_invalid")
                cand_row = fp_by_sha[sha]
                disp, dist = entry["disposition"], entry["distance"]
                if cand_row["tlsh"] is None:
                    ok = disp == "candidate_fingerprint_unavailable" and dist is None
                elif disp == "near_duplicate":
                    ok = measured_refs > 0 and type(dist) is int and 0 <= dist <= 30
                elif disp == "no_near_duplicate_in_reference":
                    ok = reference_complete and type(dist) is int and dist > 30
                elif disp == "reference_coverage_incomplete":
                    ok = (not reference_complete) and (
                        dist is None if measured_refs == 0 else (type(dist) is int and dist > 30)
                    )
                else:
                    ok = False
                if not ok:
                    raise ValueError("export_shape_invalid")
    else:
        contract = PUBLISHER_CONTRACTS[kind]
        if (
            set(value) != common | {"manifest_sha256", "feature_order", "runner", "rows"}
            or value["manifest_sha256"] != contract["manifest_sha256"]
            or value["feature_order"] != list(PUBLISHER_FEATURES)
            or not isinstance(value["rows"], list)
        ):
            raise ValueError("export_shape_invalid")
        jobs.validate_result(value["runner"], job)
        if value["runner"]["status"] not in ("passed", "partial"):
            raise ValueError("export_shape_invalid")
        seen_shas, seen_ids = set(), set()
        for row in value["rows"]:
            if (
                not isinstance(row, dict)
                or set(row) != {"sha256", "source", "id", "tlsh", "status", "features", "graph"}
                or not _hex(row["sha256"])
                or row["sha256"] in seen_shas
                or not isinstance(row["source"], str)
                or row["source"] not in contract["source_counts"]
                or not isinstance(row["id"], str)
                or re.fullmatch(re.escape(row["source"]) + r"-[0-9]{3}", row["id"]) is None
                or row["id"] in seen_ids
                or row["status"] not in jobs.PDF_STATUSES
                or row["tlsh"] is not None
                and (not isinstance(row["tlsh"], str) or not TLSH.fullmatch(row["tlsh"]))
                or (row["features"] is None) != (row["graph"] is None)
            ):
                raise ValueError("export_shape_invalid")
            seen_shas.add(row["sha256"])
            seen_ids.add(row["id"])
            if row["features"] is not None:
                feats = row["features"]
                if (
                    not isinstance(feats, list)
                    or len(feats) != len(PUBLISHER_FEATURES)
                    or any(
                        item is not None and (type(item) not in (int, float) or not math.isfinite(item))
                        for item in feats
                    )
                ):
                    raise ValueError("export_shape_invalid")
                graph = row["graph"]
                if not isinstance(graph, list) or len(graph) != 5:
                    raise ValueError("export_shape_invalid")
                node_features, node_types, edge_src, edge_dst, edge_rel = graph
                if (
                    not isinstance(node_types, list)
                    or not 0 < len(node_types) <= 200
                    or any(type(item) is not int or not 0 <= item < 9 for item in node_types)
                    or not isinstance(node_features, list)
                    or len(node_features) != len(node_types)
                    or any(
                        not isinstance(feat_row, list)
                        or len(feat_row) != 23
                        or any(type(val) not in (int, float) or not math.isfinite(val) for val in feat_row)
                        for feat_row in node_features
                    )
                    or any(not isinstance(arr, list) for arr in (edge_src, edge_dst, edge_rel))
                    or not len(edge_src) == len(edge_dst) == len(edge_rel) <= 40000
                    or any(type(idx) is not int or not 0 <= idx < len(node_types) for idx in (*edge_src, *edge_dst))
                    or any(type(rel) is not int or not 0 <= rel < 8 for rel in edge_rel)
                ):
                    raise ValueError("export_shape_invalid")
        if Counter(row["source"] for row in value["rows"]) != contract["source_counts"]:
            raise ValueError("export_shape_invalid")
    rows = value.get("rows", value.get("records", value.get("fingerprints")))
    if rows is not None and len(rows) != job["limits"]["samples"]:
        raise ValueError("export_count_mismatch")
    return value


def export_numeric(job, limit):
    from export_numeric_postrun import export_job

    with tempfile.TemporaryDirectory() as folder:
        exported = export_job(job["job_id"], job_root=jobs.JOBS, export_root=Path(folder))
        output = jobs.trusted_path(Path(exported["output"]))
        if not output.is_relative_to(Path(folder)):
            raise ValueError("export_path_invalid")
        summary = read_json(output / "coverage.json", MIB)
        rows, total = [], 0
        with gzip.open(jobs.trusted_path(output / "numeric.jsonl.gz"), "rt", encoding="utf-8", newline="") as stream:
            while line := stream.readline(2 * MIB + 1):
                total += len(line.encode("utf-8"))
                if total > limit or len(line) > 2 * MIB or len(rows) >= job["limits"]["samples"]:
                    raise ValueError("export_size_limit")
                rows.append(parse_json(line))
        return {"summary": summary, "rows": rows}


def export_cve(job, directory):
    from malpdf.extraction.contracts import validate_bundle
    from malpdf.extraction.numeric_export import project_numeric_bundle

    jobs.validate_result(read_json(directory / "result.json", MAX_REPORT), job)
    selection = read_json(directory / "selection.json", MIB)
    rows = selection["rows"]
    if (
        not isinstance(rows, list)
        or selection["job_id"] != job["job_id"]
        or selection["selection_sha256"] != jobs.sha(jobs.encoded(rows))
        or len(rows) != len(CVE_NAMES)
        or len(rows) != job["limits"]["samples"]
    ):
        raise ValueError("cve_selection_invalid")
    records = []
    seen_shas = set()
    for index, row in enumerate(rows):
        expected_name = CVE_NAMES[index]
        expected_id = f"cve_t4pdf:{expected_name}"
        expected_path = f"data/raw/cve_t4pdf/{expected_name}"
        if (
            not isinstance(row, dict)
            or set(row) not in (CVE_FIELDS, CVE_FIELDS | {"manifest_pdf_relative_path"})
            or row["Label"] not in (1, "1")
            or row["sample_id"] != expected_id
            or row["pdf_relative_path"] != expected_path
            or not _hex(row["pdf_sha256"])
            or row["pdf_sha256"] in seen_shas
            or not isinstance(row["label_source"], str)
            or not 1 <= len(row["label_source"]) <= 256
            or any(not 32 <= ord(ch) < 127 for ch in row["label_source"])
        ):
            raise ValueError("cve_selection_invalid")
        seen_shas.add(row["pdf_sha256"])
        digest = row["pdf_sha256"]
        record = {
            "index": index,
            "sha256": digest,
            "label": 1,
            "sample_id": expected_id,
            "availability": "missing",
            "source_bundle_sha256": None,
            "numeric": None,
        }
        path = jobs.trusted_path(directory / "private_bundles" / f"{index:04d}.json")
        if path.is_file():
            try:
                payload = side.bounded_read(path, jobs.pdf_bundle_limit(CVE) + 1024)
                record["source_bundle_sha256"] = jobs.sha(payload)
                bundle = parse_json(payload)
                validate_bundle(bundle)
                projected = project_numeric_bundle(bundle, digest)
            except (OSError, ValueError, TypeError, KeyError, OverflowError):
                record["availability"] = "invalid"
            else:
                record.update(availability="present", numeric=projected)
        records.append(record)
    return {
        "selection_sha256": selection["selection_sha256"],
        "rows": records,
        "availability": dict(Counter(row["availability"] for row in records)),
    }


def _adopted_bulk_hashes(plan, plan_sha, job, directory):
    baseline = plan.get("baseline")
    if baseline is None:
        return ()
    if not isinstance(baseline, dict):
        raise ValueError("bulk_plan_invalid")
    hashes = baseline.get("checkpoint_sha256")
    adopted_count = baseline.get("adopted_checkpoint_count")
    replacements = baseline.get("replaced_checkpoints")
    if (
        not isinstance(hashes, list)
        or any(not _hex(digest) for digest in hashes)
        or type(adopted_count) is not int
        or not 0 <= adopted_count <= len(hashes)
        or replacements != {str(i): hashes[i] for i in range(adopted_count, len(hashes))}
    ):
        raise ValueError("bulk_plan_invalid")
    marker = jobs.trusted_path(directory / "bulk_pilot_passed.json")
    report = jobs.trusted_path(directory / "bulk_pilot_report.json")
    if not marker.is_file():
        return ()
    if not report.is_file():
        raise ValueError("bulk_pilot_marker_invalid")
    report_bytes = side.bounded_read(report, MIB)
    report_doc = parse_json(report_bytes)
    counts = report_doc.get("counts") if isinstance(report_doc, dict) else None
    if (
        not isinstance(report_doc, dict)
        or report_doc.get("commit") != job["commit"]
        or report_doc.get("plan_sha256") != plan_sha
        or not isinstance(counts, dict)
        or type(counts.get("unexplained")) is not int
        or counts["unexplained"] != 0
    ):
        raise ValueError("bulk_pilot_report_invalid")
    expected_marker = {
        "commit": job["commit"],
        "plan_sha256": plan_sha,
        "report_sha256": jobs.sha(report_bytes),
    }
    if read_json(marker, 4096) != expected_marker:
        raise ValueError("bulk_pilot_marker_invalid")
    return tuple(hashes[:adopted_count])


def export_bulk(job, directory, data_root):
    plan_raw = side.bounded_read(jobs.trusted_path(directory / "bulk_plan.json"), RECEIPT_LIMIT)
    plan = parse_json(plan_raw)
    if (
        not isinstance(plan, dict)
        or plan.get("job_id") != job["job_id"]
        or plan.get("output_root") != BULK_OUTPUT
        or not _hex(plan.get("selection_sha256"))
    ):
        raise ValueError("bulk_plan_invalid")
    adopted_hashes = _adopted_bulk_hashes(plan, jobs.sha(plan_raw), job, directory)
    expected_producer = {
        "commit": job["commit"],
        "job_id": job["job_id"],
        "selection_sha256": plan["selection_sha256"],
    }
    chunks = []
    root = jobs.trusted_path(data_root / BULK_OUTPUT / "chunks")
    if root.is_dir():
        for index, entry in enumerate(root.iterdir()):
            if index >= 4096:
                raise ValueError("export_size_limit")
            name = re.fullmatch(r"chunk_([0-9]{5})", entry.name)
            if name and (entry / "chunk_done.json").is_file():
                raw = side.bounded_read(jobs.trusted_path(entry / "chunk_done.json"), RECEIPT_LIMIT)
                manifest = parse_json(raw)
                cid = manifest["chunk_id"]
                if manifest["schema_version"] != 1 or type(cid) is not int or cid != int(name[1]):
                    raise ValueError("chunk_manifest_mismatch")
                digest = jobs.sha(raw)
                if manifest.get("producer") == expected_producer:
                    provenance = "produced_by_job"
                elif cid < len(adopted_hashes) and digest == adopted_hashes[cid]:
                    provenance = "adopted_baseline"
                else:
                    continue
                chunks.append({"chunk_id": cid, "count": manifest["count"], "sha256": digest, "provenance": provenance})
    attempts = []
    for attempt in attempts_in(directory):
        path = attempt / "result.json"
        value = read_json(path, 4096) if path.is_file() else {"status": None, "cleanup_verified": False}
        attempts.append(
            {"attempt_id": attempt.name, "status": value["status"], "cleanup_verified": value["cleanup_verified"]}
        )
    return {
        "plan": {
            "sha256": jobs.sha(plan_raw),
            "selection_sha256": plan["selection_sha256"],
            "planned_denominator": plan["planned_denominator"],
        },
        "runner": jobs.read_result(job["job_id"]),
        "attempts": attempts,
        "chunks": sorted(chunks, key=lambda chunk: chunk["chunk_id"]),
    }


def export_job(job_id):
    if not jobs.HEX.fullmatch(job_id):
        raise ValueError("job_mismatch")
    cfg = jobs.config()
    job = jobs.load_job(job_id)
    kind = job["kind"]
    if job["job_id"] != job_id or kind not in EXPORT_CONTRACTS or job["mode"] != "offline":
        raise ValueError("job_mismatch")
    metadata = side.verify_release(job["commit"], job["manifest_sha256"])
    jobs.verify_helpers(metadata)
    source = side.RELEASES / job["commit"]
    sys.path[:0] = [str(source / "src"), str(source / "scripts/lab")]
    directory = jobs.job_directory(job_id)
    limit = EXPORT_CONTRACTS[kind]
    try:
        if kind in jobs.URI_REVIEW_KINDS:
            value = importlib.import_module("export_uri_review").export_review(job_id)
        elif kind == jobs.URI_HEAD_EVAL_KIND:
            value = importlib.import_module("export_uri_head_eval").export_eval(job_id)
        elif kind in PUBLISHER_EXPORTERS:
            value = importlib.import_module(PUBLISHER_EXPORTERS[kind]).export(job_id)
        elif kind in jobs.FINGERPRINT_KINDS:
            value = read_json(directory / "holdout_fingerprints.json", limit)
        elif kind in NUMERIC_KINDS:
            value = export_numeric(job, limit)
        elif kind == CVE:
            value = export_cve(job, directory)
        else:
            value = export_bulk(job, directory, Path(cfg["data_root"]))
    except (FileNotFoundError, ValueError) as export_error:
        unavailable_errors = {
            "offline_benign_result_unavailable",
            "offline_expanded_result_unavailable",
            "offline_diverse_result_unavailable",
            "offline_v32_result_unavailable",
        }
        eligible_error = isinstance(export_error, FileNotFoundError) or (
            str(export_error) in unavailable_errors
            or (kind in jobs.URI_REVIEW_KINDS | {jobs.URI_HEAD_EVAL_KIND} and str(export_error) == "report_invalid")
        )
        if not eligible_error or not (directory / "result.json").is_file():
            raise
        runner_result = jobs.validate_result(jobs.read_result(job_id), job)
        if runner_result["status"] not in FAILURE_ONLY_STATUSES or _is_resumable_bulk_pause(kind, runner_result):
            raise
        value = {
            "export_mode": FAILURE_EXPORT_MODE,
            "runner": runner_result,
            "unavailable_reason": FAILURE_UNAVAILABLE_REASON,
        }
    if value.get("job_id", job_id) != job_id or value.get("kind", kind) != kind or value.get("schema_version", 1) != 1:
        raise ValueError("export_identity_invalid")
    raw = json_bytes({**value, "schema_version": 1, "job_id": job_id, "kind": kind})
    validate_export(raw, job)
    return raw


def _run_isolated_receive(job_id):
    if sys.platform != "linux":
        raise ValueError("runtime_unavailable")
    if not jobs.HEX.fullmatch(job_id):
        raise ValueError("job_mismatch")
    import resource
    import signal

    signal.alarm(240)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * MIB, 2 * 1024 * MIB))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 1800))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * MIB, 64 * MIB))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (2048, 2048))
    import lab_runner

    with jobs.execution_limits("synthetic"):
        value = lab_runner.receive(sys.stdin.buffer, job_id)
    return json_bytes(jobs.validate_result(value, jobs.load_job(job_id)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "disarm", "boot-exec", "_credentials"):
        subparsers.add_parser(name)
    for name in ("arm", "read-receipt", "export", "_export", "receive", "_receive", "report", "_report"):
        child = subparsers.add_parser(name)
        child.add_argument("--job-id", required=True)
        if name == "arm":
            child.add_argument("--kind", required=True)
            child.add_argument("--cycle-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            raw = json_bytes(status())
        elif args.command == "arm":
            raw = json_bytes(arm(args.job_id, args.kind, args.cycle_id))
        elif args.command == "disarm":
            raw = json_bytes(disarm())
        elif args.command == "boot-exec":
            receipt = boot_exec()
            if receipt["outcome"] == "unexpected_incomplete":
                raise ValueError("unexpected_incomplete")
            raw = json_bytes(receipt)
        elif args.command == "read-receipt":
            require_root()
            raw = read_receipt(args.job_id)
        elif args.command == "_credentials":
            jobs.check_credentials(Path(jobs.config()["data_root"]))
            raw = b"{}\n"
        elif args.command == "_export":
            with redirect_stdout(io.StringIO()):
                raw = export_job(args.job_id)
        elif args.command == "_receive":
            with redirect_stdout(io.StringIO()):
                raw = _run_isolated_receive(args.job_id)
        elif args.command == "_report":
            if not jobs.HEX.fullmatch(args.job_id):
                raise ValueError("job_mismatch")
            job = jobs.load_job(args.job_id)
            raw = json_bytes(jobs.validate_result(jobs.read_result(job["job_id"]), job))
        elif args.command == "receive":
            require_root()
            if not jobs.HEX.fullmatch(args.job_id):
                raise ValueError("job_mismatch")
            verify_auto_manifest()
            payload = sys.stdin.buffer.read(64 * MIB + 1)
            if not payload or len(payload) > 64 * MIB:
                raise ValueError("receive_size_limit")
            _, account = runner_account()
            command = [PYTHON, "-I", "-B", ADMIN_PATH.as_posix(), "_receive", "--job-id", args.job_id]
            _, raw = as_runner(command, account, timeout=245, limit=MAX_REPORT, payload=payload)
            if text_failure(raw, "receive.json"):
                raise ValueError("export_bytes_rejected")
            jobs.validate_result(parse_json(raw), jobs.load_job(args.job_id))
        elif args.command == "report":
            require_root()
            if not jobs.HEX.fullmatch(args.job_id):
                raise ValueError("job_mismatch")
            verify_auto_manifest()
            job = jobs.load_job(args.job_id)
            _, account = runner_account()
            command = [PYTHON, "-I", "-B", ADMIN_PATH.as_posix(), "_report", "--job-id", args.job_id]
            _, raw = as_runner(command, account, timeout=30, limit=MAX_REPORT)
            if text_failure(raw, "report.json"):
                raise ValueError("export_bytes_rejected")
            jobs.validate_result(parse_json(raw), job)
        else:
            require_root()
            if not jobs.HEX.fullmatch(args.job_id):
                raise ValueError("job_mismatch")
            verify_auto_manifest()
            job = jobs.load_job(args.job_id)
            account_config, account = runner_account()
            command = [account_config["python"], "-I", "-B", ADMIN_PATH.as_posix(), "_export", "--job-id", args.job_id]
            _, raw = as_runner(command, account, timeout=1800, limit=EXPORT_CONTRACTS[job["kind"]])
            parsed = validate_export(raw, job)
            if parsed.get("export_mode") == FAILURE_EXPORT_MODE:
                expected_runner = jobs.validate_result(jobs.read_result(job["job_id"]), job)
                if not _exact_json_equal(parsed["runner"], expected_runner):
                    raise ValueError("export_shape_invalid")
            if job["kind"] == BULK:
                expected_bulk = {
                    **export_bulk(job, jobs.job_directory(job["job_id"]), Path(account_config["data_root"])),
                    "schema_version": 1,
                    "job_id": job["job_id"],
                    "kind": BULK,
                }
                if not _exact_json_equal(parsed, expected_bulk):
                    raise ValueError("export_shape_invalid")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "reason": _safe_error_reason(error)}, separators=(",", ":")))
        return 2
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
