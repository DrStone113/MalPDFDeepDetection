"""Run an explicitly authorized static LAB cycle and save bounded evidence."""

import argparse
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
import hmac
import io
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from lab_contract import MAX_REPORT, parse_json, text_failure
import lab_jobs as jobs
from lab_offline_oneshot import bounded_command
from lab_oneshot_adm import (
    ADMIN_PATH,
    BULK,
    CYCLE_ID,
    EXPORT_CONTRACTS,
    MANIFEST_PATH,
    PINNED_LIB,
    RECEIPT_LIMIT,
    RUNNER_PATH,
    TERMINAL_STATUSES,
    json_bytes,
    utc_now,
    validate_export,
)
import lab_vmware as vmware
import labctl as ctl

VMX = vmware.VMX
STATE_ROOT = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "MalPDFDeepDetection/lab_auto_cycle"
)
EVIDENCE_ROOT = ctl.REPO / "reports/experiments/lab_runs"
CLEAN = "Clean LAB"
FINISHED = {"REVERTED", "COMPLETED_KEPT_STATE"}
BLOCKED = "BLOCKED_ISOLATION_OR_COMPLETION"
ARTIFACT_LIMITS = {
    "runner_receipt.json": MAX_REPORT,
    "oneshot_receipt.json": RECEIPT_LIMIT,
    "profile_export.json": max(EXPORT_CONTRACTS.values()),
    "locked_methodology.json": RECEIPT_LIMIT,
}
VMX_LIMIT = 1024**2
LOG_LIMIT = 64 * 1024**2
SHARE_KEYS = {f"isolation.tools.{name}.disable" for name in ("copy", "paste", "dnd", "hgfs")}
VMX_KEY = re.compile(r'\s*([\w.:-]+)\s*=\s*"([^"\r\n]*)"\s*', re.ASCII)
ADAPTER = re.compile(r"(ethernet[0-9]{1,2})\.present")
CONNECT_EVENT = b"VNET: MACVNetConnectToNetwork"
BOOT_MARKER = b"Powering on guestOS"
OFF_MARKER = b"Transitioned vmx/execState/val to poweredOff"
P9FS_DISABLED = b"P9FS_PowerOn: 9PFS server is not enabled."
SESSION_HEADER = re.compile(
    rb"(?m)^(\S+)\s+In\(05\)\s+vmx\s+Log for VMware [^\r\n]*\bpid=([0-9]+)\s+version=(\S+)\s+build=(build-[0-9]+)\b([^\r\n]*)\r?$"
)
LOG_TIMESTAMP = re.compile(
    rb"(?m)^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2}))\s+"
)
HOST_OFFSET_LINE = re.compile(rb"In\(05\)\s+vmx\s+Host offset from UTC is [+-][0-9]{2}:[0-9]{2}\.\r?$")
VTHREAD_INIT_LINE = re.compile(rb'In\(05\)\s+vmx\s+VTHREAD\s+[0-9]+\s+"vmx"\r?$')
SSH_OPTIONS = [
    *ctl.SSH_SECURITY,
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "IdentityAgent=none",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-p",
    "22",
    "-i",
    str(Path.home() / ".ssh/id_ed25519_remnux"),
]
PINNED_HELPERS = (
    ("lab_contract.py", Path("scripts/lab/lab_contract.py")),
    ("lab_readonly.py", Path("scripts/lab/lab_readonly.py")),
    ("lab_side.py", Path("scripts/lab/lab_side.py")),
    ("lab_jobs.py", Path("scripts/lab/lab_jobs.py")),
    ("lab_runner.py", Path("scripts/lab/lab_runner.py")),
    ("check_local.py", Path("scripts/lab/check_local.py")),
    ("lab_guard.py", Path("src/malpdf/static/lab_guard.py")),
)
AUTO_HELPERS = (
    (ADMIN_PATH.name, Path("scripts/lab/lab_oneshot_adm.py")),
    (RUNNER_PATH.name, Path("scripts/lab/lab_offline_oneshot.py")),
)
INSTALL_SCRIPT = (
    "import base64, hashlib, json, os, pathlib, stat, sys, tempfile\n"
    "pinned = pathlib.Path(sys.argv[1]); dest = pathlib.Path(sys.argv[2])\n"
    "expected = json.loads(sys.argv[3]); manifest_path = pathlib.Path(sys.argv[4])\n"
    "wire = sys.stdin.buffer.read(6 * 1024**2 + 1)\n"
    "if len(wire) > 6 * 1024**2: raise SystemExit('auto_helper_limit')\n"
    "files = json.loads(wire)\n"
    "if set(files) != {'lab_oneshot_adm.py', 'lab_offline_oneshot.py'}: raise SystemExit('auto_helper_names')\n"
    "for path in {pinned, dest.parent, manifest_path.parent, *pinned.parents, *dest.parents, *manifest_path.parents}:\n"
    "    info = path.lstat()\n"
    "    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:\n"
    "        raise SystemExit('unsafe_install_parent')\n"
    "for name, digest in expected.items():\n"
    "    path = pinned / name\n"
    "    info = path.lstat()\n"
    "    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 2 * 1024**2:\n"
    "        raise SystemExit('unsafe_pinned_helper')\n"
    "    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:\n"
    "        raise SystemExit('pinned_helper_mismatch:' + name)\n"
    "if dest.is_symlink(): raise SystemExit('unsafe_auto_helper_destination')\n"
    "dest.mkdir(mode=0o755, exist_ok=True)\n"
    "info = dest.lstat()\n"
    "if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:\n"
    "    raise SystemExit('unsafe_auto_helper_destination')\n"
    "os.chown(dest, 0, 0); os.chmod(dest, 0o755)\n"
    "hashes = {}\n"
    "sources = {name: base64.b64decode(value, validate=True) for name, value in files.items()}\n"
    "if any(not raw or len(raw) > 2 * 1024**2 for raw in sources.values()): raise SystemExit('auto_helper_limit')\n"
    "for name, raw in sources.items():\n"
    "    fd, tmp = tempfile.mkstemp(prefix='.auto-', dir=dest)\n"
    "    try:\n"
    "        with os.fdopen(fd, 'wb') as s:\n"
    "            os.fchmod(s.fileno(), 0o755); os.fchown(s.fileno(), 0, 0); s.write(raw); s.flush(); os.fsync(s.fileno())\n"
    "        os.replace(tmp, dest / name)\n"
    "    finally:\n"
    "        pathlib.Path(tmp).unlink(missing_ok=True)\n"
    "    hashes[name] = hashlib.sha256((dest / name).read_bytes()).hexdigest()\n"
    "manifest_bytes = (json.dumps({'schema_version': 1, 'pinned': expected, 'auto': hashes}, sort_keys=True) + '\\n').encode('ascii')\n"
    "fd, tmp = tempfile.mkstemp(prefix='.manifest-', dir=manifest_path.parent)\n"
    "try:\n"
    "    with os.fdopen(fd, 'wb') as s:\n"
    "        os.fchmod(s.fileno(), 0o600); os.fchown(s.fileno(), 0, 0); s.write(manifest_bytes); s.flush(); os.fsync(s.fileno())\n"
    "    os.replace(tmp, manifest_path)\n"
    "finally:\n"
    "    pathlib.Path(tmp).unlink(missing_ok=True)\n"
    "for directory in (dest, manifest_path.parent):\n"
    "    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)\n"
    "    try: os.fsync(fd)\n"
    "    finally: os.close(fd)\n"
    "print(json.dumps({'installed': True, 'hashes': hashes, 'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest()}, sort_keys=True))\n"
)
ADMIN_COMMAND = f"sudo -n /usr/bin/python3 -I -B {ADMIN_PATH.as_posix()}"


def safe_path(path):
    path = jobs.trusted_path(path)
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("unsafe_path")
    return path


def read(path, limit):
    return jobs.side.bounded_read(safe_path(path), limit)


def atomic_write(path, raw):
    path = safe_path(path)
    descriptor, filename = tempfile.mkstemp(prefix=".lab-auto-", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def cycle_lock(root):
    root = safe_path(root)
    root.mkdir(parents=True, exist_ok=True)
    with safe_path(root / "cycle.lock").open("a+b") as lock:
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError("cycle_lock_busy") from error
        yield


def checked_packet(state, *, adoption_source=False):
    job = state["job"]
    manifest = read(Path(state["source_manifest"]), 512 * 1024)
    archive = read(Path(state["source_archive"]), 40 * 1024**2)
    if jobs.sha(manifest) != job["manifest_sha256"] or jobs.sha(archive) != job["archive_sha256"]:
        raise ValueError("release_mismatch")
    metadata = parse_json(manifest)
    if metadata["commit"] != job["commit"] or metadata["archive_sha256"] != job["archive_sha256"]:
        raise ValueError("release_mismatch")
    source_job = None
    if adoption_source and job["kind"] == BULK:
        from lab_runner import BULK_RECOVERY_CONFIG

        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            entry = source.getmember(BULK_RECOVERY_CONFIG)
            if not entry.isfile() or entry.size > RECEIPT_LIMIT:
                raise ValueError("bulk_recovery_config_invalid")
            with source.extractfile(entry) as stream:
                config = parse_json(stream.read(RECEIPT_LIMIT + 1))
        source_job = config["source_job"]
        if not isinstance(source_job, str) or not jobs.HEX.fullmatch(source_job) or source_job == job["job_id"]:
            raise ValueError("bulk_recovery_config_invalid")
    parts = jobs.encoded(job), manifest, archive
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts), source_job


def require_new_cycle(active):
    if active is not None and active["stage"] not in FINISHED:
        raise ValueError("active_cycle_unfinished")


def authorize(
    proposal,
    *,
    authorize_job=None,
    auto_authorize_standing=False,
    recovery_mode=None,
    active=None,
):
    require_new_cycle(active)
    if (authorize_job is None) == (not auto_authorize_standing):
        raise ValueError("authorization_required")
    value = parse_json(read(proposal, 1024**2))
    job = jobs.validate_job(value["job"])
    job_id, kind = job["job_id"], job["kind"]
    if job["mode"] != "offline" or kind not in EXPORT_CONTRACTS:
        raise ValueError("job_mismatch")
    if authorize_job is not None and (not jobs.HEX.fullmatch(authorize_job) or authorize_job != job_id):
        raise ValueError("authorized_job_mismatch")
    mode = recovery_mode or ("keep_lab_state" if kind == BULK else "revert_pre_job")
    if mode not in ("keep_lab_state", "revert_pre_job"):
        raise ValueError("recovery_mode_invalid")
    if kind == BULK and mode != "keep_lab_state":
        raise ValueError("bulk_requires_keep_lab_state")
    cycle_id = uuid.uuid4().hex
    state = {
        "schema_version": 1,
        "cycle_id": cycle_id,
        "vmx_path": VMX.as_posix(),
        "job": job,
        "job_id": job_id,
        "kind": kind,
        "commit": job["commit"],
        "manifest_sha256": job["manifest_sha256"],
        "archive_sha256": job["archive_sha256"],
        "snapshot_name": f"pre-job-{job_id[:12]}-{cycle_id[:8]}",
        "source_archive": str(safe_path(Path(value["source_archive"]))),
        "source_manifest": str(safe_path(Path(value["source_manifest"]))),
        "recovery_mode": mode,
        "export_profile": kind,
        "standing_rule_authorization": auto_authorize_standing,
        "hostonly_adapter_id": None,
        "hostonly_vnet": None,
        "stage": "AUTHORIZED",
        "evidence_dir": None,
        "artifact_sha256s": {},
        "pre_boot_log_size": None,
        "offline_session_verified": False,
        "attempt": 1,
    }
    checked_packet(state)
    return state


def vmx_fields(lines):
    fields = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = VMX_KEY.fullmatch(line)
        if not match or match[1].casefold() in fields:
            raise ValueError("vmware_configuration_invalid")
        fields[match[1].casefold()] = match[2].casefold()
    return fields


def vmx_text(raw):
    if not isinstance(raw, bytes) or len(raw) > VMX_LIMIT or b"\0" in raw:
        raise ValueError("vmware_configuration_invalid")
    return raw.decode("utf-8-sig", "strict")


def adapters(fields):
    values = {match[1]: value for key, value in fields.items() if (match := ADAPTER.fullmatch(key))}
    if (
        not values
        or any(value not in ("true", "false") for value in values.values())
        or any(re.match(r"ethernet[0-9]+\.", key) and key.split(".")[0] not in values for key in fields)
    ):
        raise ValueError("vmware_adapters_unverified")
    present = {name for name, value in values.items() if value == "true"}
    if not present:
        raise ValueError("vmware_adapters_unverified")
    return present


def hostonly_adapter(fields):
    names = [
        name
        for name in adapters(fields)
        if fields.get(f"{name}.connectiontype") == "hostonly" and fields.get(f"{name}.vnet", "vmnet1") == "vmnet1"
    ]
    if len(names) != 1:
        raise ValueError("hostonly_adapter_unverified")
    return names[0]


def verify_shares(fields):
    if any(fields.get(key) != "true" for key in SHARE_KEYS) or any(
        key.startswith("sharedfolder") and key.endswith((".present", ".enabled")) and value != "false"
        for key, value in fields.items()
    ):
        raise ValueError("vmware_sharing_enabled")


def verify_offline_fields(fields):
    verify_shares(fields)
    if any(
        fields.get(f"{name}.{key}") != "false"
        for name in adapters(fields)
        for key in ("startconnected", "allowguestconnectioncontrol")
    ):
        raise ValueError("vmware_nic_connected_or_unverified")


def verify_vmx_offline_config(raw_bytes):
    verify_offline_fields(vmx_fields(vmx_text(raw_bytes).splitlines()))
    return True


def rewrite_vmx_network(raw_bytes, mode="offline"):
    text = vmx_text(raw_bytes)
    lines = text.splitlines()
    fields = vmx_fields(lines)
    if mode not in ("offline", "host-only"):
        raise ValueError("vmware_mode_invalid")
    hostonly = hostonly_adapter(fields) if mode == "host-only" else None
    changes = dict.fromkeys(sorted(SHARE_KEYS), "TRUE")
    for name in sorted(adapters(fields)):
        changes[f"{name}.allowguestconnectioncontrol"] = "FALSE"
        changes[f"{name}.startconnected"] = "TRUE" if name == hostonly else "FALSE"
    for index, line in enumerate(lines):
        key = line.split("=", 1)[0].strip().casefold()
        if key in changes:
            lines[index] = f'{key} = "{changes.pop(key)}"'
    lines.extend(f'{key} = "{value}"' for key, value in changes.items())
    newline = "\r\n" if "\r\n" in text else "\n"
    bom = b"\xef\xbb\xbf" if raw_bytes.startswith(b"\xef\xbb\xbf") else b""
    rewritten = bom + (newline.join(lines) + newline).encode("utf-8")
    if mode == "offline":
        verify_vmx_offline_config(rewritten)
    else:
        baseline_hostonly(rewritten)
    return rewritten


def baseline_hostonly(raw):
    value = vmware.configuration_isolation(raw)
    if value["network_configuration"] != "host_only_nat_disconnected" or any(
        value[key] != "disabled" for key in ("shared_folders", "copy_paste", "drag_drop")
    ):
        raise ValueError("host_only_nat_disconnected_required")
    fields = vmx_fields(vmx_text(raw).splitlines())
    verify_shares(fields)
    return hostonly_adapter(fields)


def _parse_log_lines(chunk, *, allow_vthread_init_flush=False):
    parsed = []
    seen_dict = False
    used_vthread_flush = False
    previous = None
    prev_line = b""
    for raw_line in chunk.splitlines():
        if not raw_line.strip():
            continue
        match = LOG_TIMESTAMP.match(raw_line)
        if match is None:
            raise ValueError("vmware_session_incomplete")
        stamp = datetime.fromisoformat(match[1].decode("ascii"))
        if stamp.tzinfo is None:
            raise ValueError("vmware_session_incomplete")
        if b" vmx DICT " in raw_line or raw_line.startswith(b"DICT "):
            if not seen_dict and parsed and stamp < parsed[0][0]:
                raise ValueError("vmware_session_incomplete")
            seen_dict = True
        if previous is not None:
            delta = (stamp - previous).total_seconds()
            if delta < 0.0:
                # Real VMware Workstation Log_Init emits VTHREAD "vmx" ~15-41ms earlier than Host offset before DICT.
                if not (
                    allow_vthread_init_flush
                    and not seen_dict
                    and not used_vthread_flush
                    and -1.0 <= delta
                    and HOST_OFFSET_LINE.search(prev_line) is not None
                    and VTHREAD_INIT_LINE.search(raw_line) is not None
                ):
                    raise ValueError("vmware_session_incomplete")
                used_vthread_flush = True
        previous = stamp
        prev_line = raw_line
        parsed.append((stamp, raw_line))
    if not parsed or len(SESSION_HEADER.findall(chunk)) != 1 or SESSION_HEADER.match(parsed[0][1]) is None:
        raise ValueError("vmware_session_incomplete")
    return parsed


def _stitch_rotated_vmware_log(rotated_raw, raw, *, previous_size=0, previous_digest=None):
    if previous_digest and jobs.sha(rotated_raw) == previous_digest:
        raise ValueError("vmware_session_incomplete")
    if previous_size and len(rotated_raw) >= previous_size and jobs.sha(rotated_raw[:previous_size]) == previous_digest:
        rotated_raw = rotated_raw[previous_size:]
    if CONNECT_EVENT in rotated_raw or CONNECT_EVENT in raw:
        raise ValueError("vmware_session_isolation_failed")
    if (
        len(rotated_raw) + len(raw) > LOG_LIMIT
        or BOOT_MARKER not in rotated_raw
        or OFF_MARKER in rotated_raw.partition(BOOT_MARKER)[2]
        or BOOT_MARKER in raw
        or b" vmx DICT " in raw
        or raw.startswith(b"DICT ")
        or b"\nDICT " in raw
    ):
        raise ValueError("vmware_session_incomplete")
    rotated_lines = _parse_log_lines(rotated_raw, allow_vthread_init_flush=True)
    active_lines = _parse_log_lines(raw, allow_vthread_init_flush=False)
    rotated_headers = SESSION_HEADER.findall(rotated_raw)
    active_headers = SESSION_HEADER.findall(raw)
    if rotated_headers[0][1:] != active_headers[0][1:]:
        raise ValueError("vmware_session_incomplete")
    delta = (active_lines[0][0] - rotated_lines[-1][0]).total_seconds()
    if not 0 <= delta <= 300:
        raise ValueError("vmware_session_incomplete")
    return rotated_raw + b"\n" + raw, [*rotated_lines, *active_lines]


def verify_vmware_offline_session_log(
    log_path, *, previous_size=0, previous_digest=None, expected_adapters=None, not_before=None, not_after=None
):
    raw = read(log_path, LOG_LIMIT)
    if previous_size and len(raw) == previous_size and jobs.sha(raw) == previous_digest:
        raise ValueError("stale_vmware_log")
    if previous_size and len(raw) >= previous_size and jobs.sha(raw[:previous_size]) == previous_digest:
        raw = raw[previous_size:]
        if raw.count(BOOT_MARKER) != 1 or CONNECT_EVENT in raw:
            raise ValueError("vmware_session_isolation_failed")
        session_lines = _parse_log_lines(raw, allow_vthread_init_flush=True)
    elif BOOT_MARKER in raw:
        if raw.count(BOOT_MARKER) != 1 or CONNECT_EVENT in raw:
            raise ValueError("vmware_session_isolation_failed")
        session_lines = _parse_log_lines(raw, allow_vthread_init_flush=True)
    else:
        rotated = log_path.with_name("vmware-0.log")
        if not os.path.lexists(rotated):
            raise ValueError("vmware_session_isolation_failed")
        raw, session_lines = _stitch_rotated_vmware_log(
            read(rotated, LOG_LIMIT),
            raw,
            previous_size=previous_size,
            previous_digest=previous_digest,
        )
    min_stamp = max_stamp = None
    if not_before is not None:
        min_stamp = datetime.fromisoformat(not_before) if isinstance(not_before, str) else not_before
        if min_stamp.tzinfo is None:
            raise ValueError("vmware_session_incomplete")
        if session_lines[0][0] < min_stamp - timedelta(seconds=5):
            raise ValueError("stale_vmware_log")
    if not_after is not None:
        max_stamp = datetime.fromisoformat(not_after) if isinstance(not_after, str) else not_after
        if max_stamp.tzinfo is None:
            raise ValueError("vmware_session_incomplete")
        if min_stamp is not None and max_stamp < min_stamp:
            raise ValueError("stale_vmware_log")
    if raw.count(BOOT_MARKER) != 1 or CONNECT_EVENT in raw:
        raise ValueError("vmware_session_isolation_failed")
    before, _, after = raw.partition(BOOT_MARKER)
    p9fs = after.find(P9FS_DISABLED)
    if p9fs < 0 or after.count(OFF_MARKER) != 1 or after.find(OFF_MARKER) <= p9fs:
        raise ValueError("vmware_session_incomplete")
    boot_indices = [idx for idx, (_, line) in enumerate(session_lines) if BOOT_MARKER in line]
    if len(boot_indices) != 1:
        raise ValueError("vmware_session_incomplete")
    boot_idx = boot_indices[0]
    p9fs_indices = [idx for idx, (_, line) in enumerate(session_lines) if idx > boot_idx and P9FS_DISABLED in line]
    off_indices = [idx for idx, (_, line) in enumerate(session_lines) if idx > boot_idx and OFF_MARKER in line]
    if not p9fs_indices or len(off_indices) != 1:
        raise ValueError("vmware_session_incomplete")
    p9fs_idx, off_idx = p9fs_indices[0], off_indices[0]
    if not (
        boot_idx < p9fs_idx < off_idx
        and session_lines[boot_idx][0]
        <= session_lines[p9fs_idx][0]
        <= session_lines[off_idx][0]
        <= session_lines[-1][0]
    ):
        raise ValueError("vmware_session_incomplete")
    if min_stamp is not None:
        if session_lines[boot_idx][0] < min_stamp - timedelta(seconds=1) or session_lines[off_idx][0] < min_stamp:
            raise ValueError("stale_vmware_log")
    if max_stamp is not None:
        upper = max_stamp + timedelta(seconds=5)
        if session_lines[0][0] > upper or session_lines[boot_idx][0] > upper or session_lines[off_idx][0] > upper:
            raise ValueError("stale_vmware_log")
    lines = []
    for line in before.splitlines():
        _, marker, setting = line.partition(b" vmx DICT ")
        if not marker and line.startswith(b"DICT "):
            setting = line.removeprefix(b"DICT ")
        key = setting.split(b"=", 1)[0].strip().lower()
        if (
            re.fullmatch(rb"ethernet[0-9]+\.(present|startconnected|allowguestconnectioncontrol)", key)
            or key in {name.encode("ascii") for name in SHARE_KEYS}
            or re.fullmatch(rb"sharedfolder[0-9]{1,3}\.(present|enabled)", key)
        ):
            lines.append(setting.decode("utf-8", "strict"))
    fields = vmx_fields(lines)
    verify_offline_fields(fields)
    if expected_adapters is not None and adapters(fields) != set(expected_adapters):
        raise ValueError("vmware_session_adapter_mismatch")
    return jobs.sha(raw)


def tcp_reachable():
    try:
        with socket.create_connection((vmware.EXPECTED_IP, 22), timeout=1):
            return True
    except OSError:
        return False


def ssh(command, *, timeout=30, limit=RECEIPT_LIMIT, payload=None):
    return bounded_command([ctl.SSH, *SSH_OPTIONS, ctl.ADMIN, command], limit, timeout=timeout, payload=payload)[1]


def remote_json(command, *, timeout=30, limit=RECEIPT_LIMIT, payload=None):
    raw = ssh(command, timeout=timeout, limit=limit, payload=payload)
    if text_failure(raw, "remote.json"):
        raise ValueError("remote_json_rejected")
    value = parse_json(raw.decode("utf-8", "strict"))
    if not isinstance(value, dict):
        raise ValueError("remote_json_rejected")
    return value, raw


def verify_oneshot_receipt(value, state):
    fields = {
        "schema_version",
        "cycle_id",
        "job_id",
        "kind",
        "commit",
        "outcome",
        "runner_status",
        "reason",
        "pty_confirmed",
        "pty_exit_code",
        "workers_remaining",
        "completed_utc",
    }
    if (
        set(value) != fields
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or any(value[name] != state[name] for name in ("cycle_id", "job_id", "kind", "commit"))
        or value["pty_confirmed"] is not True
        or type(value["pty_exit_code"]) is not int
        or value["pty_exit_code"] != 0
        or type(value["workers_remaining"]) is not int
        or value["workers_remaining"] != 0
        or value["reason"] is not None
        and value["reason"] not in jobs.REASONS
    ):
        raise ValueError("oneshot_receipt_invalid")
    completed = datetime.fromisoformat(value["completed_utc"])
    armed = datetime.fromisoformat(state["armed_utc"])
    if completed.tzinfo is None or armed.tzinfo is None or completed <= armed:
        raise ValueError("oneshot_receipt_stale")
    if value["outcome"] == "terminal_result" and value["runner_status"] in TERMINAL_STATUSES:
        return
    if (
        value["outcome"] == "bulk_paused_resumable"
        and state["kind"] == BULK
        and value["runner_status"] == "interrupted"
        and value["reason"] == "already_claimed"
    ):
        return
    raise ValueError("unexpected_incomplete")


class Cycle:
    def __init__(self, root, evidence_root=EVIDENCE_ROOT):
        self.path = root / "active_cycle.json"
        self.evidence_root = evidence_root
        self.state = parse_json(read(self.path, RECEIPT_LIMIT)) if os.path.lexists(self.path) else None

    def save(self, **changes):
        value = {**(self.state or {}), **changes}
        self.write_state(value)

    def write_state(self, value):
        atomic_write(self.path, json_bytes(value))
        self.state = value

    def require(self, stage):
        state = self.state
        if state is None or state["stage"] != stage:
            raise ValueError("cycle_transition_refused")
        validate_identity(state)
        return state

    def vmrun(self, action, *args, timeout=20, check=True):
        safe_path(VMX)
        binary = next((path for path in vmware.VMRUNS if path.is_file()), None)
        if sys.platform != "win32" or not VMX.is_file() or binary is None:
            raise ValueError("vmware_unavailable")
        return bounded_command([str(binary), "-T", "ws", action, *args], 65536, timeout=timeout, check=check)

    def running(self):
        _, raw = self.vmrun("list")
        lines = raw.decode("utf-8", "strict").splitlines()
        header = re.fullmatch(r"Total running VMs: ([0-9]+)", lines[0]) if lines else None
        if not header or int(header[1]) != len(lines) - 1:
            raise ValueError("vmware_list_invalid")
        return any(line.replace("\\", "/").casefold() == VMX.as_posix().casefold() for line in lines[1:])

    def locked(self):
        return os.path.lexists(VMX.with_name(VMX.name + ".lck"))

    def require_stopped(self):
        if self.running() or self.locked():
            raise ValueError("vmware_must_be_stopped_and_unlocked")

    def ensure_vm_stopped(self, *, hard_fallback=False):
        cancelled = None
        try:
            if self.running():
                self.vmrun("stop", str(VMX), "soft", timeout=120)
            self.wait_powered_off(90)
        except BaseException as error:
            if not hard_fallback:
                raise
            if not isinstance(error, Exception):
                cancelled = error
        else:
            return
        try:
            if self.running():
                self.vmrun("stop", str(VMX), "hard", timeout=60)
            self.wait_powered_off(90)
        except BaseException as hard_error:
            if cancelled is not None:
                raise cancelled from hard_error
            raise
        if cancelled is not None:
            raise cancelled

    def wait_powered_off(self, seconds):
        deadline = time.monotonic() + seconds
        while self.running() or self.locked():
            if time.monotonic() >= deadline:
                raise ValueError("vmware_shutdown_unverified")
            time.sleep(1)

    def snapshots(self):
        _, raw = self.vmrun("listSnapshots", str(VMX))
        lines = raw.decode("utf-8", "strict").splitlines()
        header = re.fullmatch(r"Total snapshots: ([0-9]+)", lines[0]) if lines else None
        if not header or int(header[1]) != len(lines) - 1 or lines[1:].count(CLEAN) != 1:
            raise ValueError("clean_snapshot_unverified")
        return lines[1:]

    def verify_connected(self, *, expect_disarmed=True):
        deadline = time.monotonic() + 120
        while True:
            try:
                status, _ = remote_json(f"{ADMIN_COMMAND} status", timeout=40)
                break
            except (OSError, subprocess.SubprocessError) as error:
                if time.monotonic() >= deadline:
                    raise ValueError("ssh_unavailable") from error
            except ValueError as error:
                if str(error) != "command_failed" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        firewall = status["firewall"]
        if (
            status["schema_version"] != 1
            or status["installed"] is not True
            or status["host_only_network"] is not True
            or status.get("firewall_pre_network") is not True
            or firewall["mode"] != "phase2_locked"
            or firewall["nat_up"] is not False
            or status["offline_boot_netplan"] is not True
        ):
            raise ValueError("hostonly_firewall_or_boot_unverified")
        if expect_disarmed and any(
            status[name] is not False for name in ("ticket_present", "unit_present", "wants_present")
        ):
            raise ValueError("oneshot_not_disarmed")
        return status

    def snapshot_create(self):
        state = self.require("AUTHORIZED")
        self.ensure_vm_stopped()
        adapter = baseline_hostonly(read(VMX, VMX_LIMIT))
        snapshots = self.snapshots()
        if state.get("snapshot_op") == "creating" and snapshots.count(state["snapshot_name"]) == 1:
            self.require_stopped()
            self.save(stage="SNAPSHOTTED", hostonly_adapter_id=adapter, hostonly_vnet="vmnet1", snapshot_op=None)
            return
        if state["snapshot_name"] in snapshots:
            raise ValueError("pre_job_snapshot_already_exists")
        self.save(snapshot_op="creating")
        self.require_stopped()
        self.vmrun("snapshot", str(VMX), state["snapshot_name"], timeout=300)
        self.require_stopped()
        if self.snapshots().count(state["snapshot_name"]) != 1:
            raise ValueError("pre_job_snapshot_unverified")
        self.save(stage="SNAPSHOTTED", hostonly_adapter_id=adapter, hostonly_vnet="vmnet1", snapshot_op=None)

    def check_adapter(self, raw, *, connected):
        if self.state["hostonly_vnet"] != "vmnet1" or self.state["hostonly_adapter_id"] != hostonly_adapter(
            vmx_fields(vmx_text(raw).splitlines())
        ):
            raise ValueError("recorded_hostonly_adapter_changed")
        if connected:
            baseline_hostonly(raw)

    def arm(self):
        state = self.state
        job_id = state["job_id"]
        ticket, _ = remote_json(
            f"{ADMIN_COMMAND} arm --job-id {job_id} --kind {state['kind']} --cycle-id {state['cycle_id']}", timeout=45
        )
        if (
            any(ticket[key] != state[key] for key in ("cycle_id", "job_id", "kind", "commit", "manifest_sha256"))
            or ticket["schema_version"] != 1
            or ticket["poweroff_on_finish"] is not True
            or datetime.fromisoformat(ticket["armed_utc"]).tzinfo is None
        ):
            raise ValueError("arm_ticket_mismatch")
        return ticket["armed_utc"]

    def provision_auto_helpers(self):
        import base64
        import json

        expected_pinned = {
            name: jobs.sha(read(ctl.REPO / rel, 2 * 1024**2).replace(b"\r\n", b"\n")) for name, rel in PINNED_HELPERS
        }
        payload_map = {}
        expected_auto = {}
        for name, rel in AUTO_HELPERS:
            raw = read(ctl.REPO / rel, 2 * 1024**2).replace(b"\r\n", b"\n")
            if text_failure(raw, rel.as_posix()):
                raise ValueError("helper_text_rejected")
            expected_auto[name] = jobs.sha(raw)
            payload_map[name] = base64.b64encode(raw).decode("ascii")
        deadline = time.monotonic() + 120
        script_b64 = base64.b64encode(INSTALL_SCRIPT.encode("ascii")).decode("ascii")
        pinned_b64 = base64.b64encode(json.dumps(expected_pinned, sort_keys=True).encode("ascii")).decode("ascii")
        cmd = (
            "sudo -n /usr/bin/python3 -I -B -c "
            f"\"import base64,sys; sys.argv=['-', '{PINNED_LIB.as_posix()}', '{ADMIN_PATH.parent.as_posix()}', "
            f"base64.b64decode('{pinned_b64}').decode('ascii'), '{MANIFEST_PATH.as_posix()}']; "
            f"exec(base64.b64decode('{script_b64}'))\""
        )
        wire = json.dumps(payload_map, sort_keys=True).encode("ascii")
        while True:
            try:
                reply, _ = remote_json(cmd, timeout=45, payload=wire)
                break
            except (OSError, subprocess.SubprocessError) as error:
                if time.monotonic() >= deadline:
                    raise ValueError("ssh_unavailable") from error
            except ValueError as error:
                if str(error) != "command_failed" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        if reply.get("installed") is not True or reply.get("hashes") != expected_auto:
            raise ValueError("auto_helper_provision_mismatch")
        return reply

    def live_status(self):
        info = {
            "vmx_exists": VMX.is_file(),
            "vm_locked": self.locked(),
            "vm_running": None,
            "snapshots": None,
            "vmx_isolation": None,
        }
        if info["vmx_exists"]:
            try:
                raw_vmx = read(VMX, VMX_LIMIT)
                info["vmx_isolation"] = vmware.configuration_isolation(raw_vmx)
            except (OSError, ValueError):
                pass
            try:
                info["vm_running"] = self.running()
                info["snapshots"] = self.snapshots()
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        return info

    def queue(self):
        state = self.require("SNAPSHOTTED")
        if self.snapshots().count(state["snapshot_name"]) != 1:
            raise ValueError("pre_job_snapshot_unverified")
        self.check_adapter(read(VMX, VMX_LIMIT), connected=True)
        source, adoption_source = checked_packet(state, adoption_source=True)
        if not self.running():
            self.require_stopped()
            self.vmrun("start", str(VMX), "nogui", timeout=90)
        self.provision_auto_helpers()
        status = self.verify_connected(expect_disarmed=False)
        job_id = state["job_id"]
        pending = status["pending_job_ids"]
        allowed = [[], [job_id]]
        if adoption_source is not None and not status["ticket_present"]:
            allowed.append([adoption_source])
        if pending not in allowed or (status["ticket_present"] and pending != [job_id]):
            raise ValueError("queue_not_exclusive")
        if not status["ticket_present"]:
            value, _ = remote_json(
                f"{ADMIN_COMMAND} receive --job-id {job_id}", timeout=250, limit=MAX_REPORT, payload=source
            )
            if jobs.validate_result(value, state["job"])["status"] != "queued":
                raise ValueError("job_not_queued")
        self.save(stage="QUEUED_ARMED", armed_utc=self.arm())

    def log_path(self):
        return VMX.with_name("vmware.log")

    def log_proof(self):
        state = self.state
        boot_started = state.get("boot_started_utc")
        boot_finished = state.get("boot_finished_utc")
        if (
            not isinstance(boot_started, str)
            or not boot_started
            or not isinstance(boot_finished, str)
            or not boot_finished
        ):
            raise ValueError("vmware_boot_timestamp_missing")
        return verify_vmware_offline_session_log(
            self.log_path(),
            previous_size=state["pre_boot_log_size"],
            previous_digest=state["pre_boot_log_sha256"],
            expected_adapters=state["offline_adapters"],
            not_before=boot_started,
            not_after=boot_finished,
        )

    def isolate_and_run(self):
        state = self.require("QUEUED_ARMED")
        try:
            self.save(stage=BLOCKED, blocked_reason="offline_boot_in_progress")
            if self.snapshots().count(state["snapshot_name"]) != 1:
                raise ValueError("pre_job_snapshot_unverified")
            self.ensure_vm_stopped()
            raw = read(VMX, VMX_LIMIT)
            self.check_adapter(raw, connected=True)
            rewritten = rewrite_vmx_network(raw, "offline")
            before = read(self.log_path(), LOG_LIMIT) if os.path.lexists(self.log_path()) else b""
            self.save(
                pre_boot_log_size=len(before),
                pre_boot_log_sha256=jobs.sha(before),
                offline_adapters=sorted(adapters(vmx_fields(vmx_text(rewritten).splitlines()))),
            )
            self.require_stopped()
            atomic_write(VMX, rewritten)
            verify_vmx_offline_config(read(VMX, VMX_LIMIT))
            self.save(boot_started_utc=utc_now())
            self.vmrun("start", str(VMX), "nogui", timeout=90)
            deadline = time.monotonic() + state["job"]["limits"]["wall_seconds"] + 300
            observed_running = False
            while self.running():
                observed_running = True
                code, address = self.vmrun("getGuestIPAddress", str(VMX), timeout=5, check=False)
                if (code == 0 and address.strip()) or tcp_reachable():
                    self.ensure_vm_stopped(hard_fallback=True)
                    raise ValueError("offline_guest_reachable")
                if time.monotonic() >= deadline:
                    self.ensure_vm_stopped(hard_fallback=True)
                    raise ValueError("offline_completion_timeout")
                time.sleep(2)
            if not observed_running:
                raise ValueError("offline_vm_never_observed_running")
            self.wait_powered_off(max(0, deadline - time.monotonic()))
            self.save(boot_finished_utc=utc_now())
            verify_vmx_offline_config(read(VMX, VMX_LIMIT))
            proof = self.log_proof()
            self.save(
                stage="OFFLINE_COMPLETED",
                offline_session_verified=True,
                offline_log_sha256=proof,
                blocked_reason=None,
            )
        except BaseException as error:
            cancel_error = None if isinstance(error, Exception) else error
            self.rollback_to_offline(
                str(error) or type(error).__name__,
                raise_save_error=False,
                original_cancel=cancel_error,
            )
            raise

    def rollback_to_offline(self, reason, *, raise_save_error=True, original_cancel=None):
        save_error = None
        cancel_error = original_cancel
        try:
            self.save(stage=BLOCKED, blocked_reason=reason)
        except BaseException as error:
            if isinstance(error, Exception):
                save_error = error
            elif cancel_error is None:
                cancel_error = error
        try:
            try:
                self.ensure_vm_stopped(hard_fallback=True)
            except BaseException as stop_error:
                if isinstance(stop_error, Exception):
                    raise
                if cancel_error is None:
                    cancel_error = stop_error
                if stop_error.__cause__ is not None:
                    raise stop_error.__cause__
            self.require_stopped()
            raw = read(VMX, VMX_LIMIT)
            atomic_write(VMX, rewrite_vmx_network(raw, "offline"))
            verify_vmx_offline_config(read(VMX, VMX_LIMIT))
        except BaseException as rollback_error:
            detail = str(rollback_error) or type(rollback_error).__name__
            try:
                self.save(stage=BLOCKED, blocked_reason=f"{reason}; rollback_failed:{detail}")
            except Exception:
                pass
            if cancel_error is not None and cancel_error is not rollback_error:
                raise cancel_error from rollback_error
            raise
        if cancel_error is not None:
            try:
                self.save(stage=BLOCKED, blocked_reason=reason)
            except Exception:
                pass
            raise cancel_error from None
        if save_error is not None:
            try:
                self.save(stage=BLOCKED, blocked_reason=reason)
            except Exception:
                if raise_save_error:
                    raise save_error from None

    def restore_ssh(self):
        state = self.require("OFFLINE_COMPLETED")
        try:
            self.save(stage=BLOCKED, blocked_reason="ssh_restore_in_progress")
            if state["offline_session_verified"] is not True or self.log_proof() != state["offline_log_sha256"]:
                raise ValueError("offline_session_proof_changed")
            if self.snapshots().count(state["snapshot_name"]) != 1:
                raise ValueError("pre_job_snapshot_unverified")
            self.require_stopped()
            raw = read(VMX, VMX_LIMIT)
            self.check_adapter(raw, connected=False)
            verify_vmx_offline_config(raw)
            atomic_write(VMX, rewrite_vmx_network(raw, "host-only"))
            self.vmrun("start", str(VMX), "nogui", timeout=90)
            self.verify_connected()
            receipt, receipt_raw = remote_json(f"{ADMIN_COMMAND} read-receipt --job-id {state['job_id']}")
            verify_oneshot_receipt(receipt, state)
            if jobs.sha(receipt_raw) == state.get("previous_receipt_sha256"):
                raise ValueError("oneshot_receipt_stale")
            self.save(
                stage="SSH_RESTORED",
                blocked_reason=None,
                verified_receipt_sha256=jobs.sha(receipt_raw),
            )
        except BaseException as error:
            cancel_error = None if isinstance(error, Exception) else error
            self.rollback_to_offline(
                str(error) or type(error).__name__,
                raise_save_error=False,
                original_cancel=cancel_error,
            )
            raise

    def verify_evidence(self):
        state = self.state
        folder = safe_path(Path(state["evidence_dir"]))
        if (
            folder.parent != safe_path(self.evidence_root)
            or not re.fullmatch(rf"run_[0-9]{{8}}T[0-9]{{12}}Z_{state['commit'][:12]}", folder.name)
            or set(state["artifact_sha256s"]) != set(ARTIFACT_LIMITS)
        ):
            raise ValueError("evidence_manifest_invalid")
        for name, limit in ARTIFACT_LIMITS.items():
            expected = state["artifact_sha256s"][name]
            try:
                actual = jobs.sha(read(folder / name, limit))
            except OSError as error:
                raise ValueError("evidence_missing_or_unreadable") from error
            if not jobs.HEX.fullmatch(expected) or not hmac.compare_digest(actual, expected):
                raise ValueError("evidence_hash_mismatch")
        return folder

    def export_and_save(self):
        state = self.require("SSH_RESTORED")
        job, job_id = state["job"], state["job_id"]
        try:
            if state["offline_session_verified"] is not True:
                raise ValueError("offline_session_unverified")
            self.verify_connected()
            receipt, receipt_raw = remote_json(f"{ADMIN_COMMAND} read-receipt --job-id {job_id}")
            verify_oneshot_receipt(receipt, state)
            if jobs.sha(receipt_raw) == state.get("previous_receipt_sha256"):
                raise ValueError("oneshot_receipt_stale")
            if state.get("verified_receipt_sha256") and jobs.sha(receipt_raw) != state["verified_receipt_sha256"]:
                raise ValueError("oneshot_receipt_changed")
            stage = "BULK_PAUSED_SAVED" if receipt["outcome"] == "bulk_paused_resumable" else "EVIDENCE_SAVED"
            if state["evidence_dir"] and os.path.lexists(state["evidence_dir"]):
                self.verify_evidence()
                if state["artifact_sha256s"]["oneshot_receipt.json"] != jobs.sha(receipt_raw):
                    raise ValueError("oneshot_receipt_changed")
                self.save(stage=stage)
                return
            runner, runner_raw = remote_json(f"{ADMIN_COMMAND} report --job-id {job_id}", limit=MAX_REPORT)
            jobs.validate_result(runner, job)
            if runner["status"] != receipt["runner_status"] or runner["reason"] != receipt["reason"]:
                raise ValueError("runner_receipt_mismatch")
            raw = ssh(f"{ADMIN_COMMAND} export --job-id {job_id}", timeout=1850, limit=EXPORT_CONTRACTS[state["kind"]])
            exported = validate_export(raw, job)
            if exported.get("export_mode") == "terminal_failure_receipt_only":
                if (
                    receipt["outcome"] != "terminal_result"
                    or runner["status"] not in ("failed", "blocked", "interrupted")
                    or exported["runner"] != runner
                ):
                    raise ValueError("export_runner_mismatch")
            elif "runner" in exported and exported["runner"] != runner:
                raise ValueError("export_runner_mismatch")
            root = safe_path(self.evidence_root)
            root.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            folder = root / f"run_{stamp}_{job['commit'][:12]}"
            payloads = {
                "runner_receipt.json": runner_raw,
                "oneshot_receipt.json": receipt_raw,
                "profile_export.json": raw,
            }
            artifact_hashes = {name: jobs.sha(value) for name, value in payloads.items()}
            payloads["locked_methodology.json"] = json_bytes(
                {
                    "schema_version": 1,
                    "job": job,
                    "cycle_id": state["cycle_id"],
                    "attempt": state["attempt"],
                    "export_profile": state["export_profile"],
                    "recovery_mode": state["recovery_mode"],
                    "standing_rule_authorization": state["standing_rule_authorization"],
                    "snapshot_name": state["snapshot_name"],
                    "offline_log_sha256": state["offline_log_sha256"],
                    "hostonly_adapter_id": state["hostonly_adapter_id"],
                    "hostonly_vnet": state["hostonly_vnet"],
                    "artifact_sha256s": artifact_hashes,
                }
            )
            hashes = {name: jobs.sha(value) for name, value in payloads.items()}
            with tempfile.TemporaryDirectory(prefix=".lab-evidence-", dir=root) as staging:
                destination = Path(staging) / "evidence"
                destination.mkdir()
                for name, payload in payloads.items():
                    atomic_write(destination / name, payload)
                if os.path.lexists(folder):
                    raise ValueError("evidence_directory_exists")
                destination.rename(folder)
            self.save(evidence_dir=str(folder), artifact_sha256s=hashes)
            self.verify_evidence()
            self.save(stage=stage)
        except BaseException as error:
            cancel_error = None if isinstance(error, Exception) else error
            self.rollback_to_offline(
                str(error) or type(error).__name__,
                raise_save_error=False,
                original_cancel=cancel_error,
            )
            raise

    def revert_snapshot(self):
        state = self.require("EVIDENCE_SAVED")
        if state["recovery_mode"] != "revert_pre_job":
            raise ValueError("revert_not_authorized")
        snapshot = state["snapshot_name"]
        self.verify_evidence()
        self.ensure_vm_stopped()
        self.require_stopped()
        if state.get("snapshot_op") == "deleting" and snapshot not in self.snapshots():
            self.check_adapter(read(VMX, VMX_LIMIT), connected=True)
            self.verify_evidence()
            self.save(stage="REVERTED", snapshot_op=None)
            return
        if self.snapshots().count(snapshot) != 1:
            raise ValueError("pre_job_snapshot_unverified")
        self.verify_evidence()
        self.vmrun("revertToSnapshot", str(VMX), snapshot, timeout=300)
        self.wait_powered_off(90)
        self.require_stopped()
        self.check_adapter(read(VMX, VMX_LIMIT), connected=True)
        self.verify_evidence()
        self.save(snapshot_op="deleting")
        self.vmrun("deleteSnapshot", str(VMX), snapshot, timeout=300)
        if snapshot in self.snapshots():
            raise ValueError("pre_job_snapshot_delete_unverified")
        self.save(stage="REVERTED", snapshot_op=None)

    def finish_kept(self):
        state = self.require("EVIDENCE_SAVED")
        if state["recovery_mode"] != "keep_lab_state":
            raise ValueError("keep_state_not_authorized")
        self.verify_evidence()
        self.save(stage="COMPLETED_KEPT_STATE")

    def resume_bulk(self, cycle_id=None):
        state = self.require("BULK_PAUSED_SAVED")
        if cycle_id is not None and (not CYCLE_ID.fullmatch(cycle_id) or cycle_id != state["cycle_id"]):
            raise ValueError("cycle_mismatch")
        if state["kind"] != BULK or state["recovery_mode"] != "keep_lab_state":
            raise ValueError("bulk_resume_not_authorized")
        folder = self.verify_evidence()
        self.check_adapter(read(VMX, VMX_LIMIT), connected=True)
        if self.snapshots().count(state["snapshot_name"]) != 1:
            raise ValueError("pre_job_snapshot_unverified")
        self.provision_auto_helpers()
        status = self.verify_connected(expect_disarmed=False)
        if status["pending_job_ids"] != [state["job_id"]]:
            raise ValueError("queue_not_exclusive")
        receipt, raw = remote_json(f"{ADMIN_COMMAND} read-receipt --job-id {state['job_id']}")
        verify_oneshot_receipt(receipt, state)
        if raw != read(folder / "oneshot_receipt.json", RECEIPT_LIMIT):
            raise ValueError("oneshot_receipt_changed")
        armed = self.arm()
        self.save(
            stage="QUEUED_ARMED",
            armed_utc=armed,
            attempt=state["attempt"] + 1,
            offline_session_verified=False,
            evidence_dir=None,
            artifact_sha256s={},
            verified_receipt_sha256=None,
            previous_receipt_sha256=jobs.sha(raw),
        )
        self.run_cycle()

    def reset_clean_lab(self, abandon=None):
        state = self.state
        if state is not None:
            validate_identity(state)
            if state["stage"] not in FINISHED and abandon != state["cycle_id"]:
                raise ValueError("exact_abandon_active_cycle_required")
        self.snapshots()
        self.ensure_vm_stopped()
        self.require_stopped()
        self.vmrun("revertToSnapshot", str(VMX), CLEAN, timeout=300)
        self.wait_powered_off(90)
        self.snapshots()
        if state is not None and state["stage"] not in FINISHED:
            self.save(stage="REVERTED", reset_to_clean=True)

    def run_cycle(self):
        transitions = {
            "AUTHORIZED": self.snapshot_create,
            "SNAPSHOTTED": self.queue,
            "QUEUED_ARMED": self.isolate_and_run,
            "OFFLINE_COMPLETED": self.restore_ssh,
            "SSH_RESTORED": self.export_and_save,
        }
        while self.state is not None and self.state["stage"] in transitions:
            transitions[self.state["stage"]]()
        if self.state is None or self.state["stage"] == BLOCKED:
            raise ValueError("cycle_no_runnable_transition")
        if self.state["stage"] == "EVIDENCE_SAVED":
            if self.state["recovery_mode"] == "revert_pre_job":
                self.revert_snapshot()
            else:
                self.finish_kept()


def validate_identity(state):
    job = jobs.validate_job(state["job"])
    if (
        not CYCLE_ID.fullmatch(state["cycle_id"])
        or state["vmx_path"] != VMX.as_posix()
        or job["kind"] not in EXPORT_CONTRACTS
        or state["export_profile"] != job["kind"]
        or any(state[key] != job[key] for key in ("job_id", "kind", "commit", "manifest_sha256", "archive_sha256"))
        or state["snapshot_name"] != f"pre-job-{job['job_id'][:12]}-{state['cycle_id'][:8]}"
    ):
        raise ValueError("cycle_identity_invalid")


def authorization_flags(parser):
    parser.add_argument("--proposal", type=Path)
    parser.add_argument("--kind", choices=sorted(EXPORT_CONTRACTS))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--authorize-job")
    group.add_argument("--auto-authorize-standing", action="store_true")
    parser.add_argument("--recovery-mode", choices=("keep_lab_state", "revert_pre_job"))


def authorize_args(args, active):
    require_new_cycle(active)
    if not (args.authorize_job or args.auto_authorize_standing):
        raise ValueError("authorization_required")
    proposal = args.proposal
    if proposal is None:
        from offline_prepare import prepare

        with redirect_stdout(io.StringIO()):
            proposal = Path(prepare(args.kind or "pdf-static")["plan"])
    state = authorize(
        proposal,
        authorize_job=args.authorize_job,
        auto_authorize_standing=args.auto_authorize_standing,
        recovery_mode=args.recovery_mode,
        active=active,
    )
    if args.kind is not None and args.kind != state["kind"]:
        raise ValueError("job_mismatch")
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in (
        "status",
        "provision",
        "snapshot-create",
        "queue",
        "isolate-and-run",
        "restore-ssh",
        "export-and-save",
        "revert-snapshot",
    ):
        subparsers.add_parser(name)
    subparsers.add_parser("resume-bulk").add_argument("--cycle-id")
    for name in ("authorize", "run-cycle"):
        authorization_flags(subparsers.add_parser(name))
    subparsers.add_parser("reset-clean-lab").add_argument("--abandon-active-cycle")
    args = parser.parse_args(argv)
    try:
        with cycle_lock(STATE_ROOT):
            cycle = Cycle(STATE_ROOT)
            provision = None
            if args.command == "authorize":
                cycle.write_state(authorize_args(args, cycle.state))
            elif args.command == "run-cycle":
                new = cycle.state is None or cycle.state["stage"] in FINISHED
                if new or any(
                    (
                        args.proposal,
                        args.kind,
                        args.authorize_job,
                        args.auto_authorize_standing,
                        args.recovery_mode,
                    )
                ):
                    cycle.write_state(authorize_args(args, cycle.state))
                cycle.run_cycle()
            elif args.command == "provision":
                provision = cycle.provision_auto_helpers()
            elif args.command == "resume-bulk":
                cycle.resume_bulk(args.cycle_id)
            elif args.command == "reset-clean-lab":
                cycle.reset_clean_lab(args.abandon_active_cycle)
            elif args.command != "status":
                getattr(cycle, args.command.replace("-", "_"))()
            result = {"schema_version": 1, "active_cycle": cycle.state}
            if args.command == "status":
                result["vmware"] = cycle.live_status()
            if args.command == "provision":
                result["provision"] = provision
            raw = json_bytes(result)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        raw = json_bytes({"status": "blocked", "reason": str(error)})
        sys.stdout.buffer.write(raw)
        return 2
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
