from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
PROD_DIR = REPO_ROOT / "production"
SUPERVISOR_MJS = PROD_DIR / "9router_space" / "hf_supervisor.mjs"
SECRETS_CACHE_PATH = REPO_ROOT / "artifacts" / "tmp" / "9router_space_bootstrap.json"
LOCAL_ADMIN_ROOT = REPO_ROOT / "artifacts" / "tmp" / "9router_local_staging"

OWNER = "DrStone113"
STATE_DATASET_NAME = "malpdf-9router-state"
STATE_DATASET_REPO = f"{OWNER}/{STATE_DATASET_NAME}"
MALPDF_SPACE_REPO = f"{OWNER}/malpdfdetection"
MALPDF_PUBLIC_ORIGIN = "https://drstone113-malpdfdetection.hf.space"
DEFAULT_COMBO_NAME = "malpdf-default"
HF_API_BASE = "https://huggingface.co"
LOCAL_ADMIN_PORT = 20130


def _resolve_hf_token() -> str:
    env_tok = os.environ.get("HF_TOKEN", "").strip()
    if env_tok:
        return env_tok
    proc = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=huggingface.co\n\n",
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("password=") and line.split("=", 1)[1].strip():
            return line.split("=", 1)[1].strip()
    raise RuntimeError("hf_token_unavailable")


def _hf_request(
    method: str,
    path_or_url: str,
    token: str | None = None,
    *,
    json_body: Any = None,
    raw_body: bytes | None = None,
    content_type: str = "application/json",
    timeout: float = 30.0,
    bypass_proxy: bool = False,
) -> tuple[int, bytes]:
    url = path_or_url if path_or_url.startswith("http") else f"{HF_API_BASE}{path_or_url}"
    headers = {"User-Agent": "MalPDFDeepDetection-Deploy/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = raw_body
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = content_type
    elif raw_body is not None:
        headers["Content-Type"] = content_type
    req = Request(url, data=data, method=method, headers=headers)
    opener = build_opener(ProxyHandler({})) if bypass_proxy else None
    try:
        resp_ctx = opener.open(req, timeout=timeout) if opener is not None else urlopen(req, timeout=timeout)
        with resp_ctx as resp:
            return resp.status, resp.read()
    except HTTPError as err:
        body = err.read()
        err.close()
        return err.code, body
    except (URLError, TimeoutError, OSError):
        return 0, b""


def _write_private_json_atomic(target: Path, payload: dict[str, str]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = target.parent / f".{target.name}.{os.getpid()}.tmp"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp_path, target)


def _load_or_create_bootstrap_secrets() -> dict[str, str]:
    existing: dict[str, str] = {}
    if SECRETS_CACHE_PATH.is_file():
        existing = json.loads(SECRETS_CACHE_PATH.read_text(encoding="utf-8"))
    generated = {
        "INITIAL_PASSWORD": existing.get("INITIAL_PASSWORD") or secrets.token_urlsafe(24),
        "JWT_SECRET": existing.get("JWT_SECRET") or secrets.token_hex(32),
        "API_KEY_SECRET": existing.get("API_KEY_SECRET") or secrets.token_hex(32),
        "MACHINE_ID_SALT": existing.get("MACHINE_ID_SALT") or secrets.token_hex(24),
        "STATE_ENCRYPTION_KEY": existing.get("STATE_ENCRYPTION_KEY") or secrets.token_hex(32),
        "BOOTSTRAP_API_KEY": existing.get("BOOTSTRAP_API_KEY") or ("9r_" + secrets.token_urlsafe(32)),
        "BOOTSTRAP_COMBO_NAME": existing.get("BOOTSTRAP_COMBO_NAME") or DEFAULT_COMBO_NAME,
    }
    _write_private_json_atomic(SECRETS_CACHE_PATH, generated)
    return generated


def _ensure_private_dataset(token: str) -> dict[str, Any]:
    status, body = _hf_request(
        "POST",
        "/api/repos/create",
        token,
        json_body={"type": "dataset", "name": STATE_DATASET_NAME, "private": True},
    )
    if status not in {200, 201, 409}:
        raise RuntimeError(f"hf_dataset_create_failed:HTTP_{status}:{body[:200]!r}")
    meta_code, meta_raw = _hf_request("GET", f"/api/datasets/{STATE_DATASET_REPO}", token)
    if meta_code != 200:
        raise RuntimeError(f"state_dataset_metadata_failed:HTTP_{meta_code}")
    meta = json.loads(meta_raw.decode("utf-8"))
    if meta.get("private") is not True:
        raise RuntimeError("state_dataset_must_be_private")
    return meta


def _set_space_secret(token: str, key: str, value: str) -> None:
    status, _ = _hf_request(
        "POST",
        f"/api/spaces/{MALPDF_SPACE_REPO}/secrets",
        token,
        json_body={"key": key, "value": value},
    )
    if status not in {200, 201}:
        raise RuntimeError(f"hf_set_secret_failed:{key}:HTTP_{status}")


def _wait_for_space_running(token: str, timeout_sec: int = 420) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_sec
    last_stage = "UNKNOWN"
    while time.monotonic() < deadline:
        status, raw = _hf_request("GET", f"/api/spaces/{MALPDF_SPACE_REPO}/runtime", token)
        if status == 200:
            info = json.loads(raw.decode("utf-8"))
            last_stage = str(info.get("stage") or "UNKNOWN")
            if last_stage == "RUNNING":
                return info
            if "ERROR" in last_stage or "STOPPED" in last_stage:
                raise RuntimeError(f"space_runtime_failed:{last_stage}")
        time.sleep(5)
    raise TimeoutError(f"space_runtime_timeout:last_stage={last_stage}")


def _decrypt_persisted_connections_count(hf_token: str, commit_sha: str, state_encryption_key: str) -> int:
    code, enc_bytes = _hf_request(
        "GET",
        f"/datasets/{STATE_DATASET_REPO}/resolve/{commit_sha}/state.enc",
        hf_token,
        timeout=30.0,
    )
    if code != 200:
        raise RuntimeError(f"state_snapshot_download_failed:HTTP_{code}")

    supervisor_uri = SUPERVISOR_MJS.resolve().as_uri()
    node_script = (
        f"import {{ decryptStateBundle }} from {json.dumps(supervisor_uri)};"
        "import fs from 'node:fs';"
        "const enc = fs.readFileSync(0);"
        "const out = decryptStateBundle(enc, process.env.STATE_KEY);"
        "if (!out.files['db/data.sqlite']) process.exit(2);"
        "process.stdout.write(Buffer.from(out.files['db/data.sqlite'], 'base64'));"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", node_script],
        input=enc_bytes,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "STATE_KEY": state_encryption_key,
        },
        capture_output=True,
        check=True,
        timeout=20,
    )
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(proc.stdout)
        row = conn.execute("SELECT COUNT(*) FROM providerConnections WHERE isActive = 1").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _approved_remote_state_commit(hf_token: str, state_encryption_key: str) -> tuple[str | None, int]:
    meta = _ensure_private_dataset(hf_token)
    siblings = meta.get("siblings") or []
    has_state = any(isinstance(item, dict) and item.get("rfilename") == "state.enc" for item in siblings)
    if not has_state:
        return None, 0
    head_sha = str(meta.get("sha") or "")
    if len(head_sha) != 40:
        raise RuntimeError("invalid_dataset_head_sha")
    count = _decrypt_persisted_connections_count(hf_token, head_sha, state_encryption_key)
    return head_sha, count


def _import_connections_into_sqlite(sqlite_db_path: Path, source_path: Path) -> int:
    rows: list[tuple[Any, ...]] = []
    if source_path.suffix.lower() in {".sqlite", ".db", ".sqlite3"}:
        src_conn = sqlite3.connect(f"file:{source_path.resolve().as_posix()}?mode=ro", uri=True)
        try:
            rows = src_conn.execute(
                "SELECT id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt "
                "FROM providerConnections"
            ).fetchall()
        finally:
            src_conn.close()
    else:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
        conns = payload.get("providerConnections") if isinstance(payload, dict) else None
        if not isinstance(conns, list):
            raise ValueError("import_source_missing_providerConnections")
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for item in conns:
            if not isinstance(item, dict) or not item.get("id") or not item.get("provider"):
                continue
            rest = {
                k: v
                for k, v in item.items()
                if k
                not in {"id", "provider", "authType", "name", "email", "priority", "isActive", "createdAt", "updatedAt"}
            }
            rows.append(
                (
                    str(item["id"]),
                    str(item["provider"]),
                    str(item.get("authType") or "oauth"),
                    item.get("name"),
                    item.get("email"),
                    item.get("priority"),
                    0 if item.get("isActive") is False else 1,
                    json.dumps(rest, ensure_ascii=False),
                    str(item.get("createdAt") or now),
                    str(item.get("updatedAt") or now),
                )
            )
    if not rows:
        raise ValueError("no_provider_connections_found_in_import")

    dst_conn = sqlite3.connect(sqlite_db_path, timeout=10.0)
    try:
        with dst_conn:
            for row in rows:
                dst_conn.execute(
                    "INSERT OR REPLACE INTO providerConnections"
                    "(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    row,
                )
    finally:
        dst_conn.close()
    return len(rows)


def _port_closed(port: int, timeout_sec: float = 5.0) -> bool:
    import socket

    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return True
        time.sleep(0.2)
    return False


def stage_local_onboarding(*, import_db: Path | None = None, interactive_wait_sec: int = 300) -> dict[str, Any]:
    hf_token = _resolve_hf_token()
    _ensure_private_dataset(hf_token)
    confirmed_disabled = False
    for _ in range(6):
        h_code, h_raw = _hf_request("GET", f"{MALPDF_PUBLIC_ORIGIN}/api/health", timeout=10.0)
        if h_code == 200:
            h_doc = json.loads(h_raw.decode("utf-8"))
            sidecar_info = h_doc.get("router_sidecar")
            if sidecar_info is None or sidecar_info.get("enabled") is False:
                confirmed_disabled = True
                break
            raise RuntimeError("hosted_sidecar_currently_enabled_stop_it_before_local_onboarding")
        time.sleep(3.0)
    if not confirmed_disabled:
        raise RuntimeError("hosted_sidecar_state_unconfirmed_cannot_start_local_onboarding")

    if str(PROD_DIR) not in sys.path:
        sys.path.insert(0, str(PROD_DIR))
    from sidecar_9router import ensure_node_binary, ensure_router_package

    bootstrap = _load_or_create_bootstrap_secrets()
    runtime_dir = LOCAL_ADMIN_ROOT / "runtime"
    data_dir = LOCAL_ADMIN_ROOT / "data"
    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    node_bin = ensure_node_binary(runtime_dir)
    app_dir = ensure_router_package(runtime_dir)
    env = {
        **os.environ,
        **bootstrap,
        "PORT": str(LOCAL_ADMIN_PORT),
        "INTERNAL_PORT": str(LOCAL_ADMIN_PORT + 1),
        "HOSTNAME": "127.0.0.1",
        "DATA_DIR": str(data_dir),
        "SERVER_SCRIPT": str(app_dir / "custom-server.js"),
        "SERVER_CWD": str(app_dir),
        "HF_STATE_REPO": STATE_DATASET_REPO,
        "HF_SYNC_TOKEN": hf_token,
        "AUTH_COOKIE_SECURE": "false",
    }
    proc = subprocess.Popen([node_bin, str(SUPERVISOR_MJS)], env=env)
    base_url = f"http://127.0.0.1:{LOCAL_ADMIN_PORT}"
    api_key = bootstrap["BOOTSTRAP_API_KEY"]
    try:
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("local_staging_router_exited_early")
            code, raw = _hf_request("GET", f"{base_url}/_supervisor/status", api_key, timeout=5.0, bypass_proxy=True)
            if code == 200 and json.loads(raw.decode("utf-8")).get("ok") is True:
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("local_staging_router_boot_timeout")

        sqlite_file = data_dir / "db" / "data.sqlite"
        if import_db is not None:
            _import_connections_into_sqlite(sqlite_file, import_db)
        else:
            print(
                f"Local 9Router staging UI ready at {base_url} "
                f"(initial password in {SECRETS_CACHE_PATH}). Connect accounts now...",
                flush=True,
            )
            wait_deadline = time.monotonic() + interactive_wait_sec
            while time.monotonic() < wait_deadline:
                conn = sqlite3.connect(sqlite_file, timeout=5.0)
                try:
                    cnt = conn.execute("SELECT COUNT(*) FROM providerConnections WHERE isActive = 1").fetchone()[0]
                finally:
                    conn.close()
                if cnt >= 1:
                    break
                time.sleep(2.0)
            else:
                raise TimeoutError("no_active_provider_connections_added_within_timeout")

        comp_code, comp_raw = _hf_request(
            "POST",
            f"{base_url}/v1/chat/completions",
            api_key,
            json_body={
                "model": bootstrap["BOOTSTRAP_COMBO_NAME"],
                "messages": [{"role": "user", "content": "Trả lời ngắn gọn: OK"}],
                "max_tokens": 128,
                "reasoning_effort": "low",
            },
            timeout=40.0,
            bypass_proxy=True,
        )
        if comp_code != 200:
            raise RuntimeError(f"local_combo_completion_failed:HTTP_{comp_code}")
        comp_doc = json.loads(comp_raw.decode("utf-8"))
        choices = comp_doc.get("choices")
        first = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
        if first.get("finish_reason") not in {None, "stop"}:
            raise RuntimeError(f"local_combo_non_stop_finish:{first.get('finish_reason')!r}")
        content = (first.get("message") or {}).get("content") if isinstance(first.get("message"), dict) else None
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("local_combo_empty_completion")

        s_code, s_raw = _hf_request(
            "POST", f"{base_url}/_supervisor/sync", api_key, json_body={}, timeout=30.0, bypass_proxy=True
        )
        if s_code != 200:
            raise RuntimeError(f"local_sync_failed:HTTP_{s_code}")
        s_doc = json.loads(s_raw.decode("utf-8"))
        if not (s_doc.get("ok") is True and s_doc.get("inSync") is True and s_doc.get("parentCommit")):
            raise RuntimeError(f"local_sync_not_confirmed:{s_doc}")
        synced_commit = str(s_doc["parentCommit"])
        persisted_cnt = _decrypt_persisted_connections_count(hf_token, synced_commit, bootstrap["STATE_ENCRYPTION_KEY"])
        if persisted_cnt < 1:
            raise RuntimeError("persisted_snapshot_missing_active_connections")
    finally:
        if proc.poll() is None:
            _hf_request("POST", f"{base_url}/_supervisor/stop", api_key, json_body={}, timeout=5.0, bypass_proxy=True)
            try:
                proc.wait(timeout=9.0)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                        check=False,
                        timeout=5,
                    )
                else:
                    proc.kill()
                proc.wait(timeout=3.0)

    both_closed = _port_closed(LOCAL_ADMIN_PORT) and _port_closed(LOCAL_ADMIN_PORT + 1)
    if proc.poll() is None or not both_closed:
        raise RuntimeError("local_router_processes_still_active_after_shutdown")

    final_sha, final_cnt = _approved_remote_state_commit(hf_token, bootstrap["STATE_ENCRYPTION_KEY"])
    if not final_sha or final_cnt < 1:
        raise RuntimeError("post_shutdown_state_verification_failed")
    return {
        "approved_state_commit": final_sha,
        "persisted_active_connections": final_cnt,
        "local_processes_stopped": True,
    }


def deploy_secrets_and_configure_sidecar() -> dict[str, Any]:
    hf_token = _resolve_hf_token()
    bootstrap = _load_or_create_bootstrap_secrets()
    approved_sha, active_cnt = _approved_remote_state_commit(hf_token, bootstrap["STATE_ENCRYPTION_KEY"])
    enable_sidecar = "1" if (approved_sha and active_cnt >= 1) else "0"

    secrets_to_push = {
        **bootstrap,
        "HF_STATE_REPO": STATE_DATASET_REPO,
        "HF_SYNC_TOKEN": hf_token,
        "MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER": "0",
        "MALPDF_ENABLE_9ROUTER_SIDECAR": enable_sidecar,
    }
    for key, val in secrets_to_push.items():
        _set_space_secret(hf_token, key, val)

    runtime = _wait_for_space_running(hf_token)
    deadline = time.monotonic() + 90.0
    health_doc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, raw = _hf_request("GET", f"{MALPDF_PUBLIC_ORIGIN}/api/health", timeout=15.0)
        if code == 200:
            health_doc = json.loads(raw.decode("utf-8"))
            sidecar_h = health_doc.get("router_sidecar") or {}
            if enable_sidecar == "0" and health_doc.get("status") == "healthy":
                break
            if (
                enable_sidecar == "1"
                and health_doc.get("status") == "healthy"
                and sidecar_h.get("ready") is True
                and sidecar_h.get("probe_ok") is True
                and sidecar_h.get("in_sync") is True
            ):
                break
        time.sleep(4.0)
    else:
        raise TimeoutError(f"hosted_health_qualification_timeout:{health_doc.get('router_sidecar')}")

    return {
        "space_repo": MALPDF_SPACE_REPO,
        "runtime_stage": runtime.get("stage"),
        "sidecar_enabled": enable_sidecar == "1",
        "approved_state_commit": approved_sha,
        "persisted_active_connections": active_cnt,
        "router_sidecar_health": health_doc.get("router_sidecar"),
    }


def cutover_routing(*, enable: bool) -> dict[str, Any]:
    hf_token = _resolve_hf_token()
    if enable:
        code, raw = _hf_request("GET", f"{MALPDF_PUBLIC_ORIGIN}/api/health", timeout=15.0)
        if code != 200:
            raise RuntimeError(f"pre_cutover_health_failed:HTTP_{code}")
        sidecar_h = (json.loads(raw.decode("utf-8")).get("router_sidecar")) or {}
        if not (
            sidecar_h.get("ready") is True and sidecar_h.get("probe_ok") is True and sidecar_h.get("in_sync") is True
        ):
            raise RuntimeError(f"cutover_blocked_sidecar_not_qualified:{sidecar_h}")

    t0 = time.monotonic()
    _set_space_secret(hf_token, "MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER", "1" if enable else "0")
    time.sleep(5.0)
    runtime = _wait_for_space_running(hf_token)
    deadline = time.monotonic() + 120.0
    health_doc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, raw = _hf_request("GET", f"{MALPDF_PUBLIC_ORIGIN}/api/health", timeout=15.0)
        if code == 200:
            health_doc = json.loads(raw.decode("utf-8"))
            sidecar_h = health_doc.get("router_sidecar") or {}
            if not enable and health_doc.get("status") == "healthy" and sidecar_h.get("routing_enabled") is False:
                break
            if (
                enable
                and health_doc.get("status") == "healthy"
                and sidecar_h.get("routing_enabled") is True
                and sidecar_h.get("ready") is True
                and sidecar_h.get("in_sync") is True
            ):
                break
        time.sleep(3.0)
    else:
        raise TimeoutError("post_switch_health_timeout")

    return {
        "routing_to_9router": enable,
        "runtime_stage": runtime.get("stage"),
        "restart_elapsed_sec": round(time.monotonic() - t0, 2),
        "router_sidecar_health": health_doc.get("router_sidecar"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage in-Space 9Router sidecar, local onboarding, and cutover.")
    parser.add_argument("--stage-local-admin", action="store_true", help="Run local loopback 9Router onboarding")
    parser.add_argument("--import-db", type=Path, help="Import providerConnections from 9Router JSON or SQLite")
    parser.add_argument("--deploy-code-and-secrets", action="store_true", help="Stage Space secrets and sidecar flag")
    parser.add_argument("--cutover", action="store_true", help="Enable MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER=1")
    parser.add_argument("--rollback", action="store_true", help="Reset MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER=0")
    args = parser.parse_args()

    summary: dict[str, Any] = {}
    if args.stage_local_admin or args.import_db is not None:
        summary["onboarding"] = stage_local_onboarding(import_db=args.import_db)
    if args.deploy_code_and_secrets:
        summary["deploy_secrets"] = deploy_secrets_and_configure_sidecar()
    if args.cutover:
        summary["cutover"] = cutover_routing(enable=True)
    if args.rollback:
        summary["rollback"] = cutover_routing(enable=False)
    if not summary:
        parser.error("Specify an action flag")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
