from __future__ import annotations

import atexit
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from malpdf.web.cloud_chat import CloudProviderConfig, register_sidecar_provider

PROD_ROOT = Path(__file__).resolve().parent
NODE_VERSION = "v22.23.5"
NODE_LINUX_X64_URL = f"https://nodejs.org/dist/{NODE_VERSION}/node-{NODE_VERSION}-linux-x64.tar.gz"
NODE_LINUX_X64_SHA256 = "c54118104acc524633b5abe106bbf44a53126ec8b4e5fa105cb92b5d7de8a1a1"

ROUTER_VERSION = "0.5.123"
ROUTER_TGZ_URL = f"https://registry.npmjs.org/9router/-/9router-{ROUTER_VERSION}.tgz"
ROUTER_TGZ_SHA512_B64 = "QnRL7dpC81H57ekl+/h3fzWYIM3QWb3WP6vZHe5oyZPGuI3or7WDzhEoZtULTjt3oeSU4IwqXtdNbpjnxLUGVA=="

SIDECAR_PUBLIC_PORT = 20128
SIDECAR_INTERNAL_PORT = 20129
DEFAULT_COMBO_NAME = "malpdf-default"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ensure_private_dir(target: Path) -> Path:
    if target.is_symlink():
        raise RuntimeError(f"symlink_rejected:{target}")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(target, 0o700)
    except OSError:
        pass
    return target


def download_verified_bytes(
    url: str,
    *,
    expected_sha256: str | None = None,
    expected_sha512_b64: str | None = None,
    max_bytes: int = 85 * 1024 * 1024,
    timeout: float = 60.0,
) -> bytes:
    req = Request(url, headers={"User-Agent": "MalPDFDeepDetection-Sidecar/1.0"})
    with build_opener(_NoRedirect()).open(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("artifact_download_exceeds_limit")
    if expected_sha256 is not None and hashlib.sha256(data).hexdigest().lower() != expected_sha256.lower():
        raise ValueError("artifact_sha256_mismatch")
    if expected_sha512_b64 is not None:
        actual_b64 = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        if actual_b64 != expected_sha512_b64:
            raise ValueError("artifact_sha512_mismatch")
    return data


def _extract_tar_gz_atomic(tgz_bytes: bytes, dest_dir: Path) -> None:
    parent = _ensure_private_dir(dest_dir.parent)
    staging = parent / f".staging-{dest_dir.name}-{os.getpid()}-{time.time_ns()}"
    _ensure_private_dir(staging)
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            tf.extractall(staging, filter="data")
        if dest_dir.exists():
            shutil.rmtree(staging, ignore_errors=True)
            return
        staging.rename(dest_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _node_binary_compatible(node_bin: str) -> bool:
    probe = (
        "const [maj,min]=process.versions.node.split('.').map(Number);"
        "import('node:sqlite').then(()=>process.exit((maj>22||(maj===22&&min>=5))?0:1)).catch(()=>process.exit(1));"
    )
    try:
        res = subprocess.run([node_bin, "-e", probe], capture_output=True, timeout=8, check=False)
        return res.returncode == 0
    except OSError:
        return False


def ensure_node_binary(runtime_dir: Path) -> str:
    sys_node = shutil.which("node")
    if sys_node and _node_binary_compatible(sys_node):
        return sys_node
    if not (sys.platform.startswith("linux") and platform.machine().lower() in {"x86_64", "amd64"}):
        raise RuntimeError("compatible_node22_unavailable")
    install_dir = _ensure_private_dir(runtime_dir) / f"node-{NODE_VERSION}"
    node_bin = install_dir / f"node-{NODE_VERSION}-linux-x64" / "bin" / "node"
    if not node_bin.is_file():
        raw = download_verified_bytes(NODE_LINUX_X64_URL, expected_sha256=NODE_LINUX_X64_SHA256)
        _extract_tar_gz_atomic(raw, install_dir)
    if not node_bin.is_file() or not _node_binary_compatible(str(node_bin)):
        raise RuntimeError("downloaded_node_verification_failed")
    return str(node_bin)


def ensure_router_package(runtime_dir: Path) -> Path:
    install_dir = _ensure_private_dir(runtime_dir) / f"9router-{ROUTER_VERSION}"
    app_dir = install_dir / "package" / "app"
    if not (app_dir / "custom-server.js").is_file():
        raw = download_verified_bytes(ROUTER_TGZ_URL, expected_sha512_b64=ROUTER_TGZ_SHA512_B64)
        _extract_tar_gz_atomic(raw, install_dir)
    if not (app_dir / "custom-server.js").is_file():
        raise RuntimeError("router_package_missing_custom_server")
    return app_dir


def resolve_supervisor_mjs() -> Path:
    for candidate in (PROD_ROOT / "9router_space" / "hf_supervisor.mjs", PROD_ROOT / "hf_supervisor.mjs"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("hf_supervisor_mjs_not_found")


def _loopback_json(
    method: str, url: str, api_key: str, body: dict[str, Any] | None = None, timeout: float = 20.0
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": f"Bearer {api_key}", "User-Agent": "MalPDFDeepDetection-Sidecar/1.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, method=method, headers=headers)
    opener = build_opener(_NoRedirect(), ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read(131072).decode("utf-8"))
    except HTTPError as err:
        err.close()
        return err.code, {}
    except (URLError, TimeoutError, OSError, ValueError):
        return 0, {}


class _SidecarRuntime:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = False
        self._stopping = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._state = "disabled"
        self._restore_state = "disabled"
        self._in_sync = False
        self._probe_ok = False
        self._ready = False
        self._api_key = ""
        self._combo_name = DEFAULT_COMBO_NAME
        self._port = SIDECAR_PUBLIC_PORT

    def start_if_enabled(self) -> None:
        if os.environ.get("MALPDF_ENABLE_9ROUTER_SIDECAR", "").strip() != "1":
            register_sidecar_provider(None)
            return
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stopping = False
            self._state = "starting"
            self._api_key = os.environ.get("BOOTSTRAP_API_KEY", "").strip()
            self._combo_name = os.environ.get("BOOTSTRAP_COMBO_NAME", "").strip() or DEFAULT_COMBO_NAME
            self._port = SIDECAR_PUBLIC_PORT
        register_sidecar_provider(self.get_ready_config)
        atexit.register(self.stop)
        threading.Thread(target=self._run_lifecycle, name="malpdf-9router-sidecar", daemon=True).start()

    def get_ready_config(self) -> CloudProviderConfig | None:
        with self._lock:
            proc_alive = self._proc is not None and self._proc.poll() is None
            if not (self._ready and self._probe_ok and proc_alive and self._api_key):
                return None
            return CloudProviderConfig(
                api_key=self._api_key,
                endpoint_url=f"http://127.0.0.1:{self._port}/v1/chat/completions",
                model=self._combo_name,
                bypass_proxy=True,
            )

    def get_health(self) -> dict[str, object]:
        enabled = os.environ.get("MALPDF_ENABLE_9ROUTER_SIDECAR", "").strip() == "1"
        routing_enabled = os.environ.get("MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER", "").strip() == "1"
        with self._lock:
            proc_alive = self._proc is not None and self._proc.poll() is None
            ready = bool(enabled and self._ready and self._probe_ok and self._in_sync and proc_alive)
            state = self._state if enabled else "disabled"
            if enabled and self._proc is not None and not proc_alive and not self._stopping:
                state = "exited"
            return {
                "enabled": enabled,
                "routing_enabled": routing_enabled,
                "state": state,
                "ready": ready,
                "probe_ok": bool(enabled and self._probe_ok and proc_alive),
                "restore_state": self._restore_state if enabled else "disabled",
                "in_sync": bool(enabled and self._in_sync and proc_alive),
            }

    def _run_lifecycle(self) -> None:
        try:
            if not self._api_key:
                raise RuntimeError("missing_bootstrap_api_key")
            base_tmp = Path(os.environ.get("MALPDF_9ROUTER_ROOT", str(Path(tempfile.gettempdir()) / "malpdf_9router")))
            runtime_dir = _ensure_private_dir(base_tmp / "runtime")
            data_dir = _ensure_private_dir(base_tmp / "data")
            node_bin = ensure_node_binary(runtime_dir)
            app_dir = ensure_router_package(runtime_dir)
            sup_mjs = resolve_supervisor_mjs()

            child_env = {
                **os.environ,
                "PORT": str(SIDECAR_PUBLIC_PORT),
                "INTERNAL_PORT": str(SIDECAR_INTERNAL_PORT),
                "HOSTNAME": "127.0.0.1",
                "DATA_DIR": str(data_dir),
                "SERVER_SCRIPT": str(app_dir / "custom-server.js"),
                "SERVER_CWD": str(app_dir),
                "BOOTSTRAP_COMBO_NAME": self._combo_name,
            }
            proc = subprocess.Popen([node_bin, str(sup_mjs)], env=child_env)
            with self._lock:
                if self._stopping:
                    proc.terminate()
                    return
                self._proc = proc

            base_url = f"http://127.0.0.1:{self._port}"
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                if proc.poll() is not None or self._stopping:
                    raise RuntimeError("sidecar_exited_during_boot")
                code, status_doc = _loopback_json("GET", f"{base_url}/_supervisor/status", self._api_key, timeout=5.0)
                if code == 200 and status_doc.get("ok") is True:
                    with self._lock:
                        self._restore_state = str(status_doc.get("restoreState") or "unknown")
                        self._in_sync = bool(status_doc.get("inSync"))
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("sidecar_status_timeout")

            if self._restore_state == "degraded":
                with self._lock:
                    self._state = "degraded_restore"
                return

            self._qualify_and_monitor(proc, base_url)
        except Exception:
            with self._lock:
                self._ready = False
                self._probe_ok = False
                if not self._stopping:
                    self._state = "failed"

    def _qualify_and_monitor(self, proc: subprocess.Popen[bytes], base_url: str) -> None:
        while not self._stopping and proc.poll() is None:
            if not self._probe_ok:
                comp_code, comp_doc = _loopback_json(
                    "POST",
                    f"{base_url}/v1/chat/completions",
                    self._api_key,
                    body={
                        "model": self._combo_name,
                        "messages": [{"role": "user", "content": "Trả lời ngắn gọn: OK"}],
                        "max_tokens": 128,
                        "reasoning_effort": "low",
                    },
                    timeout=35.0,
                )
                choices = comp_doc.get("choices") if comp_code == 200 else None
                first = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
                msg = first.get("message") if isinstance(first.get("message"), dict) else {}
                content = msg.get("content")
                comp_valid = (
                    comp_code == 200
                    and first.get("finish_reason") in {None, "stop"}
                    and isinstance(content, str)
                    and bool(content.strip())
                )
                if comp_valid:
                    s_code, s_doc = _loopback_json(
                        "POST", f"{base_url}/_supervisor/sync", self._api_key, body={}, timeout=20.0
                    )
                    sync_ok = (
                        s_code == 200
                        and s_doc.get("ok") is True
                        and s_doc.get("canSyncRemote") is True
                        and s_doc.get("inSync") is True
                    )
                    with self._lock:
                        self._in_sync = sync_ok
                        self._probe_ok = sync_ok
                        self._ready = sync_ok
                        self._state = "ready" if sync_ok else "sync_pending"
                else:
                    with self._lock:
                        self._probe_ok = False
                        self._ready = False
                        self._state = "awaiting_provider_credentials"
            else:
                code, status_doc = _loopback_json("GET", f"{base_url}/_supervisor/status", self._api_key, timeout=5.0)
                with self._lock:
                    if (
                        code == 200
                        and status_doc.get("ok") is True
                        and status_doc.get("restoreState") != "degraded"
                        and status_doc.get("canSyncRemote") is True
                        and status_doc.get("inSync") is True
                    ):
                        self._in_sync = True
                    else:
                        self._in_sync = False
                        self._ready = False
                        self._probe_ok = False
                        self._state = "unhealthy"
            for _ in range(30):
                if self._stopping or proc.poll() is not None:
                    break
                time.sleep(1.0)

        with self._lock:
            self._ready = False
            self._probe_ok = False
            if not self._stopping:
                self._state = "exited"

    def stop(self) -> None:
        with self._lock:
            self._stopping = True
            self._ready = False
            self._probe_ok = False
            self._state = "stopped"
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)


_RUNTIME = _SidecarRuntime()


def start_9router_sidecar_if_enabled() -> None:
    _RUNTIME.start_if_enabled()


def stop_9router_sidecar() -> None:
    _RUNTIME.stop()


def get_sidecar_health() -> dict[str, object]:
    return _RUNTIME.get_health()
