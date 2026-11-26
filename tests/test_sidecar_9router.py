from __future__ import annotations

import io
import json
from pathlib import Path
import socket
import subprocess
import sys

from fastapi.testclient import TestClient
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.web import cloud_chat
from malpdf.web.cloud_chat import CloudProviderConfig, register_sidecar_provider
import sidecar_9router


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_sidecar_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("MALPDF_ENABLE_9ROUTER_SIDECAR", raising=False)
    health = sidecar_9router.get_sidecar_health()
    assert health["enabled"] is False
    assert health["ready"] is False
    assert health["state"] == "disabled"


def test_download_verified_bytes_rejects_wrong_digests(monkeypatch) -> None:
    class FakeOpener:
        def open(self, request, timeout):
            return io.BytesIO(b"trusted-payload")

    monkeypatch.setattr(sidecar_9router, "build_opener", lambda *_: FakeOpener())

    with pytest.raises(ValueError, match="artifact_sha256_mismatch"):
        sidecar_9router.download_verified_bytes("https://example.com/file.tgz", expected_sha256="0" * 64)

    with pytest.raises(ValueError, match="artifact_sha512_mismatch"):
        sidecar_9router.download_verified_bytes("https://example.com/file.tgz", expected_sha512_b64="AAAA")


def test_supervisor_filters_sensitive_parent_env_from_child(tmp_path: Path) -> None:
    env_dump_file = tmp_path / "child_env.json"
    mock_child = tmp_path / "env_probe_child.mjs"
    mock_child.write_text(
        f"""
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {{ DatabaseSync }} from 'node:sqlite';

fs.writeFileSync({json.dumps(str(env_dump_file))}, JSON.stringify(process.env));
const dataDir = process.env.DATA_DIR;
fs.mkdirSync(path.join(dataDir, 'db'), {{ recursive: true }});
const db = new DatabaseSync(path.join(dataDir, 'db', 'data.sqlite'));
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, data TEXT);
  CREATE TABLE IF NOT EXISTS apiKeys (id TEXT PRIMARY KEY, key TEXT, name TEXT, machineId TEXT, isActive INTEGER, createdAt TEXT, accessRestricted INTEGER, accessAllow TEXT);
  CREATE TABLE IF NOT EXISTS combos (id TEXT PRIMARY KEY, name TEXT, kind TEXT, models TEXT, createdAt TEXT, updatedAt TEXT);
`);
const srv = http.createServer((req, res) => {{
  res.writeHead(200, {{'Content-Type': 'application/json'}});
  res.end(JSON.stringify({{requireLogin: true}}));
}});
process.on('SIGTERM', () => srv.close(() => process.exit(0)));
srv.listen(Number(process.env.PORT), '127.0.0.1');
""",
        encoding="utf-8",
    )
    pub_p, int_p = _free_port(), _free_port()
    sup_uri = (PROD_DIR / "9router_space" / "hf_supervisor.mjs").resolve().as_uri()
    js = f"""
const mod = await import({json.dumps(sup_uri)});
const sup = mod.createSupervisor({{
  dataDir: {json.dumps(str(tmp_path / "data"))},
  publicHost: '127.0.0.1',
  publicPort: {pub_p},
  internalPort: {int_p},
  serverArgs: [{json.dumps(str(mock_child))}],
  serverCwd: {json.dumps(str(tmp_path))},
  bootstrapApiKey: '9r_secret_bootstrap_test',
}});
await sup.start();
await sup.stop('SIGTERM');
"""
    env = {
        "PATH": subprocess.os.environ.get("PATH", ""),
        "SYSTEMROOT": subprocess.os.environ.get("SYSTEMROOT", ""),
        "HF_SYNC_TOKEN": "hf_sensitive_sync_token_must_not_leak",
        "STATE_ENCRYPTION_KEY": "state_enc_secret_must_not_leak",
        "VILAO_API_KEY": "vilao_secret_must_not_leak",
        "BOOTSTRAP_API_KEY": "9r_secret_bootstrap_test",
        "INITIAL_PASSWORD": "allowed_admin_password",
    }
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", js], env=env, capture_output=True, text=True, timeout=20
    )
    assert proc.returncode == 0, proc.stderr
    child_env = json.loads(env_dump_file.read_text(encoding="utf-8"))
    assert "HF_SYNC_TOKEN" not in child_env
    assert "STATE_ENCRYPTION_KEY" not in child_env
    assert "VILAO_API_KEY" not in child_env
    assert "BOOTSTRAP_API_KEY" not in child_env
    assert child_env.get("INITIAL_PASSWORD") == "allowed_admin_password"
    assert child_env.get("HOSTNAME") == "127.0.0.1"


def test_sidecar_routing_switch_falls_back_to_vilao_until_ready_and_bypasses_proxy(monkeypatch) -> None:
    for key in (
        "CLOUD_AI_API_KEY",
        "CLOUD_AI_URL",
        "CLOUD_AI_MODEL",
        "CLOUD_AI_ALLOW_LOOPBACK",
        "MALPDF_PUBLIC_ORIGIN",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VILAO_API_KEY", "vilao-test-fallback-key")
    monkeypatch.setenv("MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER", "1")

    import production.web_service as ws

    observed_handlers: list[list[str]] = []
    observed_urls: list[str] = []

    class RecordingTransport:
        def open(self, request, timeout):
            observed_urls.append(request.full_url)
            return io.BytesIO(
                json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "Trả lời hợp lệ."}}]}).encode(
                    "utf-8"
                )
            )

    def fake_build_opener(*handlers):
        observed_handlers.append([type(h).__name__ for h in handlers])
        return RecordingTransport()

    monkeypatch.setattr(cloud_chat, "build_opener", fake_build_opener)

    try:
        register_sidecar_provider(lambda: None)
        client = TestClient(ws.app, base_url="https://testserver")
        health = client.get("/api/health")
        assert health.status_code == 200
        assert "router_sidecar" in health.json()

        scan_resp = client.post(
            "/api/scan", files={"file": ("benign.pdf", load_real_benign_bytes(), "application/pdf")}
        )
        scan_id = scan_resp.json()["scan_id"]

        cold_resp = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "Tóm tắt", "mode": "cloud"})
        assert cold_resp.status_code == 200
        assert cold_resp.json()["model"] == cloud_chat.CLOUD_MODEL
        assert observed_urls[-1] == "https://api.vilao.ai/v1/chat/completions"
        assert "ProxyHandler" not in observed_handlers[-1]

        register_sidecar_provider(
            lambda: CloudProviderConfig(
                api_key="9r_loopback_key",
                endpoint_url="http://127.0.0.1:20128/v1/chat/completions",
                model="malpdf-default",
                bypass_proxy=True,
            )
        )
        warm_resp = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "Tóm tắt", "mode": "cloud"})
        assert warm_resp.status_code == 200
        assert warm_resp.json()["model"] == "malpdf-default"
        assert observed_urls[-1] == "http://127.0.0.1:20128/v1/chat/completions"
        assert "ProxyHandler" in observed_handlers[-1]
    finally:
        register_sidecar_provider(None)
