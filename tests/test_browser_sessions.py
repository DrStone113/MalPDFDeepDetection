from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from malpdf.web.sessions import BrowserSessionRegistry, session_route_class
from malpdf.web.store import ScanJobStore


def _origin_test_app(tmp_path: Path) -> FastAPI:
    registry = BrowserSessionRegistry(tmp_path / "quarantine")
    app = FastAPI()
    app.router.route_class = session_route_class(registry)

    @app.api_route("/probe", methods=["GET", "POST"])
    def probe() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_registry_refuses_new_sessions_at_capacity_without_evicting_existing_owner(tmp_path: Path) -> None:
    registry = BrowserSessionRegistry(tmp_path, max_sessions=1)
    owner_token, owner_state = registry.acquire(None)
    assert owner_token is not None
    assert owner_state is not None
    owner_state.active_job_id = "owner-document"

    with pytest.raises(RuntimeError, match="browser_session_capacity_reached"):
        registry.acquire(None)

    restored_token, restored_state = registry.acquire(owner_token)
    assert restored_token == owner_token
    assert restored_state is owner_state
    assert restored_state.active_job_id == "owner-document"
    assert registry.acquire("unregistered-token", create=False) == (None, None)


def test_health_probes_do_not_allocate_sessions_or_set_browser_cookies(tmp_path: Path) -> None:
    registry = BrowserSessionRegistry(tmp_path, max_sessions=1)
    app = FastAPI()
    app.router.route_class = session_route_class(registry)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy"}

    for _ in range(3):
        probe = TestClient(app, base_url="https://testserver")
        response = probe.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
        assert "set-cookie" not in response.headers
        assert not probe.cookies

    owner_token, owner_state = registry.acquire(None)
    assert owner_token is not None
    assert owner_state is not None


def test_quarantine_rejects_sibling_paths_sharing_the_session_directory_prefix(tmp_path: Path) -> None:
    own_directory = tmp_path / "0123456789abcdef0123456789abcdef"
    own_directory.mkdir()
    outside_directory = tmp_path / (own_directory.name + "-other")
    outside_directory.mkdir()
    (outside_directory / "sentinel.txt").write_text("outside-session", encoding="utf-8")
    store = ScanJobStore(quarantine_dir=own_directory)
    (own_directory / "sentinel.txt").write_text("inside-session", encoding="utf-8")

    relative_escape = str(Path("..") / outside_directory.name / "sentinel.txt")
    assert store.get_quarantine_bytes(relative_escape) is None
    assert store.get_quarantine_bytes(str(outside_directory / "sentinel.txt")) is None
    assert store.get_quarantine_bytes("sentinel.txt") == b"inside-session"


def test_empty_page_visitors_do_not_exhaust_session_capacity_or_create_quarantine_directories(tmp_path: Path) -> None:
    quarantine_root = tmp_path / "quarantine"
    registry = BrowserSessionRegistry(quarantine_root, max_sessions=2)
    app = FastAPI()
    app.router.route_class = session_route_class(registry)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return "<!doctype html><title>Session capacity regression</title>"

    for _ in range(6):
        with TestClient(app, base_url="https://testserver") as visitor:
            response = visitor.get("/")
            assert response.status_code == 200
            assert "Session capacity regression" in response.text
            assert visitor.cookies

    assert not quarantine_root.exists()


def test_trusted_public_origin_accepts_browser_mutations_after_tls_termination(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", "https://public.example.invalid")
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.post("/probe", headers={"Origin": "https://public.example.invalid"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}


@pytest.mark.parametrize("origin", ["http://internal-proxy", "https://foreign.example.invalid"])
def test_trusted_public_origin_rejects_internal_and_foreign_browser_origins(tmp_path: Path, monkeypatch, origin: str) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", "https://public.example.invalid")
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.post("/probe", headers={"Origin": origin})

    assert response.status_code == 403


def test_trusted_https_public_origin_sets_secure_partitioned_cookie_behind_http_proxy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", "https://public.example.invalid")
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.get("/probe")

    assert response.status_code == 200
    cookie_headers = [header.lower() for header in response.headers.get_list("set-cookie")]
    assert any(
        all(attribute in header for attribute in ("secure", "httponly", "partitioned", "samesite=none"))
        for header in cookie_headers
    )


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "public_origin",
    ["https://public.example.invalid/not-an-origin", "https://user@public.example.invalid"],
    ids=["path", "userinfo"],
)
def test_malformed_trusted_public_origin_fails_closed(tmp_path: Path, monkeypatch, method: str, public_origin: str) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", public_origin)
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.request(method, "/probe")

    assert response.status_code == 503
    assert "set-cookie" not in response.headers


def test_default_origin_validation_uses_request_origin_without_trusting_forwarded_headers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MALPDF_PUBLIC_ORIGIN", raising=False)
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")
    forwarded = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example.invalid"}

    assert client.post("/probe", headers={"Origin": "http://internal-proxy"}).status_code == 200
    response = client.post("/probe", headers={**forwarded, "Origin": "https://public.example.invalid"})
    assert response.status_code == 403
    response = client.get("/probe", headers=forwarded)
    assert response.status_code == 200
    cookie_headers = [header.lower() for header in response.headers.get_list("set-cookie")]
    assert any("httponly" in header and "samesite=lax" in header for header in cookie_headers)
    assert all("secure" not in header and "partitioned" not in header for header in cookie_headers)
