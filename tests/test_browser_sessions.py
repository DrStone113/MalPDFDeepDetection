from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
import pytest

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
def test_trusted_public_origin_rejects_internal_and_foreign_browser_origins(
    tmp_path: Path, monkeypatch, origin: str
) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", "https://public.example.invalid")
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.post("/probe", headers={"Origin": origin})

    assert response.status_code == 403


def test_trusted_https_public_origin_sets_secure_partitioned_cookie_behind_http_proxy(
    tmp_path: Path, monkeypatch
) -> None:
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
def test_malformed_trusted_public_origin_fails_closed(
    tmp_path: Path, monkeypatch, method: str, public_origin: str
) -> None:
    monkeypatch.setenv("MALPDF_PUBLIC_ORIGIN", public_origin)
    client = TestClient(_origin_test_app(tmp_path), base_url="http://internal-proxy")

    response = client.request(method, "/probe")

    assert response.status_code == 503
    assert "set-cookie" not in response.headers


def test_default_origin_validation_uses_request_origin_without_trusting_forwarded_headers(
    tmp_path: Path, monkeypatch
) -> None:
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


def test_security_headers_and_host_cookie_prefix_across_schemes_and_errors(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MALPDF_PUBLIC_ORIGIN", raising=False)
    registry = BrowserSessionRegistry(tmp_path / "quarantine")
    app = FastAPI()
    app.router.route_class = session_route_class(registry)

    @app.get("/")
    def root() -> HTMLResponse:
        return HTMLResponse("<!doctype html><title>Root</title>")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/api/scans")
    def scans() -> list[dict]:
        return []

    @app.post("/api/probe")
    def probe() -> dict[str, bool]:
        return {"ok": True}

    https_client = TestClient(app, base_url="https://testserver")
    https_res = https_client.get("/api/scans")
    assert https_res.status_code == 200
    https_cookies = [h.lower() for h in https_res.headers.get_list("set-cookie")]
    assert any(
        h.startswith("__host-malpdf_session=") and "path=/" in h and "secure" in h and "partitioned" in h
        for h in https_cookies
    )
    assert https_res.headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"
    assert https_res.headers.get("x-content-type-options") == "nosniff"
    assert https_res.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert https_res.headers.get("cross-origin-resource-policy") == "same-origin"
    assert "camera=()" in https_res.headers.get("permissions-policy", "")
    assert "x-frame-options" not in {k.lower() for k in https_res.headers.keys()}
    assert https_res.headers.get("content-security-policy") == (
        "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    vary_tokens = {token.strip().lower() for token in https_res.headers.get("vary", "").split(",")}
    assert {"origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"}.issubset(vary_tokens)

    # Legacy cookie fallback on HTTPS read
    token = https_res.cookies.get("__Host-malpdf_session")
    assert token is not None
    legacy_client = TestClient(app, base_url="https://testserver")
    legacy_client.cookies.set("malpdf_session", token)
    legacy_res = legacy_client.get("/api/scans")
    assert legacy_res.status_code == 200
    assert legacy_res.cookies.get("__Host-malpdf_session") == token

    # HTTP uses unprefixed cookie and omits HSTS
    http_client = TestClient(app, base_url="http://testserver")
    http_res = http_client.get("/api/scans")
    assert http_res.status_code == 200
    http_cookies = [h.lower() for h in http_res.headers.get_list("set-cookie")]
    assert any(h.startswith("malpdf_session=") and "samesite=lax" in h for h in http_cookies)
    assert "strict-transport-security" not in {k.lower() for k in http_res.headers.keys()}

    # Non-navigational cross-site GET to /api/* (other than /api/health) returns 403 with security headers
    blocked_api = https_client.get(
        "/api/scans",
        headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
    )
    assert blocked_api.status_code == 403
    assert blocked_api.headers.get("x-content-type-options") == "nosniff"
    assert blocked_api.headers.get("cross-origin-resource-policy") == "same-origin"

    # Health endpoint and navigational document GET remain allowed cross-site
    health_cross = https_client.get(
        "/api/health",
        headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
    )
    assert health_cross.status_code == 200
    nav_root = https_client.get(
        "/",
        headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"},
    )
    assert nav_root.status_code == 200

    # 503 capacity error retains security headers
    cap_registry = BrowserSessionRegistry(tmp_path / "cap", max_sessions=1)
    cap_app = FastAPI()
    cap_app.router.route_class = session_route_class(cap_registry)

    @cap_app.get("/api/scans")
    def cap_scans() -> list[dict]:
        return []

    owner = TestClient(cap_app, base_url="https://testserver")
    owner_tok, owner_state = cap_registry.acquire(None)
    assert owner_tok is not None and owner_state is not None
    owner_state.active_job_id = "busy"
    exhausted = owner.get("/api/scans")
    assert exhausted.status_code == 503
    assert exhausted.headers.get("x-content-type-options") == "nosniff"
    assert exhausted.headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"
