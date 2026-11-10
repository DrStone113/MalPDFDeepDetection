from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from malpdf.web.sessions import BrowserSessionRegistry, session_route_class
from malpdf.web.store import ScanJobStore


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
