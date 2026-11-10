from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from malpdf.cdr.fixtures import load_real_threat_bytes


@pytest.fixture(
    params=[
        ("malpdf.web.app", False),
        ("production.web_service", False),
        ("production.web_service", True),
    ],
    ids=["pytorch", "onnx", "onnx-copied-router"],
)
def service(request: pytest.FixtureRequest, tmp_path, monkeypatch):
    module_name, copy_router = request.param
    module = importlib.import_module(module_name)
    quarantine_dir = tmp_path / "quarantine"
    monkeypatch.setattr(module.session_registry, "quarantine_root", quarantine_dir)
    if copy_router:
        mounted_app = FastAPI()
        mounted_app.router.routes[0:0] = list(module.production_router.routes)
        return SimpleNamespace(app=mounted_app)
    return module


def _client(service: Any, cookies: dict[str, str] | None = None) -> TestClient:
    client = TestClient(service.app, base_url="https://testserver")
    for name, value in (cookies or {}).items():
        client.cookies.set(name, value, domain="testserver.local", path="/")
    return client


def _upload_reviewed_document(client: TestClient, name: str = "private-document.pdf") -> dict[str, Any]:
    response = client.post(
        "/api/scan",
        files={"file": (name, load_real_threat_bytes(), "application/pdf")},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "MALICIOUS"
    return response.json()


def test_independent_browsers_do_not_share_document_or_history(service) -> None:
    owner = _client(service)
    other = _client(service)
    scan_id = _upload_reviewed_document(owner)["scan_id"]
    mail_response = owner.post(f"/api/gateway/inspect-job/{scan_id}")
    assert mail_response.status_code == 200
    assert owner.get("/api/quarantine/list").json()
    assert owner.get("/api/audit/logs").json()["logs"]

    state = other.get("/api/session")
    assert state.status_code == 200
    assert state.json()["scan_id"] is None
    assert state.json()["staged"] is False
    assert other.get("/api/scans").json() == []
    assert other.get("/api/quarantine/list").json() == []
    assert other.get("/api/audit/logs").json()["logs"] == []
    assert other.get("/api/gateway/history").json()["results"] == []
    assert other.get("/api/health").json()["total_jobs"] == 0
    assert owner.get("/api/session").json()["scan_id"] == scan_id


def test_known_identifiers_do_not_grant_access_to_another_browsers_documents(service) -> None:
    owner = _client(service)
    other = _client(service)
    scan_id = _upload_reviewed_document(owner)["scan_id"]
    disarm_response = owner.post(f"/api/disarm/{scan_id}")
    assert disarm_response.status_code == 200
    mail_response = owner.post(f"/api/gateway/inspect-job/{scan_id}")
    assert mail_response.status_code == 200
    eml_job_id = mail_response.json()["eml_job_id"]
    quarantine_name = owner.get("/api/quarantine/list").json()[0]["stored_name"]

    requests = [
        ("GET", f"/api/scans/{scan_id}", {}),
        ("GET", f"/api/download/sanitized/{scan_id}", {}),
        ("GET", f"/api/disarm/download/{scan_id}", {}),
        ("GET", f"/api/diff/render/{scan_id}", {}),
        ("GET", f"/api/report/export?scan_id={scan_id}", {}),
        ("POST", f"/api/disarm/{scan_id}", {}),
        ("POST", f"/api/gateway/inspect-job/{scan_id}", {}),
        ("POST", "/api/ai/chat", {"json": {"scan_id": scan_id, "question": "Explain this document"}}),
        ("POST", "/api/xai/ablate", {"data": {"scan_id": scan_id, "node_id": "action:open_action"}}),
        ("GET", f"/api/gateway/download/eml/{eml_job_id}", {}),
        ("GET", f"/api/quarantine/download/{quarantine_name}", {}),
        ("DELETE", f"/api/scans/{scan_id}", {}),
    ]
    for method, path, kwargs in requests:
        response = other.request(method, path, **kwargs)
        assert response.status_code == 404, (method, path, response.status_code)

    assert owner.get(f"/api/scans/{scan_id}").status_code == 200
    assert owner.get(f"/api/download/sanitized/{scan_id}").status_code == 200
    assert owner.get(f"/api/gateway/download/eml/{eml_job_id}").status_code == 200


def test_each_browser_keeps_its_own_active_document(service) -> None:
    first = _client(service)
    second = _client(service)
    first_id = _upload_reviewed_document(first, "first-private.pdf")["scan_id"]
    second_id = _upload_reviewed_document(second, "second-private.pdf")["scan_id"]

    assert first.get("/api/session").json()["scan_id"] == first_id
    assert second.get("/api/session").json()["scan_id"] == second_id
    assert [job["scan_id"] for job in first.get("/api/scans").json()] == [first_id]
    assert [job["scan_id"] for job in second.get("/api/scans").json()] == [second_id]


def test_browser_cookie_restores_only_its_own_session(service) -> None:
    owner = _client(service)
    scan_id = _upload_reviewed_document(owner)["scan_id"]
    assert dict(owner.cookies)
    restored = _client(service, cookies=dict(owner.cookies))
    stranger = _client(service)

    assert restored.get("/api/session").json()["scan_id"] == scan_id
    assert restored.get(f"/api/scans/{scan_id}").status_code == 200
    assert stranger.get("/api/session").json()["scan_id"] is None


def test_fabricated_cookie_cannot_join_an_existing_session(service) -> None:
    owner = _client(service)
    scan_id = _upload_reviewed_document(owner)["scan_id"]
    assert dict(owner.cookies)
    fabricated = {name: "a" * 64 for name in owner.cookies.keys()}
    attacker = _client(service, cookies=fabricated)

    assert attacker.get("/api/session").json()["scan_id"] is None
    assert attacker.get(f"/api/scans/{scan_id}").status_code == 404
    assert dict(attacker.cookies) != fabricated


def test_session_cookie_is_not_accessible_to_scripts(service) -> None:
    browser = _client(service)
    response = browser.get("/api/session")
    assert response.status_code == 200
    cookie_headers = response.headers.get_list("set-cookie")
    assert cookie_headers
    assert any(
        "httponly" in header.lower()
        and "secure" in header.lower()
        and (
            any(value in header.lower() for value in ("samesite=strict", "samesite=lax"))
            or "samesite=none" in header.lower() and "partitioned" in header.lower()
        )
        for header in cookie_headers
    )


def test_foreign_browser_origins_cannot_mutate_an_existing_session(service) -> None:
    owner = _client(service)
    scan_id = _upload_reviewed_document(owner)["scan_id"]
    path = f"/api/scans/{scan_id}"

    for headers in (
        {"Origin": "https://untrusted.example"},
        {"Sec-Fetch-Site": "cross-site"},
    ):
        response = owner.delete(path, headers=headers)
        assert response.status_code == 403
        assert owner.get(path).status_code == 200

    response = owner.delete(path, headers={"Origin": "https://testserver"})
    assert response.status_code == 200
    assert owner.get(path).status_code == 404
