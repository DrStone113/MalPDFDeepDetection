from __future__ import annotations

import importlib
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from malpdf.cdr.fixtures import load_real_benign_bytes


@pytest.fixture(params=["malpdf.web.app", "production.web_service"], ids=["pytorch", "onnx"])
def service(request: pytest.FixtureRequest, monkeypatch):
    monkeypatch.delenv("VILAO_API_KEY", raising=False)
    return importlib.import_module(request.param)


def _client(service: Any) -> TestClient:
    return TestClient(service.app, base_url="https://testserver")


def _upload_reviewed_benign_document(client: TestClient) -> str:
    response = client.post(
        "/api/scan",
        files={"file": ("reviewed-private-benign.pdf", load_real_benign_bytes(), "application/pdf")},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "BENIGN"
    return response.json()["scan_id"]


def test_cloud_chat_without_server_credentials_is_explicitly_unavailable(service) -> None:
    client = _client(service)
    scan_id = _upload_reviewed_benign_document(client)

    response = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "Explain this document", "mode": "cloud"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_unavailable"


def test_deterministic_chat_remains_available_without_cloud_credentials(service) -> None:
    client = _client(service)
    scan_id = _upload_reviewed_benign_document(client)

    response = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "Explain this document"},
    )

    assert response.status_code == 200
    assert response.json()["mode"] == "deterministic_fallback"
    assert response.json()["scan_id"] == scan_id
    assert response.json()["answer"]


def test_cloud_chat_rejects_foreign_document_before_checking_provider_credentials(service) -> None:
    owner = _client(service)
    other = _client(service)
    scan_id = _upload_reviewed_benign_document(owner)

    response = other.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "Explain this document", "mode": "cloud"},
    )

    assert response.status_code == 404
    assert owner.get(f"/api/scans/{scan_id}").status_code == 200


def test_cloud_chat_rejects_oversized_question_before_provider_dispatch(service) -> None:
    client = _client(service)
    scan_id = _upload_reviewed_benign_document(client)

    response = client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "x" * 2001, "mode": "cloud"},
    )

    assert response.status_code == 400


def test_served_html_contains_no_browser_provider_credentials(service) -> None:
    response = _client(service).get("/")
    assert response.status_code == 200
    html = response.text
    contains_provider_token_literal = bool(re.search(r"\bsk-[A-Za-z0-9_-]{12,}", html))
    assert contains_provider_token_literal is False, "embedded_provider_token_literal"

    inline_scripts = "\n".join(re.findall(r"<script\b[^>]*>(.*?)</script\s*>", html, flags=re.DOTALL | re.IGNORECASE))
    contains_browser_secret_config = bool(re.search(r"\bVILAO_(?:API_KEY|API_TOKEN|TOKEN)\b", inline_scripts))
    contains_browser_authorization_header = bool(re.search(r"\bAuthorization\s*[\"']?\s*:", inline_scripts, flags=re.IGNORECASE))
    contains_browser_bearer_config = bool(re.search(r"\bBearer\s+", inline_scripts, flags=re.IGNORECASE))
    assert contains_browser_secret_config is False, "browser_provider_secret_configuration"
    assert contains_browser_authorization_header is False, "browser_provider_authorization_header"
    assert contains_browser_bearer_config is False, "browser_provider_bearer_configuration"
