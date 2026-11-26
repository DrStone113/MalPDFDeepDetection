from __future__ import annotations

import importlib
import io
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from fastapi.testclient import TestClient
import pytest

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.web import cloud_chat

TEST_CREDENTIAL = "test-only-credential-not-valid-for-any-provider"
PRIMARY_CREDENTIAL = "primary-9router-test-credential-not-valid"
REASONING_MARKER = "PRIVATE_TRANSPORT_REASONING_MARKER"
FINAL_ANSWER = "The reviewed PDF has no detected active threat."
CLOUD_ENV_VARS = (
    "CLOUD_AI_API_KEY",
    "CLOUD_AI_URL",
    "CLOUD_AI_MODEL",
    "CLOUD_AI_ALLOW_LOOPBACK",
    "MALPDF_ROUTE_CLOUD_AI_TO_9ROUTER",
    "VILAO_API_KEY",
)


class ProviderTransport:
    def __init__(self, payload: Any = None, error: Exception | None = None, raw: bytes | None = None) -> None:
        self.payload = payload
        self.error = error
        self.raw = raw
        self.calls: list[tuple[dict[str, Any], float]] = []
        self.requests: list[Request] = []

    def open(self, request: Request, timeout: float) -> io.BytesIO:
        self.requests.append(request)
        self.calls.append((json.loads(request.data or b"{}"), timeout))
        if self.error is not None:
            raise self.error
        return io.BytesIO(self.raw if self.raw is not None else json.dumps(self.payload).encode("utf-8"))


def _clear_cloud_env(monkeypatch) -> None:
    for name in CLOUD_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(params=["malpdf.web.app", "production.web_service"], ids=["pytorch", "onnx"])
def scanned_client(request: pytest.FixtureRequest, monkeypatch):
    monkeypatch.delenv("MALPDF_PUBLIC_ORIGIN", raising=False)
    _clear_cloud_env(monkeypatch)
    monkeypatch.setenv("VILAO_API_KEY", TEST_CREDENTIAL)
    service = importlib.import_module(request.param)
    client = TestClient(service.app, base_url="https://testserver")
    response = client.post(
        "/api/scan",
        files={"file": ("reviewed-cloud-adapter.pdf", load_real_benign_bytes(), "application/pdf")},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "BENIGN"
    return client, response.json()["scan_id"]


def _install_transport(monkeypatch, transport: ProviderTransport) -> None:
    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_handlers: transport)


def _request_cloud_answer(scanned_client) -> Any:
    client, scan_id = scanned_client
    return client.post(
        "/api/ai/chat",
        json={"scan_id": scan_id, "question": "Explain the result for this document", "mode": "cloud"},
    )


def _assert_provider_material_is_not_exposed(response, caplog, capsys) -> None:
    captured = capsys.readouterr()
    observed = response.text + caplog.text + captured.out + captured.err
    contains_private_provider_material = any(
        marker in observed for marker in (TEST_CREDENTIAL, PRIMARY_CREDENTIAL, REASONING_MARKER)
    )
    assert contains_private_provider_material is False, "provider_credentials_or_private_reasoning_exposed"


def test_cloud_adapter_budgets_reasoning_and_returns_only_final_content(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    transport = ProviderTransport(
        payload={
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": FINAL_ANSWER, "reasoning_content": REASONING_MARKER},
                }
            ],
        }
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 200
    assert response.json()["answer"] == FINAL_ANSWER
    assert response.json()["mode"] == "cloud"
    assert response.json()["model"] == cloud_chat.CLOUD_MODEL
    assert len(transport.calls) == 1
    body, timeout = transport.calls[0]
    assert body["model"] == cloud_chat.CLOUD_MODEL
    assert body.get("reasoning_effort") == "low"
    assert body["max_tokens"] >= 4096
    assert 30 <= timeout <= 40
    assert transport.requests[0].full_url == "https://api.vilao.ai/v1/chat/completions"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_primary_9router_config_pairs_url_key_and_model_across_handlers(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    monkeypatch.setenv("CLOUD_AI_API_KEY", PRIMARY_CREDENTIAL)
    monkeypatch.setenv("CLOUD_AI_URL", "https://drstone113-malpdf-9router.hf.space/v1")
    monkeypatch.setenv("CLOUD_AI_MODEL", "malpdf-default")
    transport = ProviderTransport(
        payload={"choices": [{"finish_reason": "stop", "message": {"content": FINAL_ANSWER}}]}
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 200
    assert response.json()["answer"] == FINAL_ANSWER
    assert response.json()["mode"] == "cloud"
    assert response.json()["model"] == "malpdf-default"
    body, _ = transport.calls[0]
    assert body["model"] == "malpdf-default"
    assert transport.requests[0].full_url == "https://drstone113-malpdf-9router.hf.space/v1/chat/completions"
    assert transport.requests[0].get_header("Authorization") == f"Bearer {PRIMARY_CREDENTIAL}"
    assert transport.requests[0].get_header("User-agent") == "MalPDFDeepDetection/1.0"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_blank_primary_key_never_sends_legacy_credential_to_leftover_primary_url(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    monkeypatch.setenv("CLOUD_AI_API_KEY", "   ")
    monkeypatch.setenv("CLOUD_AI_URL", "https://drstone113-malpdf-9router.hf.space/v1/chat/completions")
    monkeypatch.setenv("CLOUD_AI_MODEL", "malpdf-default")
    monkeypatch.setenv("VILAO_API_KEY", TEST_CREDENTIAL)
    transport = ProviderTransport(
        payload={"choices": [{"finish_reason": "stop", "message": {"content": FINAL_ANSWER}}]}
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 200
    assert response.json()["model"] == cloud_chat.CLOUD_MODEL
    assert transport.requests[0].full_url == "https://api.vilao.ai/v1/chat/completions"
    assert transport.calls[0][0]["model"] == cloud_chat.CLOUD_MODEL
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://drstone113-malpdf-9router.hf.space/v1/chat/completions",
        "https://127.0.0.1:20128/v1/chat/completions",
        "https://192.168.1.10/v1/chat/completions",
        "https://169.254.169.254/v1/chat/completions",
        "https://localhost:20128/v1/chat/completions",
        "https://user:pass@drstone113-malpdf-9router.hf.space/v1",
        "https://drstone113-malpdf-9router.hf.space/v1?leak=1",
        "https://drstone113-malpdf-9router.hf.space/v1?",
        "https://drstone113-malpdf-9router.hf.space/v1#",
        "https://[::1/v1",
        "https://%31%32%37.0.0.1/v1",
        "https://provider .example/v1",
        "",
        "   ",
    ],
)
def test_invalid_primary_url_fails_closed_without_calling_transport(scanned_client, monkeypatch, bad_url: str) -> None:
    monkeypatch.setenv("CLOUD_AI_API_KEY", PRIMARY_CREDENTIAL)
    monkeypatch.setenv("CLOUD_AI_URL", bad_url)
    transport = ProviderTransport(error=AssertionError("invalid_url_must_not_dispatch"))
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_unavailable"
    assert transport.calls == []


def test_explicit_completion_path_preserves_trailing_slash(scanned_client, monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_AI_API_KEY", PRIMARY_CREDENTIAL)
    monkeypatch.setenv("CLOUD_AI_URL", "https://drstone113-malpdf-9router.hf.space/custom/chat/")
    transport = ProviderTransport(
        payload={"choices": [{"finish_reason": "stop", "message": {"content": FINAL_ANSWER}}]}
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 200
    assert transport.requests[0].full_url == "https://drstone113-malpdf-9router.hf.space/custom/chat/"


def test_loopback_https_allowed_only_when_explicit_test_flag_enabled(scanned_client, monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_AI_API_KEY", "dummy-local-test-key")
    monkeypatch.setenv("CLOUD_AI_URL", "https://127.0.0.1:20128/v1")
    monkeypatch.setenv("CLOUD_AI_ALLOW_LOOPBACK", "1")
    transport = ProviderTransport(
        payload={"choices": [{"finish_reason": "stop", "message": {"content": FINAL_ANSWER}}]}
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 200
    assert transport.requests[0].full_url == "https://127.0.0.1:20128/v1/chat/completions"


def test_reasoning_only_output_limit_is_classified_without_exposing_reasoning(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    transport = ProviderTransport(
        payload={
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": None, "reasoning_content": REASONING_MARKER},
                }
            ],
        }
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_output_limit"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


@pytest.mark.parametrize("wrapped", [False, True], ids=["direct", "urllib-wrapped"])
def test_cloud_transport_timeout_is_classified_without_exposing_provider_material(
    scanned_client, monkeypatch, caplog, capsys, wrapped: bool
) -> None:
    timeout = TimeoutError("Provider timeout " + TEST_CREDENTIAL + " " + REASONING_MARKER)
    transport = ProviderTransport(error=URLError(timeout) if wrapped else timeout)
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_timeout"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_cloud_provider_rate_limit_is_classified_without_exposing_provider_material(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    error = HTTPError(
        "https://provider.invalid/chat/completions",
        429,
        "Provider busy " + TEST_CREDENTIAL,
        hdrs={},
        fp=io.BytesIO(json.dumps({"error": {"message": REASONING_MARKER}}).encode("utf-8")),
    )
    transport = ProviderTransport(error=error)
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_busy"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_missing_cloud_credential_returns_none_and_never_calls_transport(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    _clear_cloud_env(monkeypatch)
    transport = ProviderTransport(error=AssertionError("provider_transport_must_not_be_used_without_credentials"))
    _install_transport(monkeypatch, transport)

    assert cloud_chat.cloud_answer("Explain the result", {}, "Summarize the checked document") is None
    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_unavailable"
    assert transport.calls == []
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_truncated_final_content_is_not_presented_as_a_complete_answer(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    transport = ProviderTransport(
        payload={
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {
                        "content": "This final answer was cut off before",
                        "reasoning_content": REASONING_MARKER,
                    },
                }
            ],
        }
    )
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_output_limit"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"choices": []},
        {"choices": [None]},
        {"choices": [{"finish_reason": "stop", "message": {"reasoning_content": REASONING_MARKER}}]},
        {"choices": [{"finish_reason": "stop", "message": {"content": {"text": FINAL_ANSWER}}}]},
        {
            "choices": [
                {"finish_reason": "stop", "message": {"content": " \t\n", "reasoning_content": REASONING_MARKER}}
            ]
        },
    ],
    ids=["null-body", "empty-choices", "null-choice", "missing-final", "typed-final", "blank-final"],
)
def test_malformed_provider_payload_is_rejected_safely(
    scanned_client, monkeypatch, caplog, capsys, payload: Any
) -> None:
    transport = ProviderTransport(payload=payload)
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_invalid_response"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


def test_non_json_provider_body_is_rejected_without_reflecting_its_contents(
    scanned_client, monkeypatch, caplog, capsys
) -> None:
    transport = ProviderTransport(raw=("not-json " + TEST_CREDENTIAL + " " + REASONING_MARKER).encode("utf-8"))
    _install_transport(monkeypatch, transport)

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_invalid_response"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


@pytest.mark.parametrize("status_code", [401, 403])
def test_provider_authentication_errors_do_not_reveal_credentials(
    scanned_client, monkeypatch, caplog, capsys, status_code: int
) -> None:
    error = HTTPError(
        "https://provider.invalid/chat/completions",
        status_code,
        "Denied " + TEST_CREDENTIAL,
        hdrs={},
        fp=io.BytesIO(json.dumps({"error": {"message": REASONING_MARKER}}).encode("utf-8")),
    )
    _install_transport(monkeypatch, ProviderTransport(error=error))

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_authentication_failed"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)


@pytest.mark.parametrize("wrapped", [False, True], ids=["direct-oserror", "urllib-network-error"])
def test_non_timeout_network_errors_have_a_safe_provider_error_code(
    scanned_client, monkeypatch, caplog, capsys, wrapped: bool
) -> None:
    network_error = OSError("Connection failed " + TEST_CREDENTIAL + " " + REASONING_MARKER)
    _install_transport(monkeypatch, ProviderTransport(error=URLError(network_error) if wrapped else network_error))

    response = _request_cloud_answer(scanned_client)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_provider_error"
    _assert_provider_material_is_not_exposed(response, caplog, capsys)
