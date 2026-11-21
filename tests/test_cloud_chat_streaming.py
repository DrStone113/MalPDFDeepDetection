from __future__ import annotations

import importlib
import asyncio
import io
import json
from typing import Any
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.web import cloud_chat

PRIVATE_REASONING = "PRIVATE_REASONING_MUST_NEVER_BE_DISPLAYED"
TEST_CREDENTIAL = "test-only-credential-not-valid-for-any-provider"


def provider_event(text: str | None = None, *, reasoning: str | None = None, finish: str | None = None) -> bytes:
    delta = {"content": text, "reasoning_content": reasoning}
    return ("data: " + json.dumps({"choices": [{"delta": delta, "finish_reason": finish}]}, ensure_ascii=False) + "\r\n\r\n").encode()


class StreamTransport:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.response = io.BytesIO(raw)
        self.calls: list[dict[str, Any]] = []

    def open(self, request, timeout):
        self.calls.append(json.loads(request.data))
        self.response = io.BytesIO(self.raw)
        return self.response


@pytest.fixture(params=["malpdf.web.app", "production.web_service"], ids=["pytorch", "onnx"])
def scanned_client(request, monkeypatch):
    monkeypatch.delenv("MALPDF_PUBLIC_ORIGIN", raising=False)
    monkeypatch.setenv("VILAO_API_KEY", TEST_CREDENTIAL)
    service = importlib.import_module(request.param)
    client = TestClient(service.app, base_url="https://testserver")
    result = client.post("/api/scan", files={"file": ("reviewed-stream.pdf", load_real_benign_bytes(), "application/pdf")})
    assert result.status_code == 200
    return client, result.json()["scan_id"], service


def read_events(response):
    events = []
    for frame in response.text.replace("\r\n", "\n").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in frame.splitlines() if ": " in line and not line.startswith(":"))
        if "event" in fields and "data" in fields:
            events.append((fields["event"], json.loads(fields["data"])))
    return events


def test_cloud_stream_emits_final_deltas_and_explicit_completion(scanned_client, monkeypatch, caplog):
    client, scan_id, _ = scanned_client
    transport = StreamTransport(
        provider_event(reasoning=PRIVATE_REASONING) + provider_event("Xin chào ")
        + provider_event("bạn!", finish="stop") + b"data: [DONE]\r\n\r\n"
    )
    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: transport)

    response = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["x-accel-buffering"] == "no"
    events = read_events(response)
    assert "".join(data["text"] for event, data in events if event == "delta") == "Xin chào bạn!"
    assert events[-1] == ("done", {"mode": "cloud", "model": cloud_chat.CLOUD_MODEL})
    assert all(event != "error" for event, _ in events)
    assert PRIVATE_REASONING not in response.text + caplog.text
    assert TEST_CREDENTIAL not in response.text + caplog.text
    assert transport.calls[0]["stream"] is True
    assert transport.response.closed


def test_stream_emits_delta_before_reading_completion_and_closes_on_cancel():
    first = provider_event("Visible now")
    response = io.BytesIO(first + provider_event(" later", finish="stop"))
    events = cloud_chat._cloud_events(response)
    assert next(events).startswith("event: ready")
    assert '"text": "Visible now"' in next(events)
    assert response.tell() == len(first)
    assert not response.closed
    events.close()
    assert response.closed


def test_stream_closes_upstream_when_client_disconnects_while_sending():
    upstream = io.BytesIO(provider_event("Never finish reading"))
    response = cloud_chat.CloudStreamResponse(upstream)

    async def send(message):
        if message["type"] == "http.response.body":
            raise OSError("client disconnected")

    async def receive():
        return {"type": "http.disconnect"}

    async def run_response():
        with pytest.raises(ClientDisconnect):
            await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)

    asyncio.run(run_response())
    assert upstream.closed


def test_stream_validates_owner_input_and_missing_key_before_provider(scanned_client, monkeypatch):
    client, scan_id, service = scanned_client
    other = TestClient(service.app, base_url="https://testserver")
    transport = StreamTransport(provider_event("Should not be sent", finish="stop"))
    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: transport)
    payload = {"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True}

    assert other.post("/api/ai/chat", json=payload).status_code == 404
    assert client.post("/api/ai/chat", json={**payload, "question": "x" * 2001}).status_code == 400
    monkeypatch.delenv("VILAO_API_KEY", raising=False)
    response = client.post("/api/ai/chat", json=payload)

    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_unavailable"
    assert transport.calls == []


def test_stream_shares_the_existing_session_rate_limit(scanned_client, monkeypatch):
    client, scan_id, _ = scanned_client
    transport = StreamTransport(provider_event("Valid answer", finish="stop"))
    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: transport)
    payload = {"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True}
    for _ in range(6):
        assert client.post("/api/ai/chat", json=payload).status_code == 200
    limited = client.post("/api/ai/chat", json=payload)
    assert limited.status_code == 429
    assert limited.json()["detail"] == "cloud_ai_request_limit"
    assert len(transport.calls) == 6


def test_stream_initial_provider_failure_remains_an_http_error(scanned_client, monkeypatch):
    client, scan_id, _ = scanned_client

    class BusyTransport:
        def open(self, request, timeout):
            raise HTTPError("https://provider.invalid", 429, PRIVATE_REASONING, {}, io.BytesIO())

    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: BusyTransport())
    response = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True})
    assert response.status_code == 503
    assert response.json()["detail"] == "cloud_ai_busy"
    assert PRIVATE_REASONING not in response.text


def test_stream_mid_answer_timeout_is_a_safe_terminal_event(scanned_client, monkeypatch):
    client, scan_id, _ = scanned_client

    class TimeoutResponse(io.BytesIO):
        def readline(self, size=-1):
            line = super().readline(size)
            if not line:
                raise TimeoutError(PRIVATE_REASONING + TEST_CREDENTIAL)
            return line

    class TimeoutTransport:
        def open(self, request, timeout):
            return TimeoutResponse(provider_event("Partial answer"))

    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: TimeoutTransport())
    response = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True})
    events = read_events(response)
    assert events[-1] == ("error", {"detail": "cloud_ai_timeout"})
    assert all(event != "done" for event, _ in events)
    assert PRIVATE_REASONING not in response.text
    assert TEST_CREDENTIAL not in response.text


@pytest.mark.parametrize("raw,expected", [
    (provider_event("Incomplete", finish="length"), "cloud_ai_output_limit"),
    (provider_event("Interrupted"), "cloud_ai_stream_interrupted"),
    (provider_event(reasoning=PRIVATE_REASONING, finish="stop"), "cloud_ai_invalid_response"),
    (b"data: invalid-json\n\n", "cloud_ai_invalid_response"),
    (b"data: " + b"x" * 65536 + b"\n\n", "cloud_ai_invalid_response"),
    (provider_event("x" * 16001, finish="stop"), "cloud_ai_output_limit"),
    (b"data: \xff\n\n", "cloud_ai_invalid_response"),
], ids=["length", "interrupted", "reasoning-only", "malformed-json", "oversized-frame", "oversized-answer", "invalid-utf8"])
def test_cloud_stream_failure_is_explicit_and_never_completes(scanned_client, monkeypatch, raw, expected):
    client, scan_id, _ = scanned_client
    transport = StreamTransport(raw)
    monkeypatch.setattr(cloud_chat, "build_opener", lambda *_: transport)

    response = client.post("/api/ai/chat", json={"scan_id": scan_id, "question": "hello", "mode": "cloud", "stream": True})

    assert response.status_code == 200
    events = read_events(response)
    assert events[-1] == ("error", {"detail": expected})
    assert all(event != "done" for event, _ in events)
    assert PRIVATE_REASONING not in response.text
    assert transport.response.closed
