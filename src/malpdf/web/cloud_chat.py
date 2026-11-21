from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import json
import os
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from malpdf.web.sessions import current_session

CLOUD_MODEL = "cnb/minimax-m3.1-flash"
_request_times: dict[int, deque[float]] = {}
_request_lock = threading.Lock()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _cloud_request(question: str, context: dict, system_prompt: str, *, stream: bool = False) -> Request | None:
    key = os.environ.get("VILAO_API_KEY", "").strip()
    if not key:
        return None
    session = current_session()
    now = time.monotonic()
    with _request_lock:
        expired = [identifier for identifier, stamps in _request_times.items() if not stamps or now - stamps[-1] >= 60]
        for identifier in expired:
            del _request_times[identifier]
        stamps = _request_times.setdefault(id(session), deque(maxlen=6))
        while stamps and now - stamps[0] >= 60:
            stamps.popleft()
        if len(stamps) >= 6:
            raise HTTPException(status_code=429, detail="cloud_ai_request_limit")
        stamps.append(now)
    body = json.dumps({
        "model": CLOUD_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False) + "\n\n" + question},
        ],
        "stream": stream, "temperature": 0.2, "max_tokens": 4096,
        "reasoning_effort": "low",
    }).encode("utf-8")
    return Request(
        "https://api.vilao.ai/v1/chat/completions", data=body, method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    )


def cloud_answer(question: str, context: dict, system_prompt: str) -> str | None:
    request = _cloud_request(question, context, system_prompt)
    if request is None:
        return None
    with _provider_errors():
        with build_opener(NoRedirect()).open(request, timeout=40) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
        result = json.loads(raw)
        choice = result["choices"][0]
        if choice.get("finish_reason") == "length":
            raise HTTPException(status_code=503, detail="cloud_ai_output_limit")
        text = choice["message"]["content"]
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
        if len(text.strip()) > 16000:
            raise HTTPException(status_code=503, detail="cloud_ai_output_limit")
        return text.strip()


@contextmanager
def _provider_errors():
    try:
        yield
    except HTTPError as error:
        detail = {
            429: "cloud_ai_busy", 401: "cloud_ai_authentication_failed", 403: "cloud_ai_authentication_failed",
        }.get(error.code, "cloud_ai_provider_error")
        error.close()
        raise HTTPException(status_code=503, detail=detail) from None
    except TimeoutError:
        raise HTTPException(status_code=503, detail="cloud_ai_timeout") from None
    except URLError as error:
        detail = "cloud_ai_timeout" if isinstance(error.reason, TimeoutError) else "cloud_ai_provider_error"
        raise HTTPException(status_code=503, detail=detail) from None
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise HTTPException(status_code=503, detail="cloud_ai_invalid_response") from None
    except OSError:
        raise HTTPException(status_code=503, detail="cloud_ai_provider_error") from None


def _provider_frames(response):
    fields: list[str] = []
    total_bytes = 0
    frame_bytes = 0
    while True:
        line = response.readline(65537)
        if not line:
            return
        total_bytes += len(line)
        frame_bytes += len(line)
        if len(line) > 65536 or frame_bytes > 65536 or total_bytes > 2097152:
            raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
        text = line.decode("utf-8").rstrip("\r\n")
        if not text:
            if fields:
                yield "\n".join(fields)
            fields = []
            frame_bytes = 0
        elif text.startswith("data:"):
            fields.append(text[5:].removeprefix(" "))


def _sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _cloud_events(response):
    try:
        yield _sse_event("ready", {"mode": "cloud", "model": CLOUD_MODEL})
        with _provider_errors():
            text_length = 0
            has_content = False
            for frame in _provider_frames(response):
                if frame == "[DONE]":
                    break
                data = json.loads(frame)
                if "error" in data:
                    raise HTTPException(status_code=503, detail="cloud_ai_provider_error")
                choices = data["choices"]
                if not choices:
                    continue
                choice = choices[0]
                finish = choice.get("finish_reason")
                if finish == "length":
                    raise HTTPException(status_code=503, detail="cloud_ai_output_limit")
                if finish not in {None, "stop"}:
                    raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
                text = choice["delta"].get("content")
                if text is not None and not isinstance(text, str):
                    raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
                if text:
                    text_length += len(text)
                    if text_length > 16000:
                        raise HTTPException(status_code=503, detail="cloud_ai_output_limit")
                    has_content = has_content or bool(text.strip())
                    yield _sse_event("delta", {"text": text})
                else:
                    yield ": keepalive\n\n"
                if finish == "stop":
                    if not has_content:
                        raise HTTPException(status_code=503, detail="cloud_ai_invalid_response")
                    yield _sse_event("done", {"mode": "cloud", "model": CLOUD_MODEL})
                    return
            raise HTTPException(status_code=503, detail="cloud_ai_stream_interrupted")
    except HTTPException as error:
        yield _sse_event("error", {"detail": error.detail})
    finally:
        response.close()


class CloudStreamResponse(StreamingResponse):
    def __init__(self, response) -> None:
        self.upstream = response
        super().__init__(
            _cloud_events(response), media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.upstream.close()


def cloud_stream_response(question: str, context: dict, system_prompt: str) -> StreamingResponse | None:
    request = _cloud_request(question, context, system_prompt, stream=True)
    if request is None:
        return None
    with _provider_errors():
        response = build_opener(NoRedirect()).open(request, timeout=40)
    return CloudStreamResponse(response)
