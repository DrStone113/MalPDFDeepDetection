from __future__ import annotations

from collections import deque
import json
import os
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from fastapi import HTTPException

from malpdf.web.sessions import current_session

CLOUD_MODEL = "cnb/minimax-m3.1-flash"
_request_times: dict[int, deque[float]] = {}
_request_lock = threading.Lock()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cloud_answer(question: str, context: dict, system_prompt: str) -> str | None:
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
        "stream": False, "temperature": 0.2, "max_tokens": 4096,
        "reasoning_effort": "low",
    }).encode("utf-8")
    request = Request(
        "https://api.vilao.ai/v1/chat/completions", data=body, method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    )
    try:
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
