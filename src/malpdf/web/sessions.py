from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

from malpdf.web.http import API_CSP, apply_security_headers
from malpdf.web.store import ScanJobStore

COOKIE_NAME = "malpdf_session"
SECURE_COOKIE_NAME = "__Host-malpdf_session"


@dataclass
class BrowserSession:
    quarantine_dir: Path
    store: ScanJobStore
    active_job_id: str | None = None
    eml_store: dict[str, tuple[bytes, Any]] = field(default_factory=dict)
    last_used: float = field(default_factory=time.monotonic)
    in_flight: int = 0


_session_context: ContextVar[BrowserSession | None] = ContextVar("malpdf_browser_session", default=None)


def current_session() -> BrowserSession:
    session = _session_context.get()
    if session is None:
        raise RuntimeError("browser_session_context_required")
    return session


def optional_session() -> BrowserSession | None:
    return _session_context.get()


def _public_origin(request: Request) -> str:
    configured = os.environ.get("MALPDF_PUBLIC_ORIGIN", "").strip().rstrip("/")
    if not configured:
        return str(request.base_url).rstrip("/")
    origin = urlsplit(configured)
    if (
        origin.scheme not in {"http", "https"}
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path
        or origin.query
        or origin.fragment
    ):
        raise ValueError("invalid_public_origin_configuration")
    origin.port
    return f"{origin.scheme}://{origin.netloc.lower()}"


class BrowserSessionRegistry:
    def __init__(self, quarantine_root: Path | str, max_sessions: int = 128, idle_seconds: int = 28800) -> None:
        self.quarantine_root = Path(quarantine_root)
        self.max_sessions = max_sessions
        self.idle_seconds = idle_seconds
        self._sessions: dict[str, BrowserSession] = {}
        self._lock = threading.RLock()

    def acquire(
        self, token: str | None, *, create: bool = True, reserve: bool = False
    ) -> tuple[str | None, BrowserSession | None]:
        now = time.monotonic()
        with self._lock:
            expired = [
                key
                for key, state in self._sessions.items()
                if not state.in_flight and now - state.last_used >= self.idle_seconds
            ]
            for key in expired:
                del self._sessions[key]
            state = self._sessions.get(token) if token is not None and len(token) == 43 else None
            if state is not None:
                state.last_used = now
                state.in_flight += int(reserve)
                return token, state
            if not create:
                return None, None
            if len(self._sessions) >= self.max_sessions:
                empty = [
                    key
                    for key, candidate in self._sessions.items()
                    if not candidate.in_flight
                    and not candidate.active_job_id
                    and not candidate.eml_store
                    and not candidate.store.list_jobs(limit=1)
                    and not candidate.store.get_audit_logs(limit=1)
                ]
                if not empty:
                    raise RuntimeError("browser_session_capacity_reached")
                del self._sessions[min(empty, key=lambda key: self._sessions[key].last_used)]
            token = secrets.token_urlsafe(32)
            directory = self.quarantine_root / uuid4().hex
            state = BrowserSession(
                directory, ScanJobStore(quarantine_dir=directory), last_used=now, in_flight=int(reserve)
            )
            self._sessions[token] = state
            return token, state

    def release(self, state: BrowserSession) -> None:
        with self._lock:
            state.in_flight -= 1


def session_route_class(registry: BrowserSessionRegistry) -> type[APIRoute]:
    class BrowserSessionRoute(APIRoute):
        async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
            request = Request(scope)
            path = request.url.path
            is_api = path.startswith("/api/")
            secure = request.url.scheme == "https"
            token: str | None = None

            async def send_with_cookie(message: Message) -> None:
                if message["type"] == "http.response.start":
                    headers = MutableHeaders(raw=message.setdefault("headers", []))
                    if token is not None:
                        cookie_response = Response()
                        cookie_name = SECURE_COOKIE_NAME if secure else COOKIE_NAME
                        cookie_response.set_cookie(
                            cookie_name,
                            token,
                            path="/",
                            max_age=registry.idle_seconds,
                            httponly=True,
                            secure=secure,
                            samesite="none" if secure else "lax",
                        )
                        cookie = cookie_response.headers["set-cookie"]
                        headers.append("set-cookie", cookie + ("; Partitioned" if secure else ""))
                    headers["cache-control"] = "no-store"
                    headers.add_vary_header("Origin, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site")
                    message["headers"] = apply_security_headers(
                        headers.raw, secure=secure, default_csp=API_CSP if is_api else None
                    )
                await send(message)

            try:
                public_origin = _public_origin(request)
            except ValueError:
                response = JSONResponse({"detail": "invalid_public_origin_configuration"}, status_code=503)
                await response(scope, receive, send_with_cookie)
                return
            secure = public_origin.startswith("https://")
            origin = request.headers.get("origin")
            sec_fetch_site = request.headers.get("sec-fetch-site")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                refuse = (origin is not None and origin != public_origin) or sec_fetch_site == "cross-site"
            else:
                refuse = (
                    is_api
                    and path != "/api/health"
                    and sec_fetch_site == "cross-site"
                    and request.headers.get("sec-fetch-mode") != "navigate"
                )
            if refuse:
                response = JSONResponse({"detail": "cross_origin_request_refused"}, status_code=403)
                await response(scope, receive, send_with_cookie)
                return

            raw_cookie = request.cookies.get(COOKIE_NAME)
            if secure:
                raw_cookie = request.cookies.get(SECURE_COOKIE_NAME) or raw_cookie
            create = path not in {"/api/health", "/favicon.ico", "/env-config.js"}
            try:
                token, state = registry.acquire(raw_cookie, create=create, reserve=True)
            except RuntimeError:
                response = JSONResponse({"detail": "browser_session_capacity_reached"}, status_code=503)
                await response(scope, receive, send_with_cookie)
                return
            context_token = _session_context.set(state)

            try:
                await super().handle(scope, receive, send_with_cookie)
            finally:
                _session_context.reset(context_token)
                if state is not None:
                    registry.release(state)

    return BrowserSessionRoute
