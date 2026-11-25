import hashlib
from pathlib import Path
import secrets
from urllib.parse import quote
import zlib

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.routing import APIRoute

STATIC_DIR = Path(__file__).parent / "static"
GRAPH_ASSET_PATH = "/assets/vis-network-10.1.5.min.js"
STATIC_ASSETS: dict[str, tuple[str, str, bool]] = {
    "/assets/dashboard.css": ("dashboard.css", "text/css", False),
    "/assets/dashboard-theme.css": ("dashboard-theme.css", "text/css", False),
    "/assets/dashboard-core.js": ("dashboard-core.js", "text/javascript", False),
    "/assets/dashboard-ai.js": ("dashboard-ai.js", "text/javascript", False),
    "/assets/dashboard-graph.js": ("dashboard-graph.js", "text/javascript", False),
    "/assets/dashboard-app.js": ("dashboard-app.js", "text/javascript", False),
    GRAPH_ASSET_PATH: ("vis-network-10.1.5.min.js", "text/javascript", True),
    "/assets/marked-18.3.0.min.js": ("marked-18.3.0.min.js", "text/javascript", True),
    "/assets/purify-3.5.0.min.js": ("purify-3.5.0.min.js", "text/javascript", True),
}
ASSET_VERSION_FILES = (
    "dashboard.css",
    "dashboard-theme.css",
    "dashboard-core.js",
    "dashboard-ai.js",
    "dashboard-graph.js",
    "dashboard-app.js",
)
API_CSP = "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"


def compute_asset_version() -> str:
    digest = hashlib.sha256()
    for name in ASSET_VERSION_FILES:
        path = STATIC_DIR / name
        if path.is_file():
            digest.update(name.encode("utf-8") + b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def build_html_csp(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic' 'wasm-unsafe-eval' 'report-sample'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'self' https://huggingface.co https://*.hf.space; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "connect-src 'self' https://huggingface.co https://*.hf.co https://*.huggingface.co "
        "https://raw.githubusercontent.com https://esm.run https://cdn.jsdelivr.net; "
        "worker-src 'self' blob:; "
        "require-trusted-types-for 'script'; "
        "trusted-types malpdf-html malpdf-script-url dompurify"
    )


def apply_security_headers(
    headers: list[tuple[bytes, bytes]], *, secure: bool, default_csp: str | None = None
) -> list[tuple[bytes, bytes]]:
    defaults = [
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"strict-origin-when-cross-origin"),
        (b"permissions-policy", b"camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
        (b"cross-origin-resource-policy", b"same-origin"),
    ]
    if default_csp is not None:
        defaults.append((b"content-security-policy", default_csp.encode("ascii")))
    if secure:
        defaults.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    names = {name.lower() for name, _ in headers}
    return [*headers, *((name, value) for name, value in defaults if name not in names)]


def render_dashboard_html_response(template_text: str) -> HTMLResponse:
    nonce = secrets.token_urlsafe(18)
    rendered = template_text.replace("__MALPDF_CSP_NONCE__", nonce).replace(
        "__MALPDF_ASSET_VERSION__", compute_asset_version()
    )
    return HTMLResponse(
        content=rendered,
        headers={
            "Content-Security-Policy": build_html_csp(nonce),
            "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
        },
    )


def _decode_scan_gzip(content: bytes, max_bytes: int) -> bytes:
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        decoded = decoder.decompress(content, max_bytes + 1)
    except zlib.error as exc:
        raise HTTPException(status_code=400, detail="invalid_scan_upload_gzip") from exc
    if len(decoded) > max_bytes:
        raise HTTPException(status_code=413, detail="size_limit_exceeded")
    if not decoder.eof or decoder.unused_data:
        raise HTTPException(status_code=400, detail="invalid_scan_upload_gzip")
    return decoded


async def read_scan_upload(file: UploadFile, max_bytes: int, encoding: str | None) -> bytes:
    if encoding not in {None, "gzip"}:
        raise HTTPException(status_code=415, detail="unsupported_scan_upload_encoding")
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="size_limit_exceeded")
    if encoding == "gzip":
        return await run_in_threadpool(_decode_scan_gzip, content, max_bytes)
    return content


class PrivateAPIRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        if not self.path.startswith("/api/"):
            return handler

        async def private_response(request: Request) -> Response:
            try:
                response = await handler(request)
            except HTTPException as exc:
                exc.headers = {**(exc.headers or {}), "Cache-Control": "no-store"}
                raise
            response.headers["Cache-Control"] = "no-store"
            return response

        return private_response


def _dashboard_asset(
    filename: str, media_type: str, always_immutable: bool, *, secure: bool = False, v: str | None = None
) -> FileResponse:
    path = STATIC_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="asset_not_found")
    immutable = always_immutable or (v is not None and v == compute_asset_version())
    cache_control = "public, max-age=31536000, immutable" if immutable else "no-cache"
    response = FileResponse(path, media_type=media_type, headers={"Cache-Control": cache_control})
    response.raw_headers[:] = apply_security_headers(response.raw_headers, secure=secure)
    return response


def _dashboard_asset_handler(filename: str, media_type: str, always_immutable: bool):
    def asset(request: Request, v: str | None = None) -> FileResponse:
        return _dashboard_asset(filename, media_type, always_immutable, secure=request.url.scheme == "https", v=v)

    return asset


def register_dashboard_assets(router: APIRouter) -> None:
    for route_path, (filename, media_type, always_immutable) in STATIC_ASSETS.items():
        router.add_api_route(
            route_path,
            _dashboard_asset_handler(filename, media_type, always_immutable),
            methods=["GET"],
            include_in_schema=False,
            route_class_override=APIRoute,
        )


def dashboard_styles() -> FileResponse:
    return _dashboard_asset(*STATIC_ASSETS["/assets/dashboard.css"])


def dashboard_graph() -> FileResponse:
    return _dashboard_asset(*STATIC_ASSETS[GRAPH_ASSET_PATH])


def sanitized_pdf_response(content: bytes, filename: str) -> Response:
    name = quote(f"sanitized_{filename or 'document.pdf'}", safe="")
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{name}"},
    )


def omit_preview_images(audit: dict) -> None:
    audit["page_previews"] = [
        {key: value for key, value in page.items() if key != "image_data_uri"}
        for page in audit.get("page_previews", [])
    ]
