from pathlib import Path
from urllib.parse import quote
import zlib

from fastapi import HTTPException, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.routing import APIRoute


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


def dashboard_styles() -> FileResponse:
    return FileResponse(
        Path(__file__).parent / "static" / "dashboard.css",
        media_type="text/css",
        headers={"Cache-Control": "no-cache"},
    )


GRAPH_ASSET_PATH = "/assets/vis-network-10.1.5.min.js"


def dashboard_graph() -> FileResponse:
    return FileResponse(
        Path(__file__).parent / "static" / Path(GRAPH_ASSET_PATH).name,
        media_type="text/javascript",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


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
