from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.routing import APIRoute


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
