"""The admin web UI's files (app/ui), served by the API at /ui: same origin, never cached, and every answer
carries the browser security headers. A mount, so it is not in the OpenAPI document."""

from pathlib import Path
from typing import Final

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

UI_PATH: Final = "/ui"
UI_FOLDER: Final = Path(__file__).resolve().parent.parent / "ui"
#: On every answer: the page runs only this origin's own files (no inline script or style), in no frame.
UI_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
#: Said outright, never guessed: a Windows registry can name .js text/plain, and with nosniff the browser
#: then refuses to run the page's scripts.
UI_MEDIA_TYPES: Final = {".js": "text/javascript", ".css": "text/css", ".html": "text/html"}


class AdminUiFiles(StaticFiles):
    """The files of app/ui; /ui/ answers index.html."""

    def __init__(self) -> None:
        super().__init__(directory=UI_FOLDER, html=True)

    async def get_response(self, path: str, scope: Scope) -> Response:
        """The file, or the 404 for a missing one, with the UI's headers."""
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            raise HTTPException(exc.status_code, exc.detail, {**(exc.headers or {}), **UI_HEADERS}) from exc
        response.headers.update(UI_HEADERS)
        served = getattr(response, "path", path)  # the directory's index.html, when the path names a directory
        if media_type := UI_MEDIA_TYPES.get(Path(served).suffix):
            response.headers["Content-Type"] = f"{media_type}; charset=utf-8"
        return response
