"""Minimal FastAPI server used to preview canvas diagrams in the browser."""

from pathlib import Path

import fastapi
import uvicorn
from fastapi.staticfiles import StaticFiles


app = fastapi.FastAPI()

# Directories for canvases and the simple web app
BASE_DIR = Path(__file__).resolve().parent.parent / "root"
WEB_DIR = Path(__file__).resolve().parent / "web"


@app.get("/")
def index() -> fastapi.responses.FileResponse:
    """Serve the viewer HTML page."""
    return fastapi.responses.FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/canvas")
def list_canvases() -> list[str]:
    """Return all available ``.canvas`` files under the root directory."""
    return [str(p.relative_to(BASE_DIR)) for p in BASE_DIR.rglob("*.canvas")]


@app.get("/canvas/{canvas:path}")
def get_canvas(canvas: str) -> fastapi.responses.FileResponse:
    """Return the raw ``.canvas`` file so the frontend can render it."""
    path = (BASE_DIR / canvas).with_suffix(".canvas")
    if not path.exists():
        raise fastapi.HTTPException(status_code=404, detail="Canvas not found")
    return fastapi.responses.FileResponse(path)


def start_local_server() -> None:
    """Start a development server on http://localhost:8000."""
    uvicorn.run(app, host="localhost", port=8000)

