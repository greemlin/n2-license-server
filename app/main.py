"""N2 License Server — FastAPI entry point."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from app import admin, api
from app.config import get_settings
from app.crypto import generate_keypair
from app.database import init_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    init_engine(settings)

    # Ensure Ed25519 keys exist.
    private_path = settings.keys_dir / "private.pem"
    public_path = settings.keys_dir / "public.pem"
    if not private_path.exists() or not public_path.exists():
        generate_keypair(private_path, public_path)

    yield


settings = get_settings()
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

if not settings.debug:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/", response_class=HTMLResponse)
def root() -> HTMLResponse:
    return HTMLResponse(
        """<html><head><title>N2 License Server</title></head>
        <body style="font-family:sans-serif;max-width:700px;margin:40px auto">
            <h1>N2 License Server</h1>
            <p><a href="/admin">Admin Dashboard</a></p>
            <p><a href="/api/updates/check?installation_id=demo&current_version=1.0.0">Sample update check</a></p>
        </body></html>"""
    )


app.include_router(admin.router)
app.include_router(api.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
