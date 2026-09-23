"""N2 License Server — FastAPI entry point."""
from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

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

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers[
            "Content-Security-Policy"
        ] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")
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
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>N2 License Server</title>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <link rel="stylesheet" href="/static/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="landing">
        <a href="/" class="n2-logo" style="font-size:1.5rem;">
            <svg viewBox="0 0 144 100" xmlns="http://www.w3.org/2000/svg">
                <defs><clipPath id="n2-landing"><rect x="0" y="15" width="144" height="70"/></clipPath></defs>
                <g clip-path="url(#n2-landing)" stroke="currentColor" stroke-width="18" stroke-linejoin="miter" stroke-linecap="butt" fill="none">
                    <line x1="10" y1="100" x2="30" y2="0"/>
                    <path d="M 34 100 L 54 0 L 74 100 L 94 0"/>
                    <line x1="98" y1="100" x2="118" y2="0"/>
                </g>
            </svg>
            <span class="n2-wordmark">N2<span class="copper-text">.</span>LICENSE</span>
        </a>
        <h1>License &amp; Update Server</h1>
        <p>Secure Ed25519-signed licensing, heartbeat monitoring, and release distribution for ThaliaMed.</p>
        <div class="landing-actions">
            <a href="/admin" class="btn btn-primary">Admin Dashboard</a>
            <a href="/admin/health" class="btn btn-secondary">Health Check</a>
        </div>
        <p class="muted mono" style="margin-top:48px;font-size:0.75rem;">ATHENS, GREECE &middot; N2 SYSTEMS &copy; 2026</p>
    </div>
</body>
</html>"""
    )


app.include_router(admin.router)
app.include_router(api.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
