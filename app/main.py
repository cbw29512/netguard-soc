"""NetGuard ASGI application assembly."""

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .data_sources import VERSION
from .routes_api import router as api_router
from .routes_ui import router as ui_router
from .security import allowed_hosts, require_auth

app = FastAPI(
    title="NetGuard SOC",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts(),
)
app.mount(
    "/static",
    StaticFiles(directory="/opt/netguard/static"),
    name="static",
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    """Prevent browser caching and framing of sensitive dashboard responses."""
    response = await call_next(request)
    protected_path = (
        request.url.path in {"/", "/v2"}
        or request.url.path.startswith("/api/")
    )
    if protected_path:
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


route_dependencies = [Depends(require_auth)]
app.include_router(api_router, dependencies=route_dependencies)
app.include_router(ui_router, dependencies=route_dependencies)
