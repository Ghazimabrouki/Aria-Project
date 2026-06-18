"""
FastAPI application for the Response Intelligence Layer.
Runs on port 8001 (configurable via BACKEND_PORT).
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pathlib import Path

from api.routes.investigations import router as investigations_router
from api.routes.archives import router as archives_router
from api.routes.reports import router as reports_router
from api.routes.assistant import router as assistant_router
from api.routes.adaptive import router as adaptive_router
from api.routes.alerts import router as alerts_router
from api.routes.incidents import router as incidents_router
from api.routes.assets import router as assets_router
from api.routes.auth import router as auth_router
from api.routes.accounts import router as accounts_router

from api.routes.approval_ui import router as approval_ui_router

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    from response.db import init_db

    await init_db()
    logger.info("response_intelligence_db_initialized")
    yield


app = FastAPI(
    title="OpenSOAR Response Intelligence",
    description=(
        "AI-powered incident investigation, playbook generation, "
        "Ansible remediation, fix verification, and case archiving."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS hardening: use configured origins instead of wildcard
from config import get_settings

_settings = get_settings()
_cors_origins = _settings.cors_origins_list
if not _cors_origins:
    _cors_origins = ["http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-ARIA-Admin-Secret", "X-Request-ID"],
)


# ── Rate Limiting Middleware ────────────────────────────────────────────────
class RateLimitMiddleware:
    """Simple in-memory rate limiter per client IP.

    Skips loopback addresses (127.0.0.1, ::1) and requests with
    X-ARIA-Test-Bypass: true header (for test suites).
    """

    def __init__(self, app):
        self.app = app
        self._requests: dict[str, list[float]] = {}
        self._sensitive_paths = {
            "/api/v1/investigations",
            "/api/v1/investigations/",
            "/api/v1/assistant/actions",
            "/api/v1/assistant/actions/",
        }
        self._skip_hosts = {"127.0.0.1", "::1", "localhost"}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        if not settings.rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        import time
        from starlette.requests import Request as StarletteRequest
        from starlette.responses import JSONResponse

        request = StarletteRequest(scope, receive)
        client = request.client.host if request.client else "unknown"

        # Skip loopback and test bypass
        if client in self._skip_hosts:
            await self.app(scope, receive, send)
            return
        if request.headers.get("x-aria-test-bypass") == "true":
            await self.app(scope, receive, send)
            return

        path = request.url.path

        is_sensitive = any(path.startswith(p) for p in self._sensitive_paths)
        max_requests = (
            settings.rate_limit_sensitive_max_requests
            if is_sensitive
            else settings.rate_limit_max_requests
        )
        window = settings.rate_limit_window_seconds

        now = time.time()
        window_start = now - window

        history = self._requests.get(client, [])
        history = [t for t in history if t > window_start]
        history.append(now)
        self._requests[client] = history

        if len(history) > max_requests:
            response = JSONResponse(
                {"detail": "Rate limit exceeded. Please slow down."},
                status_code=429,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


app.add_middleware(RateLimitMiddleware)

app.include_router(investigations_router)
app.include_router(archives_router)
app.include_router(reports_router)
app.include_router(assistant_router)
app.include_router(adaptive_router)
app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(assets_router)
from api.routes.monitoring import router as monitoring_router

app.include_router(monitoring_router)

from api.routes.pipeline import router as pipeline_router

app.include_router(pipeline_router)

from api.routes.search import router as search_router

app.include_router(search_router)

from api.routes.dashboard import router as dashboard_router

app.include_router(dashboard_router)

from api.routes.ips import router as ips_router

app.include_router(ips_router)

# Performance monitoring routes
from api.routes.performance import router as performance_router

app.include_router(performance_router)

# Whitelist routes
from api.routes.whitelist import router as whitelist_router

app.include_router(whitelist_router)

# AI Operator routes
from api.routes.operator import router as operator_router

app.include_router(operator_router)

# WebSocket for real-time updates
from api.websocket import router as websocket_router

app.include_router(websocket_router)

# Infrastructure routes
from api.routes.infrastructure import router as infrastructure_router

app.include_router(infrastructure_router)

# Runtime Security routes
from api.routes.runtime import router as runtime_router

# ARIA internal alerting routes
from api.routes.aria_alerts import router as aria_alerts_router

app.include_router(aria_alerts_router)

app.include_router(runtime_router)

# Settings routes
from api.routes.settings import router as settings_router

app.include_router(settings_router)

# Approval UI routes (no prefix - serves HTML pages)
app.include_router(approval_ui_router)


@app.get("/")
async def root():
    return {
        "service": "ARIA - Adaptive Response Intelligence Automation",
        "version": "1.0.0",
        "endpoints": {
            "alerts": "/api/v1/alerts",
            "incidents": "/api/v1/incidents",
            "investigations": "/api/v1/investigations",
            "archives": "/api/v1/archives",
            "pipeline": "/api/v1/pipeline/status",
            "dashboard": "/api/v1/dashboard/summary",
            "search": "/api/v1/search",
            "metrics": "/api/v1/metrics/dashboard",
            "assistant": "/api/v1/assistant/query",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/health")
async def api_health():
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the approval dashboard UI."""
    from pathlib import Path

    dashboard_path = Path(__file__).parent / "templates" / "dashboard.html"
    if dashboard_path.exists():
        return dashboard_path.read_text()
    return "<h1>Dashboard not found</h1>"


@app.post("/api/v1/investigations/trigger-watch")
async def trigger_watcher():
    """Manually trigger the incident watcher to poll OpenSOAR for new incidents."""
    import asyncio
    from response.watcher import watch_incidents

    # Run one cycle in a separate task (non-blocking)
    asyncio.create_task(watch_incidents())
    return {"message": "Watcher triggered - checking for new incidents"}
