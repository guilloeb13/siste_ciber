"""
NavajaCyber - Main FastAPI Application

USO AUTORIZADO ÚNICAMENTE. Este software está diseñado para defensa,
capacitación y análisis forense. Cualquier uso no autorizado es ilegal.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.routers import metrics, findings, analysis, ctf, forensic, auth, agents, database_analysis
from backend.app.services.redis_service import RedisService
from backend.app.services.database import init_db, close_db

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class ConnectionManager:
    """Manage WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.subscriptions: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str = "default"):
        await websocket.accept()
        self.active_connections.append(websocket)
        if channel not in self.subscriptions:
            self.subscriptions[channel] = []
        self.subscriptions[channel].append(websocket)
        logger.info("websocket_connected", channel=channel, total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        for channel in self.subscriptions.values():
            if websocket in channel:
                channel.remove(websocket)
        logger.info("websocket_disconnected", total=len(self.active_connections))

    async def broadcast(self, message: dict, channel: str = "default"):
        """Broadcast message to all connections in a channel."""
        if channel in self.subscriptions:
            for connection in self.subscriptions[channel]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error("broadcast_error", error=str(e))

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to specific connection."""
        await websocket.send_json(message)


manager = ConnectionManager()
redis_service: RedisService | None = None


async def _authenticate_websocket(websocket: WebSocket) -> bool:
    """Validate the JWT supplied as a ``token`` query parameter.

    WebSocket handshakes cannot use the Authorization header from browsers, so
    the short-lived access token is passed as a query parameter. Closes the
    socket with policy-violation (1008) when the token is missing or invalid.
    """
    from jose import JWTError, jwt

    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return False
    try:
        jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        await websocket.close(code=1008)
        return False
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global redis_service

    logger.info("starting_application", app_name=settings.app_name, env=settings.app_env)

    # Initialize database
    await init_db()

    # Initialize Redis
    redis_service = RedisService(settings.redis_url)
    await redis_service.connect()

    # Start metric subscriber
    asyncio.create_task(metric_subscriber())

    logger.info("application_started")

    yield

    # Cleanup
    logger.info("shutting_down_application")
    if redis_service:
        await redis_service.disconnect()
    await close_db()
    logger.info("application_shutdown_complete")


async def metric_subscriber():
    """Subscribe to Redis pubsub for real-time metric updates."""
    global redis_service
    if not redis_service:
        return

    try:
        async for message in redis_service.subscribe("metrics"):
            await manager.broadcast(message, "metrics")
    except Exception as e:
        logger.error("metric_subscriber_error", error=str(e))


# Create FastAPI application
app = FastAPI(
    title="NavajaCyber API",
    description="""
    Swiss-Army Cyber Toolkit - Defense, Monitoring, Forensics & CTF Training Platform

    **USO AUTORIZADO ÚNICAMENTE**

    Este software está diseñado exclusivamente para:
    - Defensa y monitoreo de infraestructura
    - Análisis forense autorizado
    - Capacitación en ciberseguridad (CTF)
    - Análisis de código y dependencias

    Cualquier uso no autorizado, intento de intrusión o explotación contra
    sistemas externos sin permiso es ilegal.
    """,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Reject requests with an unexpected Host header (defends against Host-header
# poisoning and DNS-rebinding). "*" only when explicitly configured.
if settings.allowed_hosts_list and "*" not in settings.allowed_hosts_list:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts_list,
    )

# CORS: only explicit origins may be combined with credentials. The old code
# fell back to "*" with allow_credentials=True, which is invalid and unsafe.
_cors_origins = settings.cors_origins_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=bool(_cors_origins),
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["Metrics"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(database_analysis.router, prefix="/api/db-analysis", tags=["Database Analysis"])
app.include_router(forensic.router, prefix="/api/forensic", tags=["Forensic"])
app.include_router(ctf.router, prefix="/api/ctf", tags=["CTF"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "status": "operational",
        "documentation": "/docs" if settings.debug else "disabled",
        "legal_notice": (
            "USO AUTORIZADO ÚNICAMENTE. Este software está diseñado para defensa, "
            "capacitación y análisis forense. El uso no autorizado es ilegal."
        ),
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0",
        "checks": {
            "api": "ok",
            "database": "unknown",
            "redis": "unknown",
        }
    }

    # Check Redis
    if redis_service and await redis_service.ping():
        health_status["checks"]["redis"] = "ok"
    else:
        health_status["checks"]["redis"] = "error"
        health_status["status"] = "degraded"

    return health_status


@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics streaming."""
    if not await _authenticate_websocket(websocket):
        return
    await manager.connect(websocket, "metrics")
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
            message = json.loads(data)
            if message.get("type") == "ping":
                await manager.send_personal(websocket, {"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        manager.disconnect(websocket)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert streaming."""
    if not await _authenticate_websocket(websocket):
        return
    await manager.connect(websocket, "alerts")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket("/ws/ctf")
async def websocket_ctf(websocket: WebSocket):
    """WebSocket endpoint for CTF scoreboard updates."""
    if not await _authenticate_websocket(websocket):
        return
    await manager.connect(websocket, "ctf")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    logger.error("unhandled_exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "detail": str(exc) if settings.debug else None,
        }
    )


def run_server():
    """Run the server using uvicorn."""
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers if settings.app_env == "production" else 1,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run_server()
