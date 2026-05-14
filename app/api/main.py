from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logging import configure_logging
from app.core.middleware import CorrelationIdMiddleware
from app.db.base import close_database
from app.api.routes import scans, auth, reports, dashboard, health


configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_database()

app = FastAPI(
    title=settings.app_name,
    description="Application Security Orchestration & Validation Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or ["http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CorrelationIdMiddleware)

# Include routers
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(dashboard.router, tags=["dashboard"])

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
