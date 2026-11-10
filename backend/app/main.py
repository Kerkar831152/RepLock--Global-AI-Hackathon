from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.ai import router as ai_router
from app.api.research import router as research_router
from app.api.security_analysis import router as security_analysis_router
from app.api.dashboard import router as dashboard_router
from app.api.repository_security import router as repository_security_router
from app.api.pull_requests import router as pull_requests_router
from app.api.merge_intelligence import router as merge_intelligence_router
from app.api.reports import router as reports_router

from app.services.ai_service import ai_service
from app.services.research_service import research_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        yield
    finally:
        try:
            await ai_service.close()
        finally:
            await research_service.close()


app = FastAPI(
    title="RepLock API",
    description="AI-powered Autonomous Repository Security Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

routers = [
    repositories_router,
    scans_router,
    findings_router,
    auth_router,
    users_router,
    ai_router,
    research_router,
    security_analysis_router,
    dashboard_router,
    repository_security_router,
    pull_requests_router,
    merge_intelligence_router,
    reports_router,
]

for router in routers:
    app.include_router(router, prefix="/api/v1")


@app.get("/")
def home():
    return {
        "message": "Welcome to RepLock API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}