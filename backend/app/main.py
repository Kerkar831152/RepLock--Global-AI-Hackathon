
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.auth import router as auth_router
from app.api.ai import router as ai_router
from app.api.research import router as research_router
from app.api.security_analysis import router as security_analysis_router

from app.services.ai_service import ai_service
from app.services.research_service import research_service

from app.api.dashboard import router as dashboard_router
from app.api.repository_security import router as repository_security_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

    await ai_service.close()
    await research_service.close()


app = FastAPI(
    title="RepLock API",
    description="AI-powered Autonomous Repository Security Platform",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(repositories_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(research_router, prefix="/api/v1")
app.include_router(security_analysis_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(repository_security_router, prefix="/api/v1")

@app.get("/")
def home():
    return {
        "message": "Welcome to RepLock API",
        "status": "running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
