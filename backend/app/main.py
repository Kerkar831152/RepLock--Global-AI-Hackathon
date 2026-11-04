from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.auth import router as auth_router

app = FastAPI(
    title="RepLock API",
    description="AI-powered Autonomous Repository Security Platform",
    version="0.1.0"
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


@app.get("/")
def home():
    return {"message": "Welcome to RepLock API", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}