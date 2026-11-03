from fastapi import FastAPI
from app.api.users import router as users_router
from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router

app = FastAPI(
    title="RepLock API",
    description="AI-powered Autonomous Repository Security Platform",
    version="0.1.0"
)

app.include_router(users_router, prefix="/api/v1")
app.include_router(repositories_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")

@app.get("/")
def home():
    return {"message": "Welcome to RepLock API", "status": "running"}

@app.get("/health")
def health():
    return {"status": "healthy"}