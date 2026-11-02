from fastapi import FastAPI

app = FastAPI(
    title="RepLock API",
    description="AI-powered Autonomous Repository Security Platform",
    version="0.1.0"
)

@app.get("/")
def home():
    return {
        "message": "Welcome to RepLock API",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}