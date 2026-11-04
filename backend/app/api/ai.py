from fastapi import APIRouter, HTTPException

from app.services.ai_service import ai_service

router = APIRouter(prefix="/ai", tags=["AI"])


@router.get("/health")
async def ai_health():
    try:
        connected = await ai_service.check_connection()

        if not connected:
            raise HTTPException(
                status_code=503,
                detail="Configured AI model is unavailable"
            )

        return {
            "status": "healthy",
            "provider": "Bifrost",
            "model": "qwen3.5:4b"
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="AI service is unavailable"
        )