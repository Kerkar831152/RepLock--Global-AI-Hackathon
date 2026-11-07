
from fastapi import APIRouter, Depends, HTTPException

from app.core.dependencies import get_current_user
from app.models import User
from app.schemas.security_analysis import (
    SecurityAnalysisRequest,
    SecurityAnalysisResponse
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError
)

router = APIRouter(
    prefix="/security-analysis",
    tags=["Security Analysis"]
)


@router.post(
    "/analyze",
    response_model=SecurityAnalysisResponse
)
async def analyze_code_security(
    analysis_data: SecurityAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        return await security_analysis_service.analyze(
            analysis_data
        )

    except SecurityAnalysisError:
        raise HTTPException(
            status_code=502,
            detail="AI security analysis failed"
        )
