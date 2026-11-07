
from fastapi import APIRouter, Depends, HTTPException

from app.core.dependencies import get_current_user
from app.models import User
from app.schemas.research import (
    ResearchSearchRequest,
    ResearchSearchResponse
)
from app.services.research_service import (
    research_service,
    TavilyConfigurationError,
    TavilyAuthenticationError,
    TavilyRateLimitError,
    TavilyError
)

router = APIRouter(prefix="/research", tags=["Research"])


@router.post(
    "/search",
    response_model=ResearchSearchResponse
)
async def search_security_information(
    search_data: ResearchSearchRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        return await research_service.search(
            query=search_data.query,
            max_results=search_data.max_results
        )

    except TavilyConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc)
        )

    except TavilyAuthenticationError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc)
        )

    except TavilyRateLimitError as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc)
        )

    except TavilyError:
        raise HTTPException(
            status_code=502,
            detail="Tavily research service failed"
        )
