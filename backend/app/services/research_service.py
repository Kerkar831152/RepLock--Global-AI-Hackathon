
import asyncio
import time
from collections import OrderedDict

import httpx

from app.core.config import settings


class TavilyError(Exception):
    pass


class TavilyConfigurationError(TavilyError):
    pass


class TavilyAuthenticationError(TavilyError):
    pass


class TavilyRateLimitError(TavilyError):
    pass


class ResearchService:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=settings.TAVILY_BASE_URL,
            headers={
                "Authorization": f"Bearer {settings.TAVILY_API_KEY}",
                "Content-Type": "application/json"
            },
            timeout=httpx.Timeout(
                settings.TAVILY_TIMEOUT,
                connect=5.0
            ),
            limits=httpx.Limits(
                max_connections=3,
                max_keepalive_connections=2,
                keepalive_expiry=30
            )
        )

        self.semaphore = asyncio.Semaphore(
            settings.TAVILY_MAX_CONCURRENT_REQUESTS
        )

        self.cache = OrderedDict()
        self.cache_lock = asyncio.Lock()

    async def search(
        self,
        query: str,
        max_results: int = 5
    ) -> dict:

        if not settings.TAVILY_API_KEY:
            raise TavilyConfigurationError(
                "TAVILY_API_KEY is missing"
            )

        query = " ".join(query.split())
        cache_key = query.casefold()

        async with self.cache_lock:
            cached = self.cache.get(cache_key)

            if cached and cached["expires_at"] > time.monotonic():
                self.cache.move_to_end(cache_key)

                return {
                    "query": query,
                    "results": [
                        dict(item) for item in cached["results"]
                    ],
                    "cached": True
                }

            if cached:
                del self.cache[cache_key]

        payload = {
            "query": query,
            "search_depth": "basic",
            "topic": "general",
            "max_results": min(
                max_results,
                settings.TAVILY_MAX_RESULTS
            ),
            "chunks_per_source": 2,
            "include_answer": False,
            "include_raw_content": False
        }

        async with self.semaphore:
            try:
                response = await self.client.post(
                    "/search",
                    json=payload
                )

                response.raise_for_status()

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 401:
                    raise TavilyAuthenticationError(
                        "Tavily API key is invalid"
                    ) from exc

                if exc.response.status_code == 429:
                    raise TavilyRateLimitError(
                        "Tavily rate limit reached"
                    ) from exc

                raise TavilyError(
                    "Tavily search request failed"
                ) from exc

            except httpx.RequestError as exc:
                raise TavilyError(
                    "Unable to connect to Tavily"
                ) from exc

        data = response.json()
        results = []

        for item in data.get("results", []):
            content = item.get("content") or ""

            results.append({
                "title": (item.get("title") or "")[:200],
                "url": item.get("url") or "",
                "content": content[
                    :settings.TAVILY_MAX_CONTENT_CHARS
                ],
                "score": item.get("score"),
                "published_date": item.get("published_date")
            })

        async with self.cache_lock:
            self.cache[cache_key] = {
                "expires_at": (
                    time.monotonic()
                    + settings.TAVILY_CACHE_TTL_SECONDS
                ),
                "results": results
            }

            self.cache.move_to_end(cache_key)

            while len(self.cache) > settings.TAVILY_CACHE_MAX_ITEMS:
                self.cache.popitem(last=False)

        return {
            "query": query,
            "results": results,
            "cached": False
        }

    async def close(self):
        await self.client.aclose()


research_service = ResearchService()
