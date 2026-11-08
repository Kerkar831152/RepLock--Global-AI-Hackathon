
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
        headers = {
            "Content-Type": "application/json"
        }

        if settings.TAVILY_API_KEY:
            headers["Authorization"] = (
                f"Bearer {settings.TAVILY_API_KEY}"
            )

        self.client = httpx.AsyncClient(
            base_url=settings.TAVILY_BASE_URL,
            headers=headers,
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
            max(1, settings.TAVILY_MAX_CONCURRENT_REQUESTS)
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

        if not isinstance(query, str):
            raise ValueError("Search query must be text")

        query = " ".join(query.split())

        if not query:
            raise ValueError("Search query cannot be empty")

        if not isinstance(max_results, int) or max_results < 1:
            raise ValueError("max_results must be a positive integer")

        result_limit = min(
            max_results,
            max(1, settings.TAVILY_MAX_RESULTS)
        )

        cache_key = (query.casefold(), result_limit)

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
            "max_results": result_limit,
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
                status_code = exc.response.status_code

                if status_code in {401, 403}:
                    raise TavilyAuthenticationError(
                        "Tavily API key is invalid or unauthorized"
                    ) from exc

                if status_code == 429:
                    raise TavilyRateLimitError(
                        "Tavily rate limit reached"
                    ) from exc

                raise TavilyError(
                    f"Tavily search request failed ({status_code})"
                ) from exc

            except httpx.RequestError as exc:
                raise TavilyError(
                    "Unable to connect to Tavily"
                ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise TavilyError(
                "Tavily returned invalid JSON"
            ) from exc

        if not isinstance(data, dict):
            raise TavilyError(
                "Tavily returned an invalid response"
            )

        raw_results = data.get("results", [])

        if not isinstance(raw_results, list):
            raise TavilyError(
                "Tavily returned an invalid results list"
            )

        results = []

        for item in raw_results:
            if not isinstance(item, dict):
                continue

            title = item.get("title")
            url = item.get("url")
            content = item.get("content")

            if not isinstance(title, str) or not isinstance(url, str):
                continue

            if not url.startswith(("https://", "http://")):
                continue

            if not isinstance(content, str):
                content = ""

            results.append({
                "title": title[:200],
                "url": url[:1000],
                "content": content[
                    :settings.TAVILY_MAX_CONTENT_CHARS
                ],
                "score": item.get("score"),
                "published_date": item.get("published_date")
            })

            if len(results) >= result_limit:
                break

        cache_ttl = max(
            0,
            settings.TAVILY_CACHE_TTL_SECONDS
        )

        cache_limit = max(
            0,
            settings.TAVILY_CACHE_MAX_ITEMS
        )

        if cache_ttl > 0 and cache_limit > 0:
            async with self.cache_lock:
                self.cache[cache_key] = {
                    "expires_at": time.monotonic() + cache_ttl,
                    "results": results
                }

                self.cache.move_to_end(cache_key)

                while len(self.cache) > cache_limit:
                    self.cache.popitem(last=False)

        return {
            "query": query,
            "results": results,
            "cached": False
        }

    async def close(self):
        if not self.client.is_closed:
            await self.client.aclose()


research_service = ResearchService()
