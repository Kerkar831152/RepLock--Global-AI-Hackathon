
import asyncio
import httpx

from app.core.config import settings


class AIService:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=settings.BIFROST_BASE_URL,
            headers={
                "x-bf-vk": settings.BIFROST_API_KEY,
                "Content-Type": "application/json"
            },
            timeout=httpx.Timeout(
                settings.AI_TIMEOUT,
                connect=5.0
            ),
            limits=httpx.Limits(
                max_connections=2,
                max_keepalive_connections=1,
                keepalive_expiry=30
            )
        )

        self.semaphore = asyncio.Semaphore(
            settings.AI_MAX_CONCURRENT_REQUESTS
        )

    async def generate(
        self,
        messages: list[dict],
        max_tokens: int | None = None
    ) -> str:
        if not settings.BIFROST_API_KEY:
            raise RuntimeError("BIFROST_API_KEY is missing")

        payload = {
            "model": settings.AI_MODEL,
            "messages": messages,
            "max_tokens": (
                max_tokens
                if max_tokens is not None
                else settings.AI_MAX_TOKENS
                ),
                "reasoning_effort": "none",
                "response_format": {
                    "type": "json_object"
                    },
                    "stream": False
                    }

        async with self.semaphore:
            response = await self.client.post(
                "/v1/chat/completions",
                json=payload
            )

            response.raise_for_status()
            data = response.json()

            print(
                "BIFROST RESPONSE:",
                repr(data.get("choices", []))[:4000]
            )

            message = data["choices"][0]["message"]
            return message.get("content") or ""

    async def check_connection(self) -> bool:
        if not settings.BIFROST_API_KEY:
            return False

        response = await self.client.get("/v1/models")
        response.raise_for_status()

        models = response.json().get("data", [])

        return any(
            model.get("id") == settings.AI_MODEL
            for model in models
        )

    async def close(self):
        await self.client.aclose()


ai_service = AIService()
