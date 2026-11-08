
import asyncio
import httpx

from app.core.config import settings


class AIService:
    def __init__(self):
        headers = {
            "Content-Type": "application/json"
        }

        if settings.BIFROST_API_KEY:
            headers["x-bf-vk"] = settings.BIFROST_API_KEY

        self.client = httpx.AsyncClient(
            base_url=settings.BIFROST_BASE_URL,
            headers=headers,
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
            max(1, settings.AI_MAX_CONCURRENT_REQUESTS)
        )

    async def generate(
        self,
        messages: list[dict],
        max_tokens: int | None = None
    ) -> str:
        if not settings.BIFROST_API_KEY:
            raise RuntimeError("BIFROST_API_KEY is missing")

        token_limit = (
            max_tokens
            if max_tokens is not None
            else settings.AI_MAX_TOKENS
        )

        if token_limit <= 0:
            raise ValueError("max_tokens must be greater than zero")

        payload = {
            "model": settings.AI_MODEL,
            "messages": messages,
            "max_tokens": token_limit,
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

            try:
                data = response.json()
            except ValueError as exc:
                raise RuntimeError(
                    "Bifrost returned invalid JSON"
                ) from exc

            if not isinstance(data, dict):
                raise RuntimeError(
                    "Bifrost returned an invalid response"
                )

            choices = data.get("choices")

            if not isinstance(choices, list) or not choices:
                raise RuntimeError(
                    "Bifrost returned no AI response"
                )

            message = choices[0].get("message")

            if not isinstance(message, dict):
                raise RuntimeError(
                    "Bifrost returned an invalid message"
                )

            content = message.get("content")

            if not isinstance(content, str) or not content.strip():
                raise RuntimeError(
                    "Bifrost returned empty AI content"
                )

            return content

    async def check_connection(self) -> bool:
        if not settings.BIFROST_API_KEY:
            return False

        async with self.semaphore:
            response = await self.client.get("/v1/models")
            response.raise_for_status()

            try:
                data = response.json()
            except ValueError:
                return False

            if not isinstance(data, dict):
                return False

            models = data.get("data", [])

            if not isinstance(models, list):
                return False

            return any(
                isinstance(model, dict)
                and model.get("id") == settings.AI_MODEL
                for model in models
            )

    async def close(self):
        if not self.client.is_closed:
            await self.client.aclose()


ai_service = AIService()
