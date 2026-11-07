
from pathlib import Path
import os

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


class Settings:
    BIFROST_BASE_URL = os.getenv(
        "BIFROST_BASE_URL",
        "http://localhost:8080"
    )
    BIFROST_API_KEY = os.getenv("BIFROST_API_KEY", "")
    AI_MODEL = os.getenv(
        "AI_MODEL",
        "ollama/qwen3.5:4b"
    )

    AI_TIMEOUT = 180.0
    AI_MAX_TOKENS = 512
    AI_MAX_CONCURRENT_REQUESTS = 1

    OLLAMA_KEEP_ALIVE = "5m"

    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
    TAVILY_BASE_URL = "https://api.tavily.com"
    TAVILY_TIMEOUT = 30.0
    TAVILY_MAX_CONCURRENT_REQUESTS = 2
    TAVILY_CACHE_TTL_SECONDS = 3600
    TAVILY_CACHE_MAX_ITEMS = 100
    TAVILY_MAX_RESULTS = 5
    TAVILY_MAX_CONTENT_CHARS = 1200


settings = Settings()
