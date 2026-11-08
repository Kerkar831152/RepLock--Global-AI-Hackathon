
from pathlib import Path
import os

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


def get_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")

    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")

    return value


def get_float(name: str, default: float, minimum: float = 0.1) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")

    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")

    return value


class Settings:
    BIFROST_BASE_URL = os.getenv(
        "BIFROST_BASE_URL",
        "http://localhost:8080"
    ).rstrip("/")

    BIFROST_API_KEY = os.getenv("BIFROST_API_KEY", "")
    AI_MODEL = os.getenv("AI_MODEL", "ollama/qwen3.5:4b")

    AI_TIMEOUT = get_float("AI_TIMEOUT", 180.0)
    AI_MAX_TOKENS = get_int("AI_MAX_TOKENS", 512)
    AI_MAX_CONCURRENT_REQUESTS = get_int(
        "AI_MAX_CONCURRENT_REQUESTS",
        1
    )

    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
    TAVILY_BASE_URL = "https://api.tavily.com"
    TAVILY_TIMEOUT = get_float("TAVILY_TIMEOUT", 30.0)
    TAVILY_MAX_CONCURRENT_REQUESTS = get_int(
        "TAVILY_MAX_CONCURRENT_REQUESTS",
        2
    )
    TAVILY_CACHE_TTL_SECONDS = get_int(
        "TAVILY_CACHE_TTL_SECONDS",
        3600,
        minimum=0
    )
    TAVILY_CACHE_MAX_ITEMS = get_int(
        "TAVILY_CACHE_MAX_ITEMS",
        100,
        minimum=0
    )
    TAVILY_MAX_RESULTS = get_int("TAVILY_MAX_RESULTS", 5)
    TAVILY_MAX_CONTENT_CHARS = get_int(
        "TAVILY_MAX_CONTENT_CHARS",
        1200
    )

    SEMGREP_PATH = os.getenv(
        "SEMGREP_PATH",
        str(ROOT_DIR / "semgrep_env" / "Scripts" / "semgrep.exe")
    )

    SEMGREP_TIMEOUT = get_int("SEMGREP_TIMEOUT", 120)
    REPOSITORY_MAX_ARCHIVE_SIZE = get_int(
        "REPOSITORY_MAX_ARCHIVE_SIZE",
        25 * 1024 * 1024
    )
    REPOSITORY_MAX_FILES = get_int(
        "REPOSITORY_MAX_FILES",
        200
    )
    REPOSITORY_MAX_TOTAL_SIZE = get_int(
        "REPOSITORY_MAX_TOTAL_SIZE",
        5 * 1024 * 1024
    )
    REPOSITORY_MAX_FILE_SIZE = get_int(
        "REPOSITORY_MAX_FILE_SIZE",
        200_000
    )


settings = Settings()
