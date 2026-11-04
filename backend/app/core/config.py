import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    BIFROST_BASE_URL: str = os.getenv(
        "BIFROST_BASE_URL",
        "http://localhost:8080"
    )
    BIFROST_API_KEY: str = os.getenv("BIFROST_API_KEY", "")
    AI_MODEL: str = os.getenv(
        "AI_MODEL",
        "ollama/qwen3.5:4b"
    )

    AI_TIMEOUT: float = 90.0
    AI_MAX_TOKENS: int = 512
    AI_MAX_CONCURRENT_REQUESTS: int = 1

    OLLAMA_KEEP_ALIVE: str = "5m"


settings = Settings()