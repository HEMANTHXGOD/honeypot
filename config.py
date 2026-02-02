"""Configuration management using pydantic-settings."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Authentication
    API_KEY: str = "default_key_change_me"
    
    # Groq LLM API
    GROQ_API_KEY: str = ""
    
    # GUVI Callback Endpoint
    GUVI_CALLBACK_URL: str = "https://example.com/callback"
    
    # Scam Detection Thresholds
    HEURISTIC_THRESHOLD: int = 3  # Minimum keyword matches for scam
    MAX_MESSAGES_BEFORE_COMPLETE: int = 15
    
    # Callback Timeout
    CALLBACK_TIMEOUT_SECONDS: int = 5
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
