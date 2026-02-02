"""Configuration management."""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""
    
    def __init__(self):
        self.API_KEY = os.getenv("API_KEY", "default_key_change_me")
        self.GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
        self.GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
        self.HEURISTIC_THRESHOLD = int(os.getenv("HEURISTIC_THRESHOLD", "3"))
        self.MAX_MESSAGES_BEFORE_COMPLETE = int(os.getenv("MAX_MESSAGES_BEFORE_COMPLETE", "15"))
        self.CALLBACK_TIMEOUT_SECONDS = int(os.getenv("CALLBACK_TIMEOUT_SECONDS", "5"))


_settings = None

def get_settings() -> Settings:
    """Get settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
