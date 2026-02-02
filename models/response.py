"""Response models for the chat API."""

from pydantic import BaseModel
from typing import Literal


class ChatResponse(BaseModel):
    """API response format."""
    status: Literal["success", "error"] = "success"
    reply: str
