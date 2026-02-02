"""Request models for the chat API."""

from pydantic import BaseModel, Field
from typing import Optional


class Message(BaseModel):
    """Message from scammer."""
    sender: str = ""
    text: str = ""
    timestamp: Optional[str] = None
    
    class Config:
        extra = "allow"


class ChatRequest(BaseModel):
    """Incoming chat request payload."""
    sessionId: Optional[str] = Field(default=None, alias="session_id")
    message: Optional[Message] = None
    
    # Flat format fields
    sender: Optional[str] = None
    text: Optional[str] = None
    timestamp: Optional[str] = None
    
    class Config:
        extra = "allow"
        populate_by_name = True
    
    def get_session_id(self) -> str:
        """Get session ID from various possible fields."""
        return self.sessionId or "default_session"
    
    def get_message(self) -> Message:
        """Get the message, supporting both nested and flat formats."""
        if self.message:
            return self.message
        return Message(
            sender=self.sender or "unknown",
            text=self.text or "",
            timestamp=self.timestamp
        )
