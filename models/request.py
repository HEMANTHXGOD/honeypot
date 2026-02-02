"""Request models for the chat API."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class Message(BaseModel):
    """Message from scammer."""
    sender: str = Field(..., description="Sender identifier")
    text: str = Field(..., description="Message content")
    timestamp: Optional[str] = Field(default=None, description="Message timestamp")
    
    class Config:
        populate_by_name = True


class ChatRequest(BaseModel):
    """Incoming chat request payload.
    
    Supports multiple payload formats:
    - Standard: {"sessionId": "...", "message": {...}}
    - Flat: {"sessionId": "...", "sender": "...", "text": "...", "timestamp": "..."}
    """
    sessionId: str = Field(..., alias="session_id", description="Unique session identifier")
    message: Optional[Message] = Field(default=None, description="Message object")
    
    # Flat format fields
    sender: Optional[str] = Field(default=None, description="Sender (flat format)")
    text: Optional[str] = Field(default=None, description="Message text (flat format)")
    timestamp: Optional[str] = Field(default=None, description="Timestamp (flat format)")
    
    class Config:
        populate_by_name = True
    
    def get_message(self) -> Message:
        """Get the message, supporting both nested and flat formats."""
        if self.message:
            return self.message
        
        # Build message from flat fields
        return Message(
            sender=self.sender or "unknown",
            text=self.text or "",
            timestamp=self.timestamp
        )
