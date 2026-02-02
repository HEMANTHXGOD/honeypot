"""Session state model for tracking scam interactions."""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class Intelligence(BaseModel):
    """Extracted scam intelligence."""
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phoneNumbers: List[str] = []
    phishingLinks: List[str] = []
    suspiciousKeywords: List[str] = []
    
    class Config:
        extra = "allow"


class ConversationTurn(BaseModel):
    """A single turn in the conversation."""
    role: str = ""
    content: str = ""
    timestamp: str = ""
    
    class Config:
        extra = "allow"


class SessionState(BaseModel):
    """Complete session state for a scam interaction."""
    sessionId: str = ""
    scamDetected: bool = False
    agentActivated: bool = False
    totalMessages: int = 0
    intelligence: Intelligence = None
    conversationHistory: List[ConversationTurn] = []
    agentNotes: str = ""
    conversationComplete: bool = False
    callbackSent: bool = False
    createdAt: str = ""
    updatedAt: str = ""
    
    class Config:
        extra = "allow"
    
    def __init__(self, **data):
        if "intelligence" not in data or data["intelligence"] is None:
            data["intelligence"] = Intelligence()
        if not data.get("createdAt"):
            data["createdAt"] = datetime.utcnow().isoformat()
        if not data.get("updatedAt"):
            data["updatedAt"] = datetime.utcnow().isoformat()
        super().__init__(**data)
    
    def to_callback_payload(self) -> Dict[str, Any]:
        """Generate the GUVI callback payload."""
        return {
            "sessionId": self.sessionId,
            "scamDetected": self.scamDetected,
            "totalMessagesExchanged": self.totalMessages,
            "extractedIntelligence": {
                "bankAccounts": self.intelligence.bankAccounts,
                "upiIds": self.intelligence.upiIds,
                "phishingLinks": self.intelligence.phishingLinks,
                "phoneNumbers": self.intelligence.phoneNumbers,
                "suspiciousKeywords": self.intelligence.suspiciousKeywords
            },
            "agentNotes": self.agentNotes
        }
