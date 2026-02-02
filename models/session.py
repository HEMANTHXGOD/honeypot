"""Session state model for tracking scam interactions."""

from pydantic import BaseModel, Field
from typing import List, Dict, Any
from datetime import datetime


class Intelligence(BaseModel):
    """Extracted scam intelligence."""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class ConversationTurn(BaseModel):
    """A single turn in the conversation."""
    role: str  # "scammer" or "victim"
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class SessionState(BaseModel):
    """Complete session state for a scam interaction."""
    sessionId: str
    scamDetected: bool = False
    agentActivated: bool = False
    totalMessages: int = 0
    intelligence: Intelligence = Field(default_factory=Intelligence)
    conversationHistory: List[ConversationTurn] = Field(default_factory=list)
    agentNotes: str = ""
    conversationComplete: bool = False
    callbackSent: bool = False
    createdAt: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updatedAt: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
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
