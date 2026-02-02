"""Decision engine for determining conversation completion."""

from models.session import SessionState
from config import get_settings


class DecisionEngine:
    """Determines when a scam conversation should be marked complete."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def should_complete(self, session: SessionState) -> tuple[bool, str]:
        """
        Check if conversation should be marked complete.
        
        Completion criteria (ANY of these):
        - ≥1 UPI ID extracted
        - ≥1 phishing link extracted
        - ≥1 phone number + urgency keywords
        - Message count > MAX_MESSAGES_BEFORE_COMPLETE
        
        Returns:
            Tuple of (should_complete, reason)
        """
        intel = session.intelligence
        
        # Check UPI IDs
        if len(intel.upiIds) >= 1:
            return True, f"Extracted {len(intel.upiIds)} UPI ID(s)"
        
        # Check phishing links
        if len(intel.phishingLinks) >= 1:
            return True, f"Extracted {len(intel.phishingLinks)} phishing link(s)"
        
        # Check phone + urgency keywords
        urgency_keywords = {"urgent", "immediately", "asap", "now", "expire", "blocked"}
        has_urgency = bool(set(intel.suspiciousKeywords) & urgency_keywords)
        
        if len(intel.phoneNumbers) >= 1 and has_urgency:
            return True, f"Extracted phone number(s) with urgency keywords"
        
        # Check message count limit
        if session.totalMessages >= self.settings.MAX_MESSAGES_BEFORE_COMPLETE:
            return True, f"Reached message limit ({session.totalMessages})"
        
        return False, "Conversation ongoing"
    
    def get_completion_score(self, session: SessionState) -> int:
        """
        Calculate a completion readiness score (0-100).
        Higher score = more ready for completion.
        """
        score = 0
        intel = session.intelligence
        
        # Intelligence scoring
        score += len(intel.upiIds) * 30
        score += len(intel.phishingLinks) * 30
        score += len(intel.phoneNumbers) * 20
        score += len(intel.bankAccounts) * 20
        score += min(len(intel.suspiciousKeywords) * 2, 20)
        
        # Message count contribution
        msg_ratio = session.totalMessages / self.settings.MAX_MESSAGES_BEFORE_COMPLETE
        score += int(msg_ratio * 20)
        
        return min(score, 100)


# Global decision engine instance
decision_engine = DecisionEngine()
