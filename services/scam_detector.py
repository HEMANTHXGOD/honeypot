"""Hybrid scam detection using heuristics and LLM."""

import re
from typing import Tuple, List
from groq import Groq

from config import get_settings


# Scam indicator keywords (case-insensitive)
SCAM_KEYWORDS = [
    "blocked", "verify", "urgent", "kyc", "upi", "account", "suspend",
    "immediately", "expire", "warning", "alert", "confirm", "update",
    "bank", "otp", "password", "pin", "limit", "freeze", "restricted",
    "action required", "verify now", "click here", "link below",
    "pay now", "transfer", "wallet", "refund", "prize", "winner",
    "lottery", "lucky", "selected", "reward", "claim", "bonus"
]

# Urgency indicators
URGENCY_PATTERNS = [
    r"within \d+ (hour|minute|day)",
    r"immediately",
    r"right now",
    r"as soon as possible",
    r"asap",
    r"urgent",
    r"time.?limit",
    r"expire",
    r"deadline"
]


class ScamDetector:
    """Hybrid scam detection combining heuristics and LLM classification."""
    
    def __init__(self):
        self.settings = get_settings()
        self.groq_client = None
        if self.settings.GROQ_API_KEY:
            self.groq_client = Groq(api_key=self.settings.GROQ_API_KEY)
    
    def _calculate_heuristic_score(self, message: str) -> Tuple[int, List[str]]:
        """Calculate heuristic scam score based on keywords and patterns."""
        message_lower = message.lower()
        matched_keywords = []
        score = 0
        
        # Check for scam keywords
        for keyword in SCAM_KEYWORDS:
            if keyword in message_lower:
                score += 1
                matched_keywords.append(keyword)
        
        # Check for urgency patterns
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                score += 2  # Urgency is a strong indicator
                matched_keywords.append(f"urgency:{pattern}")
        
        # Check for threat + urgency combo (very strong indicator)
        threat_words = ["blocked", "suspend", "freeze", "restricted", "expire"]
        urgency_words = ["immediately", "urgent", "now", "asap"]
        
        has_threat = any(w in message_lower for w in threat_words)
        has_urgency = any(w in message_lower for w in urgency_words)
        
        if has_threat and has_urgency:
            score += 3  # Threat + urgency combo is strong scam signal
            matched_keywords.append("threat+urgency_combo")
        
        return score, matched_keywords
    
    def _llm_classify(self, message: str) -> str:
        """Use Groq LLM to classify message."""
        if not self.groq_client:
            return "UNCERTAIN"
        
        try:
            prompt = f"""You are a scam intent classifier.

Classify the following message as:
- "SCAM"
- "NOT_SCAM"
- "UNCERTAIN"

Message:
"{message}"

Return ONLY one word."""

            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=10
            )
            
            result = response.choices[0].message.content.strip().upper()
            
            # Normalize response
            if "SCAM" in result and "NOT" not in result:
                return "SCAM"
            elif "NOT_SCAM" in result or "NOT SCAM" in result:
                return "NOT_SCAM"
            else:
                return "UNCERTAIN"
                
        except Exception as e:
            print(f"LLM classification error: {e}")
            return "UNCERTAIN"
    
    def detect(self, message: str) -> Tuple[bool, str, List[str]]:
        """
        Detect if a message is a scam attempt.
        
        Returns:
            Tuple of (is_scam, reason, matched_keywords)
        """
        # Step 1: Heuristic analysis
        heuristic_score, matched_keywords = self._calculate_heuristic_score(message)
        
        # Step 2: LLM classification
        llm_result = self._llm_classify(message)
        
        # Step 3: Combined decision logic
        is_scam = False
        reason = ""
        
        # Strong heuristic signals
        if heuristic_score >= self.settings.HEURISTIC_THRESHOLD:
            is_scam = True
            reason = f"Heuristic score {heuristic_score} >= threshold ({self.settings.HEURISTIC_THRESHOLD})"
        
        # LLM confirms scam
        if llm_result == "SCAM":
            is_scam = True
            reason = f"LLM classified as SCAM. {reason}" if reason else "LLM classified as SCAM"
        
        # Moderate heuristics + LLM uncertain -> likely scam
        if heuristic_score >= 2 and llm_result == "UNCERTAIN":
            is_scam = True
            reason = f"Moderate heuristics ({heuristic_score}) + LLM uncertain"
        
        if not is_scam:
            reason = f"No scam indicators (heuristic: {heuristic_score}, LLM: {llm_result})"
        
        return is_scam, reason, matched_keywords


# Global detector instance
scam_detector = ScamDetector()
