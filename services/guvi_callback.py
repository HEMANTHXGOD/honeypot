"""GUVI callback service for reporting extracted intelligence."""

import requests
import logging
from typing import Optional, Tuple

from config import get_settings
from models.session import SessionState

logger = logging.getLogger(__name__)


class GuviCallback:
    """Handles final intelligence reporting to GUVI endpoint.
    
    CRITICAL: This callback MUST be sent for the solution to be evaluated.
    - Call only ONCE per session
    - Call only when scamDetected=true AND conversation is complete
    - Timeout: 5 seconds
    - Retries: 3 attempts with exponential backoff
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.max_retries = 3
    
    def send_callback(self, session: SessionState) -> Tuple[bool, Optional[str]]:
        """
        Send intelligence callback to GUVI.
        
        Only sends if:
        - scamDetected is True
        - conversationComplete is True
        - callbackSent is False (enforce single callback)
        
        Returns:
            Tuple of (success, error_message)
        """
        # Validation checks
        if not session.scamDetected:
            return False, "Scam not detected, skipping callback"
        
        if not session.conversationComplete:
            return False, "Conversation not complete, skipping callback"
        
        if session.callbackSent:
            return False, "Callback already sent for this session"
        
        # Build payload
        payload = session.to_callback_payload()
        
        logger.info(f"[{session.sessionId}] Sending GUVI callback with payload: {payload}")
        
        # Retry logic with exponential backoff
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    self.settings.GUVI_CALLBACK_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.settings.CALLBACK_TIMEOUT_SECONDS
                )
                
                logger.info(f"[{session.sessionId}] GUVI callback response: {response.status_code} - {response.text[:200]}")
                
                if response.status_code in [200, 201, 202]:
                    logger.info(f"[{session.sessionId}] ✅ GUVI callback SUCCESS on attempt {attempt}")
                    return True, None
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:100]}"
                    logger.warning(f"[{session.sessionId}] Callback attempt {attempt} failed: {last_error}")
                    
            except requests.exceptions.Timeout:
                last_error = f"Timeout (>{self.settings.CALLBACK_TIMEOUT_SECONDS}s)"
                logger.warning(f"[{session.sessionId}] Callback attempt {attempt} timed out")
                
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {str(e)[:50]}"
                logger.warning(f"[{session.sessionId}] Callback attempt {attempt} connection error: {e}")
                
            except requests.exceptions.RequestException as e:
                last_error = f"Request error: {str(e)[:50]}"
                logger.warning(f"[{session.sessionId}] Callback attempt {attempt} error: {e}")
            
            # Exponential backoff: 1s, 2s, 4s
            if attempt < self.max_retries:
                import time
                backoff = 2 ** (attempt - 1)
                logger.info(f"[{session.sessionId}] Retrying in {backoff}s...")
                time.sleep(backoff)
        
        logger.error(f"[{session.sessionId}] ❌ GUVI callback FAILED after {self.max_retries} attempts: {last_error}")
        return False, f"Failed after {self.max_retries} attempts: {last_error}"
    
    def generate_payload_preview(self, session: SessionState) -> dict:
        """Generate callback payload for preview/debugging."""
        return session.to_callback_payload()


# Global callback service instance
guvi_callback = GuviCallback()
