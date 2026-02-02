"""In-memory session state management."""

from typing import Dict, Optional
from datetime import datetime
import threading

from models.session import SessionState, Intelligence


class SessionManager:
    """Thread-safe in-memory session storage."""
    
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}
        self._lock = threading.Lock()
    
    def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get an existing session."""
        with self._lock:
            return self._sessions.get(session_id)
    
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create a new one."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(
                    sessionId=session_id,
                    intelligence=Intelligence()
                )
            return self._sessions[session_id]
    
    def update_session(self, session_id: str, **updates) -> SessionState:
        """Update session with new data."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")
            
            # Update fields
            for key, value in updates.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            session.updatedAt = datetime.utcnow().isoformat()
            return session
    
    def mark_scam_detected(self, session_id: str) -> SessionState:
        """Mark session as scam detected and activate agent."""
        return self.update_session(
            session_id,
            scamDetected=True,
            agentActivated=True
        )
    
    def increment_message_count(self, session_id: str) -> SessionState:
        """Increment the message counter."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.totalMessages += 1
                session.updatedAt = datetime.utcnow().isoformat()
            return session
    
    def mark_complete(self, session_id: str, notes: str = "") -> SessionState:
        """Mark conversation as complete."""
        return self.update_session(
            session_id,
            conversationComplete=True,
            agentNotes=notes
        )
    
    def mark_callback_sent(self, session_id: str) -> SessionState:
        """Mark that callback was sent."""
        return self.update_session(session_id, callbackSent=True)
    
    def get_all_sessions(self) -> Dict[str, SessionState]:
        """Get all sessions (for debugging)."""
        with self._lock:
            return dict(self._sessions)


# Global session manager instance
session_manager = SessionManager()
