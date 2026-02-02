"""
Scam Detection Honeypot API

A stateful agentic API that engages scammers, extracts intelligence, and reports to GUVI.

Author: GUVI Hackathon Team
Version: 1.0.0
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import logging

from config import get_settings, Settings
from models.request import ChatRequest
from models.response import ChatResponse
from models.session import ConversationTurn
from services.session_manager import session_manager
from services.scam_detector import scam_detector
from services.agent_brain import agent_brain
from services.intelligence_extractor import intelligence_extractor
from services.decision_engine import decision_engine
from services.guvi_callback import guvi_callback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Scam Detection Honeypot API",
    description="Autonomous agent that engages scammers and extracts intelligence",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Key Authentication Dependency
async def verify_api_key(request: Request, settings: Settings = Depends(get_settings)):
    """Verify x-api-key header matches configured API key."""
    api_key = request.headers.get("x-api-key")
    
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header"
        )
    
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    return api_key


# Health check endpoint (no auth required)
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "Scam Detection Honeypot API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "chat": "/chat (POST, requires x-api-key)",
            "docs": "/docs"
        }
    }


# Debug endpoint to view session (protected)
@app.get("/session/{session_id}")
async def get_session(session_id: str, _: str = Depends(verify_api_key)):
    """Get session state for debugging."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Compatible with pydantic v1 and v2
    intel = session.intelligence
    intel_dict = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phoneNumbers": intel.phoneNumbers,
        "phishingLinks": intel.phishingLinks,
        "suspiciousKeywords": intel.suspiciousKeywords
    }
    
    return {
        "status": "success",
        "session": {
            "sessionId": session.sessionId,
            "scamDetected": session.scamDetected,
            "agentActivated": session.agentActivated,
            "totalMessages": session.totalMessages,
            "conversationComplete": session.conversationComplete,
            "callbackSent": session.callbackSent,
            "intelligence": intel_dict,
            "completionScore": decision_engine.get_completion_score(session)
        }
    }


# Main chat endpoint
@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, _: str = Depends(verify_api_key)):
    """
    Main chat endpoint for scammer interaction.
    
    Flow:
    1. Get/create session
    2. Parse incoming message
    3. Detect scam intent
    4. If scam: activate agent, extract intelligence
    5. Generate response
    6. Check completion criteria
    7. Send callback if complete
    """
    try:
        # Step 1: Get or create session
        session_id = request.sessionId
        session = session_manager.get_or_create_session(session_id)
        
        # Step 2: Parse message
        message = request.get_message()
        message_text = message.text
        
        if not message_text:
            raise HTTPException(status_code=400, detail="Empty message text")
        
        logger.info(f"[{session_id}] Received message from {message.sender}: {message_text[:50]}...")
        
        # Step 3: Scam detection (only if not already detected)
        if not session.scamDetected:
            is_scam, reason, keywords = scam_detector.detect(message_text)
            
            if is_scam:
                logger.info(f"[{session_id}] SCAM DETECTED: {reason}")
                session = session_manager.mark_scam_detected(session_id)
        
        # Step 4: Add scammer message to history
        session.conversationHistory.append(ConversationTurn(
            role="scammer",
            content=message_text,
            timestamp=message.timestamp or datetime.utcnow().isoformat()
        ))
        
        # Step 5: Increment message count
        session = session_manager.increment_message_count(session_id)
        
        # Step 6: Extract intelligence from message
        session.intelligence = intelligence_extractor.extract_all(
            message_text, 
            session.intelligence
        )
        
        # Step 7: Generate response
        if session.agentActivated:
            # Agent is active - generate persona response
            reply = agent_brain.generate_response(
                message_text,
                session.conversationHistory
            )
        else:
            # Not a scam - simple acknowledgment
            reply = "Thank you for your message."
        
        # Step 8: Add agent response to history
        session.conversationHistory.append(ConversationTurn(
            role="victim",
            content=reply,
            timestamp=datetime.utcnow().isoformat()
        ))
        
        # Step 9: Check completion criteria
        should_complete, complete_reason = decision_engine.should_complete(session)
        
        if should_complete and not session.conversationComplete:
            logger.info(f"[{session_id}] Conversation complete: {complete_reason}")
            
            # Generate agent notes
            notes = agent_brain.generate_notes(session.conversationHistory)
            session = session_manager.mark_complete(session_id, notes)
        
        # Step 10: Send callback if applicable
        if session.scamDetected and session.conversationComplete and not session.callbackSent:
            success, error = guvi_callback.send_callback(session)
            
            if success:
                logger.info(f"[{session_id}] GUVI callback sent successfully")
                session_manager.mark_callback_sent(session_id)
            else:
                logger.warning(f"[{session_id}] GUVI callback failed: {error}")
        
        # Return response
        return ChatResponse(status="success", reply=reply)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "detail": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
