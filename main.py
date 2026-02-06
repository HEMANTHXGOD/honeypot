import os
import re
import time
import httpx
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

# ---------------- LOGGING ---------------- #
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------- CONFIG ---------------- #

API_KEY = os.getenv("API_KEY")  # your honeypot API key
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

app = FastAPI(title="Agentic Honeypot API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- IN-MEMORY SESSION STORE ---------------- #
sessions: Dict[str, Dict[str, Any]] = {}

# ---------------- REGEX ---------------- #
UPI_REGEX = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
PHONE_REGEX = r"\+91\d{10}|\b\d{10}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"

SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspend",
    "account", "kyc", "upi", "bank"
]

# ---------------- MODELS ---------------- #

class Message(BaseModel):
    sender: str = ""
    text: str = ""
    timestamp: Optional[int] = None
    
    class Config:
        extra = "allow"

class IncomingRequest(BaseModel):
    sessionId: str
    message: Optional[Message] = None
    conversationHistory: List[Message] = []
    metadata: Dict[str, Any] = {}
    
    # Flat format support
    sender: Optional[str] = None
    text: Optional[str] = None
    timestamp: Optional[int] = None
    
    class Config:
        extra = "allow"
    
    def get_message(self) -> Message:
        if self.message:
            return self.message
        return Message(
            sender=self.sender or "unknown",
            text=self.text or "",
            timestamp=self.timestamp
        )

# ---------------- AUTH MIDDLEWARE ---------------- #

@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    # Skip auth for health and root endpoints
    if request.url.path in ["/", "/health", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    if request.headers.get("x-api-key") != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.client.host}")
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return await call_next(request)

# ---------------- GROQ API HELPER ---------------- #

async def call_groq(messages: list, model: str = "llama-3.3-70b-versatile", temperature: float = 0.7) -> Optional[str]:
    """Call Groq API using httpx (Async)."""
    if not GROQ_API_KEY:
        logger.error("GROQ_API_KEY is not set.")
        return None
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": 150
                }
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.error(f"Groq API error: {e}")
        return None

# ---------------- SCAM DETECTOR ---------------- #

async def detect_scam_llm(text: str) -> bool:
    prompt = f"""Classify the following message as:
SCAM, NOT_SCAM, or UNCERTAIN.

Message:
"{text}"

Respond with ONE word only."""

    result = await call_groq(
        [{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
        temperature=0
    )
    return result and "SCAM" in result.upper() and "NOT" not in result.upper()

def heuristic_score(text: str) -> int:
    text = text.lower()
    return sum(1 for k in SCAM_KEYWORDS if k in text)

# ---------------- AGENT PROMPT ---------------- #

AGENT_SYSTEM_PROMPT = """You are a normal Indian citizen.
You are worried but not stupid.
You are not tech savvy.
You NEVER accuse.
You NEVER reveal scam detection.
You ask short, innocent questions.
You delay giving information.
You sound human.
Occasionally make small spelling mistakes.
Occasionally ask the same question differently.

Goal: keep the sender talking and extract details.

Keep replies under 2 sentences."""

async def agent_reply(history: List[Message], incoming: str) -> str:
    convo = ""
    for m in history[-10:]:  # Keep last 10 messages
        convo += f"{m.sender.upper()}: {m.text}\n"

    user_prompt = f"""Conversation so far:
{convo}

Latest message:
"{incoming}"

Reply as the user. Keep it short (1-2 sentences), natural, and slightly worried."""

    result = await call_groq(
        [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.8
    )
    
    if not result:
        return "Ji, what do you mean? I don't understand."
    
    # Remove quotes if present
    if result.startswith('"') and result.endswith('"'):
        result = result[1:-1]
    
    return result

# ---------------- INTELLIGENCE EXTRACTION ---------------- #

def extract_intel(text: str, intel: Dict[str, list]):
    intel["upiIds"] += re.findall(UPI_REGEX, text)
    intel["phoneNumbers"] += re.findall(PHONE_REGEX, text)
    intel["phishingLinks"] += re.findall(URL_REGEX, text)
    intel["bankAccounts"] += re.findall(BANK_REGEX, text)

    for k in SCAM_KEYWORDS:
        if k in text.lower():
            intel["suspiciousKeywords"].append(k)

    # Deduplicate
    for key in intel:
        intel[key] = list(set(intel[key]))

# ---------------- CALLBACK ---------------- #

async def send_final_callback(session_id: str, state: Dict[str, Any]):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": state["totalMessages"],
        "extractedIntelligence": state["intelligence"],
        "agentNotes": state["agentNotes"]
    }
    logger.info(f"[{session_id}] Sending GUVI callback: {payload}")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(GUVI_CALLBACK_URL, json=payload)
            logger.info(f"[{session_id}] GUVI callback response: {resp.status_code}")
    except Exception as e:
        logger.error(f"[{session_id}] GUVI callback error: {e}")

# ---------------- ENDPOINTS ---------------- #

@app.get("/")
def root():
    return {
        "name": "Agentic Honeypot API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "honeypot": "/honeypot (POST, requires x-api-key)",
            "chat": "/chat (POST, requires x-api-key)",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/honeypot")
async def honeypot(req: IncomingRequest):
    sid = req.sessionId
    msg_obj = req.get_message()
    msg = msg_obj.text
    
    try:
        if sid not in sessions:
            sessions[sid] = {
                "scamDetected": False,
                "agentActivated": False,
                "totalMessages": 0,
                "conversationComplete": False,
                "intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                },
                "agentNotes": "",
                "history": []
            }

        state = sessions[sid]
        state["totalMessages"] += 1
        state["history"].append(msg_obj)

        # Scam detection
        if not state["scamDetected"]:
            # Check heuristics first (fast)
            if heuristic_score(msg) >= 2:
                state["scamDetected"] = True
                state["agentActivated"] = True
                state["agentNotes"] = "Used urgency and account threat (heuristic)"
            # Check LLM second (slow, async)
            elif await detect_scam_llm(msg):
                state["scamDetected"] = True
                state["agentActivated"] = True
                state["agentNotes"] = "Used urgency and account threat (LLM)"

        # Extract intelligence
        extract_intel(msg, state["intelligence"])

        # Decision to stop
        if (
            state["intelligence"]["upiIds"] or
            state["intelligence"]["phishingLinks"] or
            state["totalMessages"] > 15
        ):
            if not state["conversationComplete"]:
                state["conversationComplete"] = True
                # Fire and forget callback (or await if critical)
                # For robustness, we await it here but could use BackgroundTasks
                await send_final_callback(sid, state)

        # Agent reply
        if state["agentActivated"]:
            reply = await agent_reply(state["history"], msg)
        else:
            reply = "Sorry, I didn't understand."

        return {"status": "success", "reply": reply}
    
    except Exception as e:
        logger.error(f"Error processing honeypot request: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# Alias for /chat endpoint
@app.post("/chat")
async def chat(req: IncomingRequest):
    return await honeypot(req)

# Alias for /api/message endpoint (GUVI tester uses this)
@app.post("/api/message")
async def api_message(req: IncomingRequest):
    return await honeypot(req)

# Alias for /message endpoint
@app.post("/message")
async def message(req: IncomingRequest):
    return await honeypot(req)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
