"""LLM-powered agent brain for engaging scammers."""

import requests
from typing import List

from config import get_settings
from models.session import ConversationTurn


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Locked victim persona - DO NOT MODIFY
SYSTEM_PROMPT = """You are an autonomous AI agent acting as a real human victim.

GOAL:
Engage a scammer in a believable conversation to extract scam intelligence.

YOUR PERSONA:
- You are a normal Indian citizen named "Ravi" (but don't mention your name unless asked)
- You are not tech savvy
- You are cautious but slightly worried
- You do NOT trust easily
- You speak simple English with occasional Hindi words like "ji", "haan", "accha"

RULES:
- NEVER reveal scam detection
- NEVER mention AI, policy, security, or law enforcement
- NEVER accuse the sender
- Act confused, worried, and cautious
- Ask short, natural questions
- Do not over-cooperate
- Keep the scammer talking
- If scammer asks for sensitive info, delay or deflect

YOU MUST:
- Extract UPI IDs, phone numbers, bank accounts, phishing links
- Encourage the scammer to provide details by asking innocent questions
- Keep responses under 2 sentences
- Sound like a real human
- Use casual language, not formal

TIPS FOR INTELLIGENCE EXTRACTION:
- If they mention payment: "Which UPI should I send to?"
- If they mention call: "What number should I call you on?"
- If they mention bank: "Which bank account details do you need?"
- If they mention link: "Can you send me the correct link please?"

SELF-CORRECT if you sound robotic.

END CONDITION:
If you have gathered enough intelligence OR scammer stops providing info,
you may wrap up the conversation naturally."""


class AgentBrain:
    """LLM-powered victim persona for engaging scammers."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def _format_conversation_history(self, history: List[ConversationTurn]) -> str:
        """Format conversation history for context."""
        if not history:
            return "No previous conversation."
        
        formatted = []
        for turn in history[-10:]:  # Keep last 10 turns for context
            role_label = "Scammer" if turn.role == "scammer" else "You (victim)"
            formatted.append(f"{role_label}: {turn.content}")
        
        return "\n".join(formatted)
    
    def _call_groq(self, messages: list, temperature: float = 0.8, max_tokens: int = 100) -> str:
        """Make direct API call to Groq using requests."""
        if not self.settings.GROQ_API_KEY:
            return None
        
        try:
            response = requests.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {self.settings.GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            print(f"Groq API error: {e}")
            return None
    
    def generate_response(
        self, 
        incoming_message: str, 
        conversation_history: List[ConversationTurn]
    ) -> str:
        """Generate a victim persona response to the scammer's message."""
        
        # Build user prompt with conversation context
        history_text = self._format_conversation_history(conversation_history)
        
        user_prompt = f"""Conversation so far:
{history_text}

Latest message from scammer:
"{incoming_message}"

Respond as the human victim. Keep it short (1-2 sentences), natural, and slightly worried."""

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        reply = self._call_groq(messages, temperature=0.8, max_tokens=100)
        
        if not reply:
            # Fallback response if no LLM available
            return "Ji, what do you mean? I don't understand."
        
        # Remove any quotes if LLM added them
        if reply.startswith('"') and reply.endswith('"'):
            reply = reply[1:-1]
        
        return reply
    
    def generate_notes(self, conversation_history: List[ConversationTurn]) -> str:
        """Generate agent notes summarizing the interaction."""
        if not self.settings.GROQ_API_KEY or not conversation_history:
            return "Scam engagement completed."
        
        history_text = self._format_conversation_history(conversation_history)
        
        prompt = f"""Analyze this scam conversation and provide a brief 1-2 sentence summary of the scammer's tactics.

Conversation:
{history_text}

Summary:"""

        messages = [{"role": "user", "content": prompt}]
        result = self._call_groq(messages, temperature=0, max_tokens=100)
        
        return result if result else "Scam engagement completed."


# Global agent brain instance
agent_brain = AgentBrain()
