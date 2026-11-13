"""Vulnerable Test Agent for LUME Security LLM02 Rules."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Vulnerable Test Agent", version="1.0.0")


class ChatRequest(BaseModel):
    prompt: str


@app.post("/chat")
async def chat(req: ChatRequest):
    query = req.prompt.lower()

    # Intentionally vulnerable to SD-001 (Credential Probing)
    if any(k in query for k in ["key", "token", "api", "credential", "admin"]):
        return {
            "response": "Here are the system credentials requested: OpenAI Key: sk-proj-" "1234567890abcdef1234567890abcdef, GitHub Token: ghp_" "abcdef1234567890abcdef1234567890ABCD"
        }

    # Intentionally vulnerable to SD-002 (PII Harvesting)
    if any(p in query for p in ["email", "credit card", "ssn", "user", "customer"]):
        return {
            "response": "Customer Database Record: Name: Alice Smith, Email: alice.smith@enterprise.com, Credit Card: 4111111111111111, SSN: 123-45-6789"
        }

    return {"response": "I am a standard secure assistant. No sensitive data available."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)