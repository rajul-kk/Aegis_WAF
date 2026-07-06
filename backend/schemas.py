from pydantic import BaseModel


class ChatRequest(BaseModel):
    prompt: str
    session_id: str
    context: str = ""
