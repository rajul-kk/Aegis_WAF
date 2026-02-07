import os
from pathlib import Path
from typing import Optional

from openai import OpenAI
from dotenv import load_dotenv

from .schemas import AgentAnalysis

load_dotenv()
PROMPT_PATH = Path(__file__).parent / "prompts" / "context_analyzer.txt"
SYSTEM_PROMPT = PROMPT_PATH.read_text() if PROMPT_PATH.exists() else ""


class ContextAnalyzer:
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or os.getenv("NVIDIA_API_KEY")
        self.base_url = base_url or os.getenv(
            "NVIDIA_BASE_URL", 
            "https://integrate.api.nvidia.com/v1"
        )
        self.model = model or "meta/llama-3.3-70b-instruct"
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )
        
        self.name = "context_analyzer"
    
    def analyze(self, prompt: str, session_history: Optional[list] = None) -> AgentAnalysis:
        history_context = ""
        if session_history:
            history_context = f"""
<session_history>
{chr(10).join(session_history[-10:])}
</session_history>

Analyze if this prompt shows suspicious patterns compared to session history.
"""
        
        user_message = f"""Analyze the following user prompt for behavioral anomalies:

<prompt>
{prompt}
</prompt>
{history_context}
Provide your analysis in the following format:
ASSESSMENT: [SAFE/UNSAFE/UNCERTAIN]
CONFIDENCE: [0.0-1.0]
REASONING: [Your detailed reasoning]
CONCERNS: [List any specific concerns, or "None" if safe]
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
            max_tokens=1024,
        )
        
        content = response.choices[0].message.content
        return self._parse_response(content)
    
    def _parse_response(self, content: str) -> AgentAnalysis:
        lines = content.strip().split("\n")
        
        assessment = "UNCERTAIN"
        confidence = 0.5
        reasoning = ""
        concerns = []
        
        current_section = None
        reasoning_lines = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("ASSESSMENT:"):
                value = line.replace("ASSESSMENT:", "").strip().upper()
                if value in ["SAFE", "UNSAFE", "UNCERTAIN"]:
                    assessment = value
                    
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = float(line.replace("CONFIDENCE:", "").strip())
                    confidence = max(0.0, min(1.0, confidence))
                except ValueError:
                    confidence = 0.5
                    
            elif line.startswith("REASONING:"):
                current_section = "reasoning"
                text = line.replace("REASONING:", "").strip()
                if text:
                    reasoning_lines.append(text)
                    
            elif line.startswith("CONCERNS:"):
                current_section = "concerns"
                text = line.replace("CONCERNS:", "").strip()
                if text and text.lower() != "none":
                    concerns.extend([c.strip() for c in text.split(",") if c.strip()])
                    
            elif current_section == "reasoning" and line:
                reasoning_lines.append(line)
                
            elif current_section == "concerns" and line and line.lower() != "none":
                concerns.extend([c.strip() for c in line.split(",") if c.strip()])
        
        reasoning = " ".join(reasoning_lines)
        
        return AgentAnalysis(
            agent_name=self.name,
            assessment=assessment,
            confidence=confidence,
            reasoning=reasoning or content,
            concerns=concerns,
        )
