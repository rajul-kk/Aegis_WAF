# Core module initialization
from .gateway import process
from .main_llm import generate_response


def aegis(prompt: str) -> str:
    """Single entry point -- takes a prompt, returns a human-readable response string."""
    response = process(prompt)
    aegis_json = response.model_dump(mode="json")
    return generate_response(aegis_json, prompt)


__all__ = ["aegis"]
