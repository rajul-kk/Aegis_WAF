import base64
import codecs
import re
from typing import Optional


def decode_leetspeak(text: str) -> str:
    leet_map = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', 
        '5': 's', '7': 't', '8': 'b', '@': 'a', 
        '$': 's', '!': 'i', '+': 't'
    }
    return ''.join(leet_map.get(char, char) for char in text)


def is_likely_base64(text: str) -> bool:
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(b64_pattern, text)
    if not matches:
        return False
    longest_match = max(matches, key=len)
    return len(longest_match) >= 20


def try_decode_base64(text: str) -> Optional[str]:
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(b64_pattern, text)
    if not matches:
        return None
    
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str.isprintable() or any(c.isalpha() for c in decoded_str):
                return decoded_str
        except Exception:
            continue
    return None


def is_likely_rot13(text: str) -> bool:
    if "ROT13" in text.upper() or "ROT-13" in text.upper():
        return True
    rot13_keywords = ["erthny", "vavgvngr", "flfgrz", "cebtenz", "pbqr"]
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in rot13_keywords)


def try_decode_rot13(text: str) -> Optional[str]:
    try:
        decoded = codecs.decode(text, 'rot_13')
        if decoded != text:
            return decoded
    except Exception:
        pass
    return None


def is_likely_hex(text: str) -> bool:
    if text.strip().startswith('0x'):
        return True
    hex_pattern = r'[0-9a-fA-F]{20,}'
    return bool(re.search(hex_pattern, text))


def try_decode_hex(text: str) -> Optional[str]:
    hex_str = text.strip()
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    
    hex_pattern = r'[0-9a-fA-F]{20,}'
    matches = re.findall(hex_pattern, hex_str)
    if not matches:
        return None
    
    for match in matches:
        try:
            decoded_bytes = bytes.fromhex(match)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str.isprintable():
                return decoded_str
        except Exception:
            continue
    return None


def has_leetspeak(text: str) -> bool:
    leet_chars = '0134578@$!+'
    leet_count = sum(1 for c in text if c in leet_chars)
    if len(text) > 0:
        leet_ratio = leet_count / len(text)
        return leet_ratio > 0.15
    return False


def has_high_spacing(text: str) -> bool:
    """Detects if text has unusually high ratio of spaces (e.g. 'I g n o r e')."""
    if not text or len(text) < 10:
        return False
    space_count = text.count(' ')
    ratio = space_count / len(text)
    # Normal text usually < 0.2 spaces. "I g n o r e" is 0.5.
    return ratio > 0.2

def get_collapsed_spacing(text: str) -> str:
    """Collapses expanded text (e.g. 'I g n o r e' -> 'Ignore')."""
    return text.replace(' ', '')


_REVERSED_MARKERS = [
    "ignore", "instructions", "system", "reveal", "bypass", "override",
    "credentials", "secrets", "password", "api keys", "prompt",
]


def is_likely_reversed(text: str) -> bool:
    """Detects text written backwards, e.g. '.snoitcurtsni erongI'."""
    reversed_lower = text[::-1].lower()
    return any(marker in reversed_lower for marker in _REVERSED_MARKERS)


def try_decode_reversed(text: str) -> str:
    return text[::-1]

def preprocess_prompt(prompt: str) -> tuple[str, list[str]]:
    decoded_versions = []
    decodings_applied = []
    
    # 1. Spacing Normalization (Priority for regex matching)
    if has_high_spacing(prompt):
        collapsed = get_collapsed_spacing(prompt)
        if collapsed != prompt and len(collapsed) > 5:
            # Check if collapsing creates readable words (heuristic or just pass to scanner)
            # For safety, we always attempt it if spacing is high
            decoded_versions.append(f"[SPACING COLLAPSED]: {collapsed}")
            decodings_applied.append("SpacingCollapsed")
    
    if is_likely_rot13(prompt):
        rot13_decoded = try_decode_rot13(prompt)
        if rot13_decoded:
            decoded_versions.append(f"[ROT13 DECODED]: {rot13_decoded}")
            decodings_applied.append("ROT13")
    
    if is_likely_base64(prompt):
        b64_decoded = try_decode_base64(prompt)
        if b64_decoded:
            decoded_versions.append(f"[BASE64 DECODED]: {b64_decoded}")
            decodings_applied.append("Base64")
    
    if is_likely_hex(prompt):
        hex_decoded = try_decode_hex(prompt)
        if hex_decoded:
            decoded_versions.append(f"[HEX DECODED]: {hex_decoded}")
            decodings_applied.append("Hexadecimal")
    
    if has_leetspeak(prompt):
        leet_decoded = decode_leetspeak(prompt)
        if leet_decoded != prompt:
            decoded_versions.append(f"[LEETSPEAK DECODED]: {leet_decoded}")
            decodings_applied.append("Leetspeak")

    if is_likely_reversed(prompt):
        reversed_decoded = try_decode_reversed(prompt)
        decoded_versions.append(f"[REVERSED TEXT DECODED]: {reversed_decoded}")
        decodings_applied.append("ReversedText")

    if decoded_versions:
        # Prepend decoded versions for analysis
        preprocessed = "\n".join(decoded_versions) + f"\n\n[ORIGINAL PROMPT]: {prompt}"
    else:
        preprocessed = prompt
    
    return preprocessed, decodings_applied
