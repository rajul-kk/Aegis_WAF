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


def preprocess_prompt(prompt: str) -> tuple[str, list[str]]:
    decoded_versions = []
    decodings_applied = []
    
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
    
    if decoded_versions:
        preprocessed = "\n".join(decoded_versions) + f"\n\n[ORIGINAL PROMPT]: {prompt}"
    else:
        preprocessed = prompt
    
    return preprocessed, decodings_applied
