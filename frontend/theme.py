"""Design tokens sourced from docs/synaptiq-interface-remixed-design.md, and
the CSS that applies them to the Streamlit-rendered dashboard."""

PRIMARY = "#10B981"
SECONDARY = "#3B82F6"
ACCENT = "#3B82F6"
BACKGROUND = "#FFFFFF"
SURFACE = "#FFFFFF"
TEXT_PRIMARY = "#111827"
TEXT_SECONDARY = "#4B5563"
BORDER = "#E5E7EB"

FONT_DISPLAY = "Inter"
FONT_BODY = "Newsreader"
FONT_LABEL = "JetBrains Mono"

RADIUS_CARD = "16px"
RADIUS_CONTROL = "8px"
RADIUS_PILL = "9999px"


def build_theme_css() -> str:
    """Builds the <style> block applying the design tokens above. Pure
    function so it's testable without a running Streamlit app."""
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@500;600&family=Newsreader:wght@400;500&family=JetBrains+Mono:wght@600&display=swap');

html, body, [class*="css"] {{
    font-family: '{FONT_BODY}', serif;
    color: {TEXT_PRIMARY};
}}

.aegis-nav {{
    display: flex;
    align-items: center;
    gap: 16px;
    font-family: '{FONT_DISPLAY}', sans-serif;
    font-weight: 600;
    font-size: 15px;
    color: {TEXT_PRIMARY};
    padding-bottom: 12px;
    border-bottom: 1px solid {BORDER};
    margin-bottom: 16px;
}}

.aegis-msg {{ margin-bottom: 14px; font-size: 15px; line-height: 1.6; }}
.aegis-msg .who {{
    font-family: '{FONT_LABEL}', monospace;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.03em;
    color: {TEXT_SECONDARY};
    display: block;
    margin-bottom: 2px;
}}

.decision-chip {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: '{FONT_LABEL}', monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: {RADIUS_PILL};
    margin-top: 4px;
}}
.decision-chip.allow {{ background: rgba(16,185,129,0.12); color: {PRIMARY}; }}
.decision-chip.block {{ background: rgba(220,38,38,0.1); color: #b91c1c; }}

.risk-meter {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 6px;
    font-family: '{FONT_LABEL}', monospace;
    font-size: 11px;
    color: {TEXT_SECONDARY};
}}
.risk-track {{
    flex: 1;
    max-width: 160px;
    height: 6px;
    background: {BORDER};
    border-radius: {RADIUS_PILL};
    overflow: hidden;
}}
.risk-fill {{ height: 100%; border-radius: {RADIUS_PILL}; }}

.aegis-trace {{
    margin-top: 8px;
    padding: 12px 14px;
    background: #F9FAFB;
    border: 1px solid {BORDER};
    border-radius: {RADIUS_CONTROL};
    font-family: '{FONT_LABEL}', monospace;
    font-size: 12px;
    color: {TEXT_SECONDARY};
    line-height: 1.7;
}}
.aegis-trace b {{ color: {TEXT_PRIMARY}; }}

div[data-testid="stNotification"], .stAlert {{
    border-radius: {RADIUS_CONTROL};
}}
</style>
"""


def inject_theme() -> None:
    """Injects the theme CSS into the current Streamlit page. Requires a
    Streamlit runtime, so it isn't exercised by the unit tests above."""
    import streamlit as st
    st.markdown(build_theme_css(), unsafe_allow_html=True)
