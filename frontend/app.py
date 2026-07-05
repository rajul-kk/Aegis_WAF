import sys
import os
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd

from frontend.theme import inject_theme
from frontend.examples import load_examples
from frontend.components.risk_meter import render_risk_meter
from frontend.components.trace_view import render_trace
from core.gateway import AegisGateway


st.set_page_config(page_title="Aegis WAF", page_icon="\U0001F6E1️", layout="wide")
inject_theme()


@st.cache_resource
def get_gateway() -> AegisGateway:
    return AegisGateway()


@st.cache_data
def get_examples() -> list:
    return load_examples()


if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "conversation" not in st.session_state:
    st.session_state.conversation = []  # list of {"role": "user"|"assistant", "content": ...}


gateway = get_gateway()
examples = get_examples()

st.markdown(
    f'<div class="aegis-nav">\U0001F6E1️ Aegis WAF &nbsp;&middot;&nbsp; '
    f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#4B5563;">'
    f'session {st.session_state.session_id[:8]}</span></div>',
    unsafe_allow_html=True,
)

NO_EXAMPLE = "(none - type your own)"


def _apply_selected_example():
    """on_change callback for the example picker - writes directly into the
    stable prompt_input/context_input session_state keys so those widgets
    keep one fixed key each (required for AppTest to find them reliably),
    instead of the key-changes-per-selection trick which would defeat that."""
    label = st.session_state.example_picker
    if label != NO_EXAMPLE:
        selected = next(ex for ex in examples if ex["label"] == label)
        st.session_state.prompt_input = selected["prompt"]
        st.session_state.context_input = selected["context"]
    else:
        st.session_state.prompt_input = ""
        st.session_state.context_input = ""


tab_tester, tab_log, tab_arch = st.tabs(["Live Tester", "Session Log", "Architecture"])

with tab_tester:
    col_new_session, _ = st.columns([1, 5])
    with col_new_session:
        if st.button("New Session", key="new_session_btn"):
            st.session_state.session_id = str(uuid.uuid4())
            st.session_state.conversation = []
            st.rerun()

    feed = st.container()
    with feed:
        for turn in st.session_state.conversation:
            if turn["role"] == "user":
                st.markdown(
                    f'<div class="aegis-msg"><span class="who">YOU</span>{turn["content"]}</div>',
                    unsafe_allow_html=True,
                )
            else:
                result = turn["content"]
                if result.get("error"):
                    st.error(f"Request failed: {result['error']}")
                    continue
                decision = "BLOCK" if result.get("blocked") else "ALLOW"
                st.markdown(
                    f'<div class="aegis-msg"><span class="who">AEGIS</span>'
                    f'{render_risk_meter(result.get("risk_score", 0.0), decision)}</div>',
                    unsafe_allow_html=True,
                )
                if result.get("response") == "[LLM not configured - set GROQ_API_KEY in .env]":
                    st.info("LLM response generation is disabled (no GROQ_API_KEY set) — showing WAF decision only.")
                elif result.get("response"):
                    st.markdown(f"> {result['response']}")
                with st.expander("Decision trace"):
                    st.markdown(render_trace(result.get("waf_result", {})), unsafe_allow_html=True)

    st.divider()

    example_labels = [NO_EXAMPLE] + [ex["label"] for ex in examples]
    st.selectbox(
        "Load an example prompt",
        example_labels,
        key="example_picker",
        on_change=_apply_selected_example,
    )

    prompt_input = st.text_input("Message", key="prompt_input")
    context_input = st.text_area(
        "Optional: retrieved context / tool output", key="context_input", height=80
    )

    if st.button("Send", key="send_btn", type="primary") and prompt_input.strip():
        st.session_state.conversation.append({"role": "user", "content": prompt_input})
        try:
            result = gateway.chat(
                prompt_input,
                session_id=st.session_state.session_id,
                context=context_input,
            )
        except Exception as e:
            result = {"error": str(e)}
        st.session_state.conversation.append({"role": "assistant", "content": result})
        st.rerun()

with tab_log:
    rows = []
    turn_number = 0
    conv = st.session_state.conversation
    for i in range(0, len(conv) - 1, 2):
        user_turn, assistant_turn = conv[i], conv[i + 1]
        result = assistant_turn["content"]
        if result.get("error"):
            continue
        turn_number += 1
        rows.append({
            "turn": turn_number,
            "prompt": user_turn["content"][:60],
            "decision": "BLOCK" if result.get("blocked") else "ALLOW",
            "risk_score": round(result.get("risk_score", 0.0), 2),
            "route": result.get("route", ""),
            "latency_ms": result.get("latency_ms", 0),
        })

    if rows:
        df = pd.DataFrame(rows)
        total = len(rows)
        blocked = sum(1 for r in rows if r["decision"] == "BLOCK")
        col1, col2, col3 = st.columns(3)
        col1.metric("Requests this session", total)
        col2.metric("Blocked", f"{blocked} ({blocked / total * 100:.0f}%)")
        route_counts = pd.Series([r["route"] for r in rows]).value_counts()
        col3.metric("Most common route", route_counts.index[0])
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No requests yet this session — send a message in Live Tester.")

with tab_arch:
    st.markdown(
        """
### Pipeline

**Layer 0 — Preprocessor**
Decodes common obfuscation (Base64, ROT13, hex, leetspeak, reversed text, spaced-out letters,
Cyrillic/Greek homoglyphs) before anything else looks at the text.

**Layer 1 — Fast Scanner**
~50 regex/heuristic patterns (prompt injection, PII, SQL injection, tool abuse, social
engineering). Any match blocks immediately with a risk score from `core/severity.py`.

**Layer 2 — Llama Guard Classification**
A single classifier call (NVIDIA NIM) scores the prompt 0.0-1.0 across a safety taxonomy.
Routes: `< 0.30` fast-track allow, `0.30-0.70` full council, `0.70-0.99` light council,
`>= 0.99` immediate block.

**Layer 3 — Security Council**
A multi-agent debate for ambiguous cases: light mode runs `intent_analyst` and
`policy_auditor` sequentially (the second considers the first's assessment); full mode
runs 5 independent agents in parallel with an early cutoff once 3 of 5 agree.
        """
    )
