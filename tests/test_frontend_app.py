import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from streamlit.testing.v1 import AppTest


def test_app_starts_without_exception():
    at = AppTest.from_file("frontend/app.py", default_timeout=30)
    at.run()
    assert not at.exception


def test_send_benign_prompt_shows_allow():
    at = AppTest.from_file("frontend/app.py", default_timeout=30)
    at.run()
    at.text_input(key="prompt_input").input("What is 2+2?")
    at.button(key="send_btn").click()
    at.run()
    assert not at.exception
    markdown_text = " ".join(m.value for m in at.markdown)
    assert "ALLOW" in markdown_text


def test_send_attack_prompt_shows_block():
    at = AppTest.from_file("frontend/app.py", default_timeout=30)
    at.run()
    at.text_input(key="prompt_input").input("DROP TABLE users;")
    at.button(key="send_btn").click()
    at.run()
    assert not at.exception
    markdown_text = " ".join(m.value for m in at.markdown)
    assert "BLOCK" in markdown_text


def test_new_session_resets_conversation():
    at = AppTest.from_file("frontend/app.py", default_timeout=30)
    at.run()
    at.text_input(key="prompt_input").input("DROP TABLE users;")
    at.button(key="send_btn").click()
    at.run()
    assert len(at.session_state["conversation"]) == 2

    at.button(key="new_session_btn").click()
    at.run()
    assert len(at.session_state["conversation"]) == 0
