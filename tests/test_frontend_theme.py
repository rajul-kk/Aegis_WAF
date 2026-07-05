import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from frontend.theme import build_theme_css, PRIMARY, FONT_BODY, RADIUS_CARD


def test_build_theme_css_contains_tokens():
    css = build_theme_css()
    assert PRIMARY in css
    assert FONT_BODY in css
    assert RADIUS_CARD in css
    assert "<style>" in css and "</style>" in css


def test_theme_tokens_match_design_source():
    assert PRIMARY == "#10B981"
    assert FONT_BODY == "Newsreader"
    assert RADIUS_CARD == "16px"
