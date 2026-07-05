import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from frontend.components.risk_meter import render_risk_meter


def test_render_risk_meter_allow():
    html = render_risk_meter(0.02, "ALLOW")
    assert "decision-chip allow" in html
    assert "ALLOW" in html
    assert "0.02" in html


def test_render_risk_meter_block():
    html = render_risk_meter(1.0, "BLOCK")
    assert "decision-chip block" in html
    assert "BLOCK" in html
    assert "1.00" in html


def test_render_risk_meter_clamps_percentage():
    html = render_risk_meter(1.5, "BLOCK")
    assert "width:100%" in html
    html_low = render_risk_meter(-0.5, "ALLOW")
    assert "width:0%" in html_low
