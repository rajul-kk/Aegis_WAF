import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.severity import detect_adversarial_fatigue


def test_no_fatigue_on_empty_history():
    assert not detect_adversarial_fatigue([])


def test_no_fatigue_when_all_low_risk():
    assert not detect_adversarial_fatigue([0.0, 0.1, 0.05, 0.0])


def test_no_fatigue_with_only_two_elevated_hits():
    # Below the default min_hits=3 threshold.
    assert not detect_adversarial_fatigue([0.4, 0.5, 0.1, 0.0])


def test_fatigue_detected_with_three_elevated_hits():
    assert detect_adversarial_fatigue([0.4, 0.1, 0.5, 0.0, 0.6])


def test_fatigue_only_considers_the_most_recent_window():
    # 3 elevated hits, but they're outside the most recent 5-entry window.
    old_elevated = [0.5, 0.6, 0.7]
    recent_low = [0.0, 0.1, 0.0, 0.0, 0.1]
    assert not detect_adversarial_fatigue(old_elevated + recent_low)


def test_custom_threshold_and_min_hits():
    assert detect_adversarial_fatigue([0.2, 0.25, 0.2], threshold=0.15, min_hits=3)
    assert not detect_adversarial_fatigue([0.2, 0.25, 0.2], threshold=0.3, min_hits=3)
