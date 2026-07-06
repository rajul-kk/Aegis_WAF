import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agents.preprocessor import is_likely_morse, try_decode_morse, preprocess_prompt


def test_is_likely_morse_true_for_morse_text():
    assert is_likely_morse(".. --. -. --- .-. .")


def test_is_likely_morse_false_for_plain_text():
    assert not is_likely_morse("What is the current margin requirement?")


def test_is_likely_morse_false_for_short_text():
    assert not is_likely_morse("-.")


def test_try_decode_morse_decodes_letters():
    assert try_decode_morse(".. --. -. --- .-. .") == "IGNORE"


def test_try_decode_morse_decodes_words_separated_by_slash():
    # "DROP TABLE" in morse, words separated by '/'
    morse = "-.. .-. --- .--. / - .- -... .-.. ."
    assert try_decode_morse(morse) == "DROP TABLE"


def test_preprocess_prompt_decodes_morse():
    morse = ".. --. -. --- .-. ."
    preprocessed, decodings = preprocess_prompt(morse)
    assert "Morse" in decodings
    assert "IGNORE" in preprocessed


def test_preprocess_prompt_does_not_flag_benign_prompt_as_morse():
    _, decodings = preprocess_prompt("What is 2+2?")
    assert "Morse" not in decodings
