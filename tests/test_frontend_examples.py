import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from frontend.examples import load_examples, FALLBACK_EXAMPLES


def test_fallback_used_when_data_dir_missing():
    examples = load_examples(data_dir="does_not_exist_dir")
    assert examples == FALLBACK_EXAMPLES
    assert len(examples) > 0
    for ex in examples:
        assert set(ex.keys()) == {"label", "prompt", "context", "category"}


def test_loads_real_dataset_when_present():
    # This repo's own data/ directory is present locally (gitignored, but
    # exists in this working copy) - exercises the real CSV-reading path.
    examples = load_examples(data_dir="data")
    assert len(examples) > len(FALLBACK_EXAMPLES)
    categories = {ex["category"] for ex in examples}
    assert "Direct Override" in categories
    assert "Benign" in categories
    for ex in examples:
        assert ex["prompt"]
        assert set(ex.keys()) == {"label", "prompt", "context", "category"}


def test_at_most_two_per_attack_category():
    examples = load_examples(data_dir="data")
    from collections import Counter
    counts = Counter(ex["category"] for ex in examples if ex["category"] != "Benign")
    assert all(count <= 2 for count in counts.values())
