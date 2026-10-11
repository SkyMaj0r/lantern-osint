from __future__ import annotations

from lantern.core.names import username_variants


def test_single_token_returns_itself() -> None:
    assert username_variants("johndoe") == ["johndoe"]


def test_full_name_generates_ordered_handle_candidates() -> None:
    variants = username_variants("John Doe")
    assert variants[0] == "johndoe"
    for expected in ("john.doe", "john_doe", "john-doe", "jdoe", "johnd", "doejohn", "doe.john"):
        assert expected in variants


def test_variants_are_deduped() -> None:
    assert len(username_variants("John Doe")) == len(set(username_variants("John Doe")))


def test_accents_and_punctuation_are_normalized() -> None:
    variants = username_variants("Jöhn O'Doe")
    assert "johndoe" in variants
    assert all(c.isalnum() or c in "._-" for v in variants for c in v)


def test_three_token_name_adds_full_concat() -> None:
    variants = username_variants("John Michael Doe")
    assert "johndoe" in variants  # first + last
    assert "johnmichaeldoe" in variants  # all tokens


def test_limit_trims_the_tail() -> None:
    assert username_variants("John Doe", limit=3) == ["johndoe", "john.doe", "john_doe"]


def test_empty_or_symbol_only_name_returns_empty() -> None:
    assert username_variants("   ") == []
    assert username_variants("!!!") == []
