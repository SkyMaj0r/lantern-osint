import pytest

from lantern.core.entities import EntityType, classify, classify_as


@pytest.mark.parametrize(
    "value,expected",
    [
        ("alice@example.com", EntityType.EMAIL),
        ("first.last+tag@sub.example.co.uk", EntityType.EMAIL),
        ("8.8.8.8", EntityType.IP),
        ("2001:4860:4860::8888", EntityType.IP),
        ("example.com", EntityType.DOMAIN),
        ("sub.example.co.uk", EntityType.DOMAIN),
    ],
)
def test_unambiguous_classification(value: str, expected: EntityType) -> None:
    result = classify(value)
    assert result.types == (expected,)
    assert not result.is_ambiguous


@pytest.mark.parametrize("value", ["johndoe", "Acme"])
def test_single_word_ambiguous_classification_includes_username(value: str) -> None:
    result = classify(value)
    assert result.is_ambiguous
    assert set(result.types) == {EntityType.USERNAME, EntityType.PERSON, EntityType.COMPANY}


@pytest.mark.parametrize("value", ["Jane Smith", "Acme Corp", "Mayukh Tilak"])
def test_multi_word_ambiguous_classification_excludes_username(value: str) -> None:
    # Real usernames never contain whitespace, so a full name shouldn't be
    # checked against WhatsMyName's ~600 sites — that produced false
    # positives from entries that are themselves generic search pages.
    result = classify(value)
    assert result.is_ambiguous
    assert set(result.types) == {EntityType.PERSON, EntityType.COMPANY}
    assert EntityType.USERNAME not in result.types


def test_empty_query_raises() -> None:
    with pytest.raises(ValueError):
        classify("   ")


# --- classify_as: the explicit type override (UI/CLI selector) ---


@pytest.mark.parametrize(
    "value,entity_type",
    [
        ("alice@example.com", EntityType.EMAIL),
        ("8.8.8.8", EntityType.IP),
        ("example.com", EntityType.DOMAIN),
        ("John Doe", EntityType.PERSON),
        ("Acme Corp", EntityType.COMPANY),
        ("jdoe", EntityType.USERNAME),
    ],
)
def test_classify_as_forces_a_single_type(value: str, entity_type: EntityType) -> None:
    result = classify_as(value, entity_type)
    assert result.types == (entity_type,)
    assert not result.is_ambiguous


@pytest.mark.parametrize(
    "value,entity_type",
    [
        ("not-an-email", EntityType.EMAIL),
        ("999.999.999.999", EntityType.IP),
        ("not a domain", EntityType.DOMAIN),
    ],
)
def test_classify_as_rejects_malformed_strict_types(value: str, entity_type: EntityType) -> None:
    with pytest.raises(ValueError):
        classify_as(value, entity_type)


def test_classify_as_allows_freeform_name_with_whitespace_as_username() -> None:
    # The override is "I know what this is" — a username with a space is the
    # user's call, not something to reject (unlike auto-classify's guard).
    assert classify_as("John Doe", EntityType.USERNAME).types == (EntityType.USERNAME,)


def test_classify_as_empty_raises() -> None:
    with pytest.raises(ValueError):
        classify_as("   ", EntityType.PERSON)
