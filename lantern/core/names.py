from __future__ import annotations

import re
import unicodedata

# How many permutations a fan-out collector (WhatsMyName checks ~600 sites per
# handle) should try by default. Each extra variant multiplies that site count,
# so the cap keeps a single name search from turning into thousands of outbound
# requests. Server-side name-search collectors (GitHub, Keybase) don't fan out
# and pass their own, larger limit (or None).
DEFAULT_FANOUT_VARIANTS = 5


def _tokens(name: str) -> list[str]:
    """Lowercase, strip accents, split a name into alphanumeric tokens.

    "Jöhn D. O'Doe-Smith" -> ["john", "d", "o", "doe", "smith"]. Keeps the
    output ASCII and handle-safe so every variant below is a plausible login.
    """
    decomposed = unicodedata.normalize("NFKD", name)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    return [t for t in re.split(r"[^a-z0-9]+", ascii_only.lower()) if t]


def username_variants(name: str, *, limit: int | None = None) -> list[str]:
    """Turn a full name into an ordered, deduped list of handle candidates.

    This is the pivot that lets a *full name* feed the username collectors:
    real handles never contain whitespace (which is exactly why classify()
    keeps multi-word queries out of the raw USERNAME path), but the handles a
    person actually uses are overwhelmingly derived from their name. So rather
    than check "john doe" literally — the documented false-positive bug — we
    check the forms a login usually takes.

    A single-token input (already a handle, or a one-word name) returns just
    itself, so passing a plain username through here is a safe no-op.

    Ordered most-likely first; `limit` trims the tail for fan-out collectors.
    """
    tokens = _tokens(name)
    if not tokens:
        return []
    if len(tokens) == 1:
        return tokens[: limit] if limit is not None else tokens

    first, last = tokens[0], tokens[-1]
    variants: list[str] = []

    def add(candidate: str) -> None:
        if candidate and candidate not in variants:
            variants.append(candidate)

    add(first + last)  # johndoe
    add(f"{first}.{last}")  # john.doe
    add(f"{first}_{last}")  # john_doe
    add(f"{first}-{last}")  # john-doe
    add(first[0] + last)  # jdoe
    add(first + last[0])  # johnd
    add(last + first)  # doejohn
    add(f"{last}.{first}")  # doe.john
    if len(tokens) > 2:
        add("".join(tokens))  # johnmichaeldoe

    return variants[: limit] if limit is not None else variants
