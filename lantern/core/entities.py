from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class EntityType(str, Enum):
    EMAIL = "email"
    IP = "ip"
    DOMAIN = "domain"
    USERNAME = "username"
    PERSON = "person"
    COMPANY = "company"


@dataclass(frozen=True)
class Classification:
    value: str
    types: tuple[EntityType, ...]

    @property
    def is_ambiguous(self) -> bool:
        return len(self.types) > 1


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Hostname label: 1-63 chars, alphanumeric/hyphen, no leading/trailing hyphen.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_TLD_RE = re.compile(r"^[a-z]{2,63}$", re.IGNORECASE)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    if value.count(".") == 0:
        return False
    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    *host_labels, tld = labels
    if not _TLD_RE.match(tld):
        return False
    return all(_LABEL_RE.match(label) for label in host_labels)


def classify(raw: str) -> Classification:
    """Classify a raw query string into one or more candidate EntityTypes.

    EMAIL, IP, and DOMAIN are unambiguous pattern matches. Anything else is
    ambiguous between USERNAME, PERSON, and COMPANY — per the brief, we run
    it against every applicable module rather than guessing a single type.

    USERNAME is dropped from that ambiguous set when the query contains
    whitespace: real usernames never do, so "Mayukh Tilak" is almost
    certainly a full name, not a handle. Without this, WhatsMyName was
    checking multi-word names against ~600 sites and returning false
    positives from entries that are themselves generic search pages
    (they "match" nearly any input) — confidently labeled 80%, misleading
    for something that was never a real hit.
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty query")

    if "@" in value and _EMAIL_RE.match(value):
        return Classification(value, (EntityType.EMAIL,))

    if _is_ip_literal(value):
        return Classification(value, (EntityType.IP,))

    if _is_domain(value):
        return Classification(value, (EntityType.DOMAIN,))

    if re.search(r"\s", value):
        return Classification(value, (EntityType.PERSON, EntityType.COMPANY))

    return Classification(value, (EntityType.USERNAME, EntityType.PERSON, EntityType.COMPANY))


# Which explicit overrides get a format check, and how to phrase a rejection.
# USERNAME/PERSON/COMPANY are free-form (any non-empty string is plausible),
# so they're validated only for emptiness.
_OVERRIDE_VALIDATORS = {
    EntityType.EMAIL: (lambda v: bool(_EMAIL_RE.match(v)), "a valid email address"),
    EntityType.IP: (_is_ip_literal, "a valid IP address"),
    EntityType.DOMAIN: (_is_domain, "a valid domain name"),
}


def classify_as(raw: str, entity_type: EntityType) -> Classification:
    """Build a single-type Classification from an explicit user override,
    bypassing auto-detection.

    This is the "I already know what this is" path (the UI/CLI type selector).
    It still runs a cheap sanity check for the strict types — picking IP but
    typing a name is almost always a slip, and firing the IP collectors at it
    wastes a run — but leaves USERNAME/PERSON/COMPANY free-form, since those
    are genuinely ambiguous human input with no format to validate against.
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty query")

    check = _OVERRIDE_VALIDATORS.get(entity_type)
    if check is not None:
        is_valid, expected = check
        if not is_valid(value):
            raise ValueError(f"{value!r} is not {expected}")

    return Classification(value, (entity_type,))
