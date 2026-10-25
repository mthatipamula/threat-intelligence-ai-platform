"""Building STIX 2.1 objects the same way for every collector.

Indicators, vulnerabilities and relationships get deterministic IDs (UUIDv5 of their natural key), so collecting the
same feed twice updates objects instead of duplicating them. Every object we create carries `created_by_ref` (the
source's Identity) and an external reference URL: that provenance is what later lets the AI cite where a fact came from.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import stix2

NAMESPACE = uuid.UUID("6f1d3c2e-5b8a-4e0f-9c7d-2a1b3c4d5e6f")

# One Identity per source, so `created_by_ref` says where each object came from.
SOURCES: dict[str, dict[str, str]] = {
    "mitre-attack": {"name": "MITRE ATT&CK", "url": "https://attack.mitre.org"},
    "cisa-kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    "ofac": {
        "name": "US Treasury OFAC SDN list (digital currency addresses)",
        "url": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses",
    },
    "threatfox": {"name": "abuse.ch ThreatFox", "url": "https://threatfox.abuse.ch"},
    "lookalike": {"name": "Lookalike domain discovery (DNS)", "url": "https://datatracker.ietf.org/doc/html/rfc1035"},
    "ct-watcher": {"name": "Certificate Transparency watcher", "url": "https://datatracker.ietf.org/doc/html/rfc6962"},
}

# STIX patterns for the observable types we produce. Crypto wallets have no standard STIX observable,
# so they use a custom object type (allowed by the spec with the x- prefix).
PATTERNS = {
    "domain-name": "[domain-name:value = '{v}']",
    "ipv4-addr": "[ipv4-addr:value = '{v}']",
    "url": "[url:value = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "crypto-wallet": "[x-crypto-wallet:address = '{v}']",
}


def deterministic_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(NAMESPACE, f'{stix_type}:{key}')}"


def now() -> datetime:
    return datetime.now(UTC)


def identity(source: str) -> stix2.Identity:
    meta = SOURCES[source]
    return stix2.Identity(
        id=deterministic_id("identity", source),
        name=meta["name"],
        identity_class="organization",
        created=datetime(2026, 1, 1, tzinfo=UTC),
        modified=datetime(2026, 1, 1, tzinfo=UTC),
        external_references=[{"source_name": source, "url": meta["url"]}],
    )


def indicator(
    source: str,
    observable_type: str,
    value: str,
    *,
    name: str,
    description: str,
    indicator_types: list[str],
    labels: list[str] | None = None,
    confidence: int | None = None,
    valid_from: datetime | None = None,
    reference_url: str | None = None,
    extra: dict[str, Any] | None = None,
) -> stix2.Indicator:
    """An Indicator for one observable value, with the value also kept in x_tip_observable for fast exact matching."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    refs = [{"source_name": source, "url": reference_url or SOURCES[source]["url"]}]
    return stix2.Indicator(
        id=deterministic_id("indicator", f"{observable_type}:{value.lower()}"),
        name=name,
        description=description,
        pattern=PATTERNS[observable_type].format(v=escaped),
        pattern_type="stix",
        indicator_types=indicator_types,
        labels=labels or [],
        confidence=confidence,
        valid_from=valid_from or now(),
        created_by_ref=identity(source).id,
        external_references=refs,
        x_tip_observable={"type": observable_type, "value": value},
        **(extra or {}),
        allow_custom=True,
    )


def relationship(
    source: str, source_ref: str, relationship_type: str, target_ref: str, **kwargs: Any
) -> stix2.Relationship:
    return stix2.Relationship(
        id=deterministic_id("relationship", f"{source_ref}|{relationship_type}|{target_ref}"),
        source_ref=source_ref,
        relationship_type=relationship_type,
        target_ref=target_ref,
        created_by_ref=identity(source).id,
        **kwargs,
    )


def to_dict(obj: Any) -> dict[str, Any]:
    """stix2 objects -> plain JSON-ready dicts (ATT&CK objects are already dicts)."""
    if isinstance(obj, dict):
        return obj
    import json

    return json.loads(obj.serialize())
