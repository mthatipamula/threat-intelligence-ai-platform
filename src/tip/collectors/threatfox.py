"""abuse.ch ThreatFox - fresh malicious domains, IPs, URLs and hashes reported by researchers.

Needs a free abuse.ch Auth-Key (ABUSECH_AUTH_KEY in .env); without one the collector is skipped. Malware families are
linked to the ATT&CK malware object of the same name when one exists, so an indicator connects to known threat actors.
"""

from datetime import UTC, datetime
from typing import Any

import httpx

from tip import stix
from tip.collectors.base import USER_AGENT, Collected
from tip.config import settings

API = "https://threatfox-api.abuse.ch/api/v1/"
TYPES = {"domain": "domain-name", "url": "url", "sha256_hash": "sha256", "ip:port": "ipv4-addr"}


def _value(ioc_type: str, ioc: str) -> str:
    return ioc.rsplit(":", 1)[0] if ioc_type == "ip:port" else ioc


def parse(entries: list[dict[str, Any]], attack_malware: dict[str, str]) -> list[Any]:
    """ThreatFox entries -> Indicators, plus "indicates" relationships to ATT&CK malware matched by name/alias."""
    objects: list[Any] = []
    for e in entries:
        observable = TYPES.get(e.get("ioc_type", ""))
        if not observable:
            continue
        value = _value(e["ioc_type"], e["ioc"])
        family = e.get("malware_printable") or e.get("malware") or "unknown"
        first_seen = datetime.strptime(e["first_seen"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=UTC)
        ind = stix.indicator(
            "threatfox",
            observable,
            value,
            name=f"{family} {observable} {value}",
            description=f"{e.get('threat_type_desc') or e.get('threat_type')}. Reported to ThreatFox as {family}.",
            indicator_types=["malicious-activity"],
            labels=[f"malware:{family}"] + [f"tag:{t}" for t in (e.get("tags") or [])],
            confidence=int(e.get("confidence_level") or 50),
            valid_from=first_seen,
            reference_url=f"https://threatfox.abuse.ch/ioc/{e['id']}/",
        )
        objects.append(ind)
        malware_id = attack_malware.get(family.lower())
        if malware_id:
            objects.append(stix.relationship("threatfox", ind.id, "indicates", malware_id))
    return objects


def collect(attack_malware: dict[str, str], days: int = 7) -> Collected:
    key = settings().abusech_auth_key
    if not key:
        return Collected(summary="skipped: set ABUSECH_AUTH_KEY in .env (free at https://auth.abuse.ch)", skipped=True)
    with httpx.Client(timeout=120, headers={"Auth-Key": key, "User-Agent": USER_AGENT}) as client:
        response = client.post(API, json={"query": "get_iocs", "days": days})
        response.raise_for_status()
        body = response.json()
    if body.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: {body.get('query_status')}")
    objects = [stix.identity("threatfox")] + parse(body.get("data") or [], attack_malware)
    linked = sum(1 for o in objects if getattr(o, "type", "") == "relationship")
    return Collected(
        objects, f"{len(objects) - 1 - linked} IOCs from the last {days} days, {linked} linked to ATT&CK malware"
    )
