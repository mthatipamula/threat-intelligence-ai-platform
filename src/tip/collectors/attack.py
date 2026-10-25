"""MITRE ATT&CK (Enterprise) - attacker techniques, groups, malware and tools, already published as STIX 2.1.

Kept: techniques and sub-techniques, tactics, intrusion sets (groups), campaigns, malware, tools, and the relationships
between them ("Lazarus Group uses T1566.002"). Revoked and deprecated objects are dropped, along with relationships
that point at anything dropped.
"""

import json
from pathlib import Path
from typing import Any

from tip.collectors.base import Collected, fetch

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
KEEP = {
    "attack-pattern",
    "x-mitre-tactic",
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "identity",
    "marking-definition",
}
KEEP_RELATIONSHIPS = {"uses", "subtechnique-of", "attributed-to"}


def parse(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    objects = [
        o for o in bundle["objects"] if o["type"] in KEEP and not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]
    kept = {o["id"] for o in objects}
    relationships = [
        o
        for o in bundle["objects"]
        if o["type"] == "relationship"
        and o.get("relationship_type") in KEEP_RELATIONSHIPS
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
        and o["source_ref"] in kept
        and o["target_ref"] in kept
    ]
    return objects + relationships


def collect(path: Path | None = None) -> Collected:
    bundle = json.loads((path or fetch(URL, "enterprise-attack.json", max_age_hours=24 * 7)).read_text())
    objects = parse(bundle)
    counts: dict[str, int] = {}
    for o in objects:
        counts[o["type"]] = counts.get(o["type"], 0) + 1
    version = next((o.get("x_mitre_version") for o in bundle["objects"] if o["type"] == "x-mitre-collection"), "?")
    summary = f"ATT&CK v{version}: " + ", ".join(f"{n} {t}" for t, n in sorted(counts.items(), key=lambda kv: -kv[1]))
    return Collected(objects, summary)
