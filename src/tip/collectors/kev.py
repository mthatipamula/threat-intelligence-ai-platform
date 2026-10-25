"""CISA Known Exploited Vulnerabilities - CVEs attackers are actively exploiting, as STIX Vulnerability objects."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import stix2

from tip import stix
from tip.collectors.base import Collected, fetch

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _date(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)


def to_vulnerability(entry: dict[str, Any]) -> stix2.Vulnerability:
    cve = entry["cveID"]
    added = _date(entry["dateAdded"])
    return stix2.Vulnerability(
        id=stix.deterministic_id("vulnerability", cve),
        name=cve,
        description=f"{entry['vulnerabilityName']}. {entry['shortDescription']}",
        created=added,
        modified=added,
        created_by_ref=stix.identity("cisa-kev").id,
        external_references=[
            {"source_name": "cve", "external_id": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            {"source_name": "cisa-kev", "url": stix.SOURCES["cisa-kev"]["url"]},
        ],
        labels=["known-exploited"] + (["ransomware"] if entry.get("knownRansomwareCampaignUse") == "Known" else []),
        x_cisa_kev={
            "vendor": entry["vendorProject"],
            "product": entry["product"],
            "date_added": entry["dateAdded"],
            "due_date": entry.get("dueDate"),
            "required_action": entry.get("requiredAction"),
            "ransomware_use": entry.get("knownRansomwareCampaignUse"),
            "cwes": entry.get("cwes", []),
        },
        allow_custom=True,
    )


def collect(path: Path | None = None) -> Collected:
    catalog = json.loads((path or fetch(URL, "known_exploited_vulnerabilities.json")).read_text())
    objects: list[Any] = [stix.identity("cisa-kev")]
    objects += [to_vulnerability(v) for v in catalog["vulnerabilities"]]
    return Collected(objects, f"KEV catalog {catalog.get('catalogVersion')}: {len(objects) - 1} known-exploited CVEs")
