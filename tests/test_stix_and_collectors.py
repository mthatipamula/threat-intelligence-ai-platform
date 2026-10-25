import json

import stix2

from tip import stix
from tip.collectors import attack, kev, lookalike, ofac, threatfox


def roundtrip(obj) -> dict:
    """Every object we create must survive a strict STIX 2.1 parse."""
    data = stix.to_dict(obj)
    stix2.parse(json.dumps(data), allow_custom=True)
    return data


def test_indicator_ids_are_deterministic_and_case_insensitive():
    a = stix.indicator("ofac", "crypto-wallet", "0xABC", name="n", description="d", indicator_types=["attribution"])
    b = stix.indicator("ofac", "crypto-wallet", "0xabc", name="n", description="d", indicator_types=["attribution"])
    assert a.id == b.id
    data = roundtrip(a)
    assert data["pattern"] == "[x-crypto-wallet:address = '0xABC']"
    assert data["x_tip_observable"] == {"type": "crypto-wallet", "value": "0xABC"}
    assert data["created_by_ref"] == stix.identity("ofac").id


def test_pattern_values_are_escaped():
    ind = stix.indicator(
        "lookalike", "url", "http://x.test/a'b", name="n", description="d", indicator_types=["malicious-activity"]
    )
    assert "a\\'b" in roundtrip(ind)["pattern"]


def test_ofac_merges_an_address_listed_on_several_chains():
    objs = ofac.build({"0x098B716B8Aaf21512996dC57EB0615e2383E2f96": ["ETH", "USDT"], "bc1qxyz": ["XBT"]})
    assert len(objs) == 2
    eth = roundtrip(objs[0])
    assert eth["labels"] == ["sanctioned", "chain:eth", "chain:usdt"]
    assert eth["x_tip_chains"] == ["ETH", "USDT"]
    assert ofac.addresses("# comment\n0xA\n\n0xA\n0xB\n") == {"0xA", "0xB"}


def test_kev_entry_becomes_a_vulnerability():
    v = roundtrip(
        kev.to_vulnerability(
            {
                "cveID": "CVE-2024-3400",
                "vendorProject": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerabilityName": "PAN-OS Command Injection",
                "dateAdded": "2024-04-12",
                "shortDescription": "OS command injection in GlobalProtect.",
                "requiredAction": "Patch.",
                "dueDate": "2024-04-19",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-77"],
            }
        )
    )
    assert v["name"] == "CVE-2024-3400"
    assert v["external_references"][0] == {
        "source_name": "cve",
        "external_id": "CVE-2024-3400",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    }
    assert v["labels"] == ["known-exploited", "ransomware"]
    assert (
        v["id"]
        == kev.to_vulnerability(
            {
                **{
                    "cveID": "CVE-2024-3400",
                    "vendorProject": "x",
                    "product": "y",
                    "vulnerabilityName": "z",
                    "dateAdded": "2024-04-12",
                    "shortDescription": "s",
                }
            }
        ).id
    )


def test_attack_drops_revoked_objects_and_their_relationships():
    bundle = {
        "objects": [
            {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Lazarus Group"},
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Phishing"},
            {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Old", "revoked": True},
            {"type": "malware", "id": "malware--1", "name": "Deprecated", "x_mitre_deprecated": True},
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--2",
            },
            {
                "type": "relationship",
                "id": "relationship--3",
                "relationship_type": "detects",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--1",
            },
            {"type": "x-mitre-data-source", "id": "x-mitre-data-source--1", "name": "Process"},
        ]
    }
    assert [o["id"] for o in attack.parse(bundle)] == ["intrusion-set--1", "attack-pattern--1", "relationship--1"]


def test_lookalike_candidates_cover_common_tricks():
    c = lookalike.candidates("coinbase.com")
    assert "coinbase.com" not in c
    assert c["coinbse.com"] == "omission"
    assert c["c0inbase.com"] == "homoglyph"
    assert c["coinbase-login.com"] == "keyword"
    assert c["coinbase.io"] == "tld-swap"
    assert any(k.startswith("xn--") and v == "idn-homoglyph" for k, v in c.items())
    ind = roundtrip(lookalike.to_indicator("coinbase.com", "c0inbase.com", "homoglyph", ["192.0.2.10"]))
    assert "needs-triage" in ind["labels"] and ind["confidence"] == 30


BEAVERTAIL = "malware--8a1c5a5d-2b9e-4c1e-9d6f-0e7b3a2c4d11"


def test_threatfox_links_families_to_attack_malware():
    entries = [
        {
            "id": "1",
            "ioc": "203.0.113.47:1224",
            "ioc_type": "ip:port",
            "malware_printable": "BeaverTail",
            "threat_type": "botnet_cc",
            "first_seen": "2026-10-20 10:00:00 UTC",
            "confidence_level": 75,
            "tags": ["dprk"],
        },
        {
            "id": "2",
            "ioc": "x.example",
            "ioc_type": "domain",
            "malware_printable": "Unknown Stealer",
            "threat_type": "payload_delivery",
            "first_seen": "2026-10-20 10:00:00 UTC",
            "confidence_level": 50,
        },
        {
            "id": "3",
            "ioc": "abc",
            "ioc_type": "md5_hash",
            "malware_printable": "x",
            "first_seen": "2026-10-20 10:00:00 UTC",
        },
    ]
    objs = [roundtrip(o) for o in threatfox.parse(entries, {"beavertail": BEAVERTAIL})]
    assert [o["type"] for o in objs] == ["indicator", "relationship", "indicator"]
    assert objs[0]["pattern"] == "[ipv4-addr:value = '203.0.113.47']"
    assert objs[1]["target_ref"] == BEAVERTAIL and objs[1]["relationship_type"] == "indicates"
