"""The facts a brief is built on, computed in code from the investigation's cited evidence (never by the AI).

Money, counts, times and indicators are exactly the things a language model gets subtly wrong, and exactly the things
an executive will repeat. So they are derived here from the log events and intelligence records the accepted findings
cite, each with the evidence IDs behind it; the AI only writes prose around them, and the brief checker rejects any
dollar figure or indicator that isn't in these facts or the cited evidence.
"""

from typing import Any

import psycopg

from tip import store
from tip.agent.report import _event_rows
from tip.agent.tools import is_event_id, is_stix_id
from tip.config import settings

INTERNAL_PREFIXES = ("10.", "100.", "192.0.2.", "198.51.100.")  # VPC, proxy pool, homes, office (reserved ranges)


def accepted_findings(inv: dict[str, Any]) -> list[dict[str, Any]]:
    report, checks = inv["report"], inv["verification"]
    return [f for f, c in zip(report["findings"], checks["findings"], strict=True) if c["status"] == "accepted"]


def ledger(inv: dict[str, Any]) -> set[str]:
    """Every evidence ID a tool returned during the investigation."""
    return {i for call in inv["trace"] for i in call.get("evidence_ids", [])}


def compute(pg: psycopg.Connection, inv: dict[str, Any]) -> dict[str, Any]:
    findings = accepted_findings(inv)
    cited = sorted({i for f in findings for i in f["evidence_ids"]})
    events = _event_rows(inv.get("logs") or str(settings().logs_db), [i for i in cited if is_event_id(i)])
    intel = {i: store.get(pg, i) for i in cited if is_stix_id(i)}
    sanctioned = {
        (o.get("x_tip_observable") or {}).get("value", "").lower(): i
        for i, o in intel.items()
        if o and "sanctioned" in (o.get("labels") or [])
    }

    withdrawals = [e for e in events.values() if "to_address" in e and e.get("to_address")]
    completed = [w for w in withdrawals if w.get("status") == "completed"]
    pending = [w for w in withdrawals if w.get("status") != "completed"]
    to_sanctioned = [w for w in withdrawals if w["to_address"].lower() in sanctioned]

    indicators: dict[tuple[str, str], set[str]] = {}
    roles: dict[tuple[str, str], str] = {}

    def add(kind: str, value: Any, evidence: str, role: str) -> None:
        if value:
            indicators.setdefault((kind, str(value)), set()).add(evidence)
            roles.setdefault((kind, str(value)), role)

    for eid, e in events.items():
        lure = e.get("category") == "newly-registered"
        if e.get("dest_ip") and not str(e["dest_ip"]).startswith(INTERNAL_PREFIXES):
            add(
                "ip",
                e["dest_ip"],
                eid,
                "Server hosting the fake recruiter site"
                if lure
                else "Malware command-and-control server (download and upload)",
            )
        if lure:
            add("domain", e.get("dest_domain"), eid, "Fake recruiter site (newly registered domain)")
        if e.get("asn") and not str(e.get("src_ip", "")).startswith(INTERNAL_PREFIXES):
            add("ip", e.get("src_ip"), eid, f"Attacker server used to replay the stolen session ({e.get('asn')})")
        if (
            e.get("process") in ("python3", "node", "curl")
            and e.get("parent_process") in ("node", "npm")
            and e.get("sha256")
        ):
            add("sha256", e["sha256"], eid, f"Hash of the {e['process']} process started by the malicious package")
        if e.get("file_path") and "/." in str(e["file_path"]):
            add("file", e["file_path"], eid, "Malware written to a hidden folder")
    for w in to_sanctioned:
        add("wallet", w["to_address"], w["event_id"], "OFAC-sanctioned destination of stolen funds")
        add(
            "wallet",
            w["to_address"],
            sanctioned[w["to_address"].lower()],
            "OFAC-sanctioned destination of stolen funds",
        )

    times = [e["ts"] for e in events.values()]
    people = sorted({str(e[k]) for e in events.values() for k in ("user_name", "principal") if e.get(k)})
    hosts = sorted({str(e["host"]) for e in events.values() if e.get("host")})
    return {
        "verdict": inv["report"]["verdict"],
        "confidence": inv["report"]["confidence"],
        "first_event": min(times).isoformat() if times else None,
        "last_event": max(times).isoformat() if times else None,
        "hours_first_to_last": round((max(times) - min(times)).total_seconds() / 3600, 1) if times else None,
        "people": people,
        "hosts": hosts,
        "money": {
            "withdrawn_usd": round(sum(w["usd_value"] for w in completed), 2),
            "pending_usd": round(sum(w["usd_value"] for w in pending), 2),
            "attempted_usd": round(sum(w["usd_value"] for w in withdrawals), 2),
            "to_sanctioned_usd": round(sum(w["usd_value"] for w in to_sanctioned), 2),
            "withdrawals": [
                {
                    "event_id": w["event_id"],
                    "asset": w["asset"],
                    "amount": w["amount"],
                    "usd_value": w["usd_value"],
                    "status": w["status"],
                    "to_address": w["to_address"],
                    "sanctioned": w in to_sanctioned,
                }
                for w in withdrawals
            ],
        },
        "indicators": [
            {"type": k, "value": v, "role": roles[(k, v)], "evidence_ids": sorted(ids)}
            for (k, v), ids in sorted(indicators.items())
        ],
        "techniques": sorted({t for f in findings for t in f["technique_ids"]}),
        "evidence_ids": cited,
        "findings": [
            {
                "title": f["title"],
                "when": f["when"],
                "severity": f["severity"],
                "technique_ids": f["technique_ids"],
                "evidence_ids": f["evidence_ids"],
            }
            for f in findings
        ],
    }


def money_figures(facts: dict[str, Any]) -> list[float]:
    m = facts["money"]
    figures = [m["withdrawn_usd"], m["pending_usd"], m["attempted_usd"], m["to_sanctioned_usd"]]
    return [x for x in figures + [w["usd_value"] for w in m["withdrawals"]] if x]


def event_text(pg: psycopg.Connection, logs_path: str, ids: list[str]) -> dict[str, str]:
    """Searchable text of cited evidence (log events and intelligence), for checking indicators really appear in it."""
    out = {
        eid: " ".join(str(v) for v in e.values() if v is not None).lower()
        for eid, e in _event_rows(logs_path, [i for i in ids if is_event_id(i)]).items()
    }
    for i in ids:
        if is_stix_id(i):
            obj = store.get(pg, i)
            if obj:
                out[i] = " ".join(
                    [
                        str(obj.get("name", "")),
                        str((obj.get("x_tip_observable") or {}).get("value", "")),
                        str(obj.get("pattern", "")),
                    ]
                ).lower()
    return out
