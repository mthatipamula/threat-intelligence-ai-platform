"""MISP export and sync: share what we learned with partners in the format crypto security teams already use.

Two event types, built from data the platform already verified:
  * incident  - indicators from an investigation's accepted findings (attacker IPs, the lure domain, malware hashes and
                file paths, the sanctioned wallet), tagged with the ATT&CK techniques and threat group. TLP:AMBER, the
                usual marking for sharing with an industry group such as a crypto ISAC.
  * lookalikes - domains imitating our brand (DNS and certificate transparency). TLP:GREEN; not marked for automatic
                blocking (to_ids false) because each one still needs triage.
Events get a stable UUID, so pushing again updates the same event instead of creating a duplicate.

`export` writes MISP's JSON event format (importable through the MISP UI or API); `push` sends it to a MISP server's
REST API (POST /events/add, or /events/edit/<uuid> when it already exists).
"""

import uuid
from datetime import UTC, date, datetime
from typing import Any

import httpx
import psycopg

from tip import store
from tip.briefs import facts as factlib
from tip.config import settings
from tip.stix import NAMESPACE

# MISP attribute type and category per indicator type. Crypto wallets use MISP's "coin-address" object.
ATTRIBUTE = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "sha256": ("sha256", "Payload delivery"),
    "file": ("filename", "Artifacts dropped"),
    "url": ("url", "Network activity"),
}
COIN_ADDRESS_TEMPLATE = "d0e6997e-78da-4815-a6a1-cfc1c1cb8a46"  # MISP object template "coin-address"
CHAIN_SYMBOL = {"XBT": "BTC", "ETH": "ETH", "USDT": "USDT", "USDC": "USDC", "TRX": "TRX", "SOL": "SOL"}


def _uuid(kind: str, key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"misp:{kind}:{key}"))


def _attack_tags(pg: psycopg.Connection, technique_ids: list[str]) -> list[dict[str, str]]:
    """MISP's MITRE ATT&CK galaxy names clusters "<technique name> - <ID>",
    e.g. "Spearphishing via Service - T1566.003"."""
    rows = pg.execute(
        "SELECT data->'external_references'->0->>'external_id' AS ext, name FROM stix_objects "
        "WHERE type = 'attack-pattern' AND NOT revoked AND data->'external_references'->0->>'external_id' = ANY(%s)",
        [technique_ids],
    ).fetchall()
    return [
        {"name": f'misp-galaxy:mitre-attack-pattern="{r["name"]} - {r["ext"]}"'}
        for r in sorted(rows, key=lambda r: r["ext"])
    ]


def incident_event(pg: psycopg.Connection, investigation_id: str) -> dict[str, Any]:
    inv = pg.execute("SELECT * FROM investigations WHERE id = %s", [investigation_id]).fetchone()
    if not inv or inv["status"] != "done":
        raise ValueError("investigation not found or not finished")
    facts = factlib.compute(pg, inv)
    report = inv["report"]
    attributes, objects = [], []
    for ind in facts["indicators"]:
        if ind["type"] == "wallet":
            stix_ids = [i for i in ind["evidence_ids"] if i.startswith("indicator--")]
            chains = (store.get(pg, stix_ids[0]) or {}).get("x_tip_chains", []) if stix_ids else []
            bitcoin = chains[:1] == ["XBT"] or ind["value"].startswith(("bc1", "1", "3"))
            objects.append(
                {
                    "name": "coin-address",
                    "template_uuid": COIN_ADDRESS_TEMPLATE,
                    "meta-category": "financial",
                    "uuid": _uuid("wallet", ind["value"].lower()),
                    "comment": ind["role"],
                    "Attribute": [
                        {
                            # MISP validates "address" (type btc) as a Bitcoin address; other chains use address-crypto
                            "object_relation": "address" if bitcoin else "address-crypto",
                            "type": "btc" if bitcoin else "text",
                            "category": "Financial fraud",
                            "value": ind["value"],
                            "to_ids": True,
                            "comment": "Destination of stolen funds; on the OFAC SDN list",
                        },
                        {
                            "object_relation": "symbol",
                            "type": "text",
                            "category": "Other",
                            "value": CHAIN_SYMBOL.get(chains[0], chains[0]) if chains else "ETH",
                            "to_ids": False,
                        },
                    ],
                }
            )
            continue
        mtype, category = ATTRIBUTE[ind["type"]]
        attributes.append(
            {
                "uuid": _uuid("attr", f"{investigation_id}:{ind['type']}:{ind['value']}"),
                "type": mtype,
                "category": category,
                "value": ind["value"],
                "comment": ind["role"],
                # file paths and the lure site's IP are context, not something to block everywhere
                "to_ids": ind["type"] in ("sha256", "domain")
                or "command-and-control" in ind["role"]
                or "replay" in ind["role"],
            }
        )
    # threat-actor tags only for groups the report's context actually cites (attribution stays evidence-based)
    cited = [i for c in report.get("context", []) for i in c["evidence_ids"] if i.startswith("intrusion-set--")]
    actors = sorted({o["name"] for o in (store.get(pg, i) for i in cited) if o})
    tags = [{"name": "tlp:amber"}] + [{"name": f'misp-galaxy:threat-actor="{a}"'} for a in actors]
    tags += _attack_tags(pg, facts["techniques"])
    return {
        "Event": {
            "uuid": _uuid("incident", investigation_id),
            "info": f"Meridian Exchange {report['verdict'].replace('-', ' ')}: "
            + report["summary"].split(". ")[0][:160],
            "date": (facts["first_event"] or date.today().isoformat())[:10],
            "threat_level_id": "1" if report["verdict"] == "confirmed-compromise" else "3",
            "analysis": "2",  # completed
            "distribution": "1",  # this community only
            "Tag": tags,
            "Attribute": attributes,
            "Object": objects,
            "EventReport": [{"name": "Summary", "content": report["summary"], "distribution": "5"}],
        }
    }


def lookalike_event(pg: psycopg.Connection) -> dict[str, Any]:
    rows = pg.execute(
        "SELECT observable_value AS domain, source, data->'labels' AS labels, data->'x_tip_ct' AS ct FROM stix_objects "
        "WHERE source IN ('lookalike', 'ct-watcher') AND type = 'indicator' AND NOT revoked "
        "AND NOT (data->'labels' ? 'sample') ORDER BY observable_value"
    ).fetchall()
    brands = sorted({lab.split(":", 1)[1] for r in rows for lab in r["labels"] if lab.startswith("brand:")})
    attributes = []
    for r in rows:
        technique = next((lab.split(":", 1)[1] for lab in r["labels"] if lab.startswith("technique:")), "lookalike")
        how = "certificate transparency" if r["source"] == "ct-watcher" else "resolves in DNS"
        attributes.append(
            {
                "uuid": _uuid("lookalike", r["domain"]),
                "type": "domain",
                "category": "Network activity",
                "value": r["domain"],
                "to_ids": False,
                "comment": f"{technique}; found via {how}; needs triage",
            }
        )
    return {
        "Event": {
            "uuid": _uuid("lookalikes", ",".join(brands) or "none"),
            "info": f"Lookalike domains imitating {', '.join(brands) or 'watched brands'}",
            "date": datetime.now(UTC).date().isoformat(),
            "threat_level_id": "3",
            "analysis": "1",
            "distribution": "1",
            "Tag": [
                {"name": "tlp:green"},
                {"name": 'misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"'},
            ],
            "Attribute": attributes,
        }
    }


# ---------------------------------------------------------------- pushing to a MISP server


class MispError(RuntimeError):
    pass


def _client() -> httpx.Client:
    s = settings()
    if not s.misp_url or not s.misp_admin_key:
        raise MispError("set MISP_URL and MISP_ADMIN_KEY in .env (./scripts/init-env.sh adds a key for the local MISP)")
    return httpx.Client(
        base_url=s.misp_url.rstrip("/"),
        verify=s.misp_verify_tls,
        timeout=60,
        headers={"Authorization": s.misp_admin_key, "Accept": "application/json", "Content-Type": "application/json"},
    )


def push(event: dict[str, Any]) -> dict[str, Any]:
    """Create the event, or update it if an event with the same UUID exists. Returns MISP's id, uuid and counts."""
    try:
        return _push(event)
    except httpx.HTTPError as e:
        raise MispError(
            f"cannot reach MISP at {settings().misp_url} ({type(e).__name__}); is it running and finished "
            "starting? `docker compose --profile misp ps`, then `./tip misp status`"
        ) from e


def ensure_reference_data(misp: httpx.Client) -> list[str]:
    """A new MISP has no object templates or galaxies loaded until an admin updates them; objects whose template is
    unknown are silently dropped, and galaxy tags stay unlinked. Load both once, on first push."""
    loaded = []
    templates = misp.get("/objectTemplates/index")
    if templates.status_code == 200 and not templates.json():
        misp.post("/objectTemplates/update", json={}, timeout=300)
        loaded.append("object templates")
    galaxies = misp.get("/galaxies/index")
    if galaxies.status_code == 200 and not galaxies.json():
        misp.post("/galaxies/update", json={}, timeout=600)
        loaded.append("galaxies")
    return loaded


def _push(event: dict[str, Any]) -> dict[str, Any]:
    with _client() as misp:
        loaded = ensure_reference_data(misp)
        event_uuid = event["Event"]["uuid"]
        existing = misp.get(f"/events/view/{event_uuid}")
        if existing.status_code == 200:
            r = misp.post(f"/events/edit/{event_uuid}", json=event)
            action = "updated"
        else:
            r = misp.post("/events/add", json=event)
            action = "created"
        if r.status_code >= 300:
            raise MispError(f"MISP returned HTTP {r.status_code}: {r.text[:400]}")
        saved = r.json().get("Event", {})
        return {
            "action": action,
            "loaded_reference_data": loaded,
            "id": saved.get("id"),
            "uuid": saved.get("uuid"),
            "attributes": len(saved.get("Attribute", [])),
            "objects": len(saved.get("Object", [])),
            "tags": len(saved.get("Tag", [])),
            "url": f"{settings().misp_url.rstrip('/')}/events/view/{saved.get('id')}",
        }


def status() -> dict[str, Any]:
    try:
        with _client() as misp:
            r = misp.get("/servers/getVersion")
    except httpx.HTTPError as e:
        raise MispError(
            f"cannot reach MISP at {settings().misp_url} ({type(e).__name__}); first start takes a few "
            "minutes: `docker compose --profile misp logs misp --tail 5`"
        ) from e
    if r.status_code != 200:
        raise MispError(f"MISP returned HTTP {r.status_code}: check MISP_ADMIN_KEY")
    return r.json()
