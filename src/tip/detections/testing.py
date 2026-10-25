"""Replay testing: run a rule's SQL over the logs and score it against the attack answer key.

Two datasets:
  * this week (with the hidden attack): which attack events does the rule catch, and what else does it flag?
  * a fresh normal-only week it has never seen: does it fire on ordinary activity? This is the check that stops a
    rule from passing just because it was written while looking at this week's data.

Synthetic "normal" activity is cleaner than a real company's, so a pass here means "worth deploying in test mode and
watching", not "proven quiet in production".
"""

import re
from typing import Any

import duckdb

from tip.config import settings
from tip.detections.sigma_engine import Converted, parse

MAX_FALSE_ALARMS = 2  # per week, on each dataset
SAMPLE_ROWS = 5


def techniques(yaml_text: str) -> list[str]:
    tags = [str(t) for t in parse(yaml_text).rules[0].tags]
    return sorted({t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t, re.I)})


def _run(db_path: str, sql: str) -> list[dict[str, Any]]:
    with duckdb.connect(db_path, read_only=True) as con:
        con.execute("SET TimeZone = 'UTC'")
        cur = con.execute(sql)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def _sample(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keep = (
        "event_id",
        "ts",
        "user_name",
        "host",
        "principal",
        "process",
        "parent_process",
        "command_line",
        "file_path",
        "dest_domain",
        "dest_ip",
        "dest_port",
        "bytes_out",
        "app",
        "src_ip",
        "asn",
        "action",
        "resource",
        "initiated_by",
        "asset",
        "amount",
        "to_address",
        "category",
    )
    return [{k: str(v) for k, v in r.items() if k in keep and v is not None} for r in rows[:SAMPLE_ROWS]]


def replay(yaml_text: str, converted: Converted) -> dict[str, Any]:
    """Score one rule. Returns counts, samples, a pass/fail verdict and plain-English reasons."""
    if not converted.sql:
        return {"verdict": "failed", "reasons": [f"could not convert to SQL: {converted.errors}"]}
    main, baseline = str(settings().logs_db), str(settings().baseline_db)
    try:
        hits = _run(main, converted.sql)
        fresh = _run(baseline, converted.sql)
    except duckdb.Error as e:
        return {"verdict": "failed", "reasons": [f"query failed: {e}"[:400]]}

    with duckdb.connect(main, read_only=True) as con:
        key = {
            r[0]: (r[1], r[2])
            for r in con.execute("SELECT event_id, table_name, technique_id FROM scenario_events").fetchall()
        }
        scanned = con.execute(f"SELECT count(*) FROM {converted.table}").fetchone()[0]
    with duckdb.connect(baseline, read_only=True) as con:
        fresh_scanned = con.execute(f"SELECT count(*) FROM {converted.table}").fetchone()[0]

    tagged = set(techniques(yaml_text))
    expected = {eid for eid, (table, tech) in key.items() if table == converted.table and tech in tagged}
    hit_ids = {r["event_id"] for r in hits}
    attack_hits = [r for r in hits if r["event_id"] in key]
    false_alarms = [r for r in hits if r["event_id"] not in key]

    reasons = []
    if not attack_hits:
        reasons.append("caught none of the attack's events")
    if len(false_alarms) > MAX_FALSE_ALARMS:
        reasons.append(
            f"{len(false_alarms)} false alarms on this week's normal activity (about {len(false_alarms) / 7:.0f} a day)"
        )
    if len(fresh) > MAX_FALSE_ALARMS:
        reasons.append(f"fires {len(fresh)} times on a fresh week of normal activity it has never seen")
    return {
        "verdict": "failed" if reasons else "passed",
        "reasons": reasons,
        "table": converted.table,
        "scanned": scanned,
        "attack_events_caught": len(attack_hits),
        "expected_for_techniques": len(expected),
        "caught_of_expected": len(expected & hit_ids),
        "false_alarms": len(false_alarms),
        "fresh_week_scanned": fresh_scanned,
        "fresh_week_alarms": len(fresh),
        "sample_attack_hits": _sample(attack_hits),
        "sample_false_alarms": _sample(false_alarms),
        "sample_fresh_week_alarms": _sample(fresh),
    }
