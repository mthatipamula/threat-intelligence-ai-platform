"""Detection engineering: turn verified investigation findings into tested, reviewed Sigma rules.

Lifecycle of a rule:  drafting -> passed | failed (replay test)  ->  approved | rejected (a person decides)
Approved rules are written to detections/ in the repository (detection-as-code), with status "test".
"""

import re
import threading
import traceback
import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from tip import store
from tip.config import ROOT
from tip.detections import drafting, sigma_engine, testing

APPROVED_DIR = ROOT / "detections"
SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id               uuid PRIMARY KEY,
    batch_id         uuid NOT NULL,
    investigation_id uuid,
    mode             text NOT NULL,
    finding          text,
    title            text,
    description      text,
    level            text,
    technique_ids    text[] NOT NULL DEFAULT '{}',
    sigma_yaml       text,
    translations     jsonb,
    test             jsonb,
    attempts         jsonb NOT NULL DEFAULT '[]',
    status           text NOT NULL,       -- drafting | passed | failed | approved | rejected | error
    reviewer         text,
    review_note      text,
    approved_path    text,
    error            text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    reviewed_at      timestamptz
);
CREATE INDEX IF NOT EXISTS detections_batch ON detections (batch_id);
"""


def init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()


def evaluate(yaml_text: str) -> dict[str, Any]:
    """Convert and replay-test one rule. Used for every draft attempt, and for any rule file (CLI)."""
    converted = sigma_engine.convert(yaml_text)
    test = testing.replay(yaml_text, converted)
    rule = sigma_engine.parse(yaml_text).rules[0] if "sigma" not in converted.errors else None
    return {
        "translations": {
            "sql": converted.sql,
            "spl": converted.spl,
            "kql": converted.kql,
            "table": converted.table,
            "errors": converted.errors,
        },
        "test": test,
        "title": rule.title if rule else None,
        "description": rule.description if rule else None,
        "level": str(rule.level.name).lower() if rule and rule.level else None,
        "technique_ids": testing.techniques(yaml_text) if rule else [],
    }


# ---------------------------------------------------------------- drafting a batch


def start_batch(conn: psycopg.Connection, investigation_id: str) -> str:
    """Check the investigation is finished and return a new batch ID."""
    init_schema(conn)
    row = conn.execute("SELECT status FROM investigations WHERE id = %s", [investigation_id]).fetchone()
    if not row or row["status"] != "done":
        raise ValueError("investigation not found or not finished")
    return str(uuid.uuid4())


def run_batch(batch_id: str, investigation_id: str, mode: str) -> None:
    """Draft and test one rule per behaviour in the investigation's accepted findings. Never raises."""
    with store.connect() as conn:
        init_schema(conn)
        inv = conn.execute(
            "SELECT report, verification FROM investigations WHERE id = %s", [investigation_id]
        ).fetchone()
        findings = [
            f
            for f, c in zip(inv["report"]["findings"], inv["verification"]["findings"], strict=True)
            if c["status"] == "accepted"
        ]
        writer = drafting.ClaudeWriter() if mode == "live" else drafting.MockWriter()
        for plan in writer.plan(findings):
            det_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO detections (id, batch_id, investigation_id, mode, finding, technique_ids, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'drafting')",
                [det_id, batch_id, investigation_id, mode, plan.finding["title"], plan.finding["technique_ids"]],
            )
            conn.commit()
            try:
                attempts = writer.draft(plan, evaluate)
                final = attempts[-1]
                conn.execute(
                    "UPDATE detections SET title = %s, description = %s, level = %s, technique_ids = %s, "
                    "sigma_yaml = %s, translations = %s, test = %s, attempts = %s, status = %s WHERE id = %s",
                    [
                        final["title"],
                        final["description"],
                        final["level"],
                        final["technique_ids"],
                        final["yaml"],
                        Jsonb(final["translations"]),
                        Jsonb(final["test"]),
                        Jsonb(
                            [
                                {
                                    "yaml": a["yaml"],
                                    "verdict": a["test"]["verdict"],
                                    "reasons": a["test"]["reasons"],
                                    "note": a.get("note"),
                                }
                                for a in attempts
                            ]
                        ),
                        final["test"]["verdict"],
                        det_id,
                    ],
                )
            except Exception as e:  # recorded on the row for the UI; traceback to the server log
                traceback.print_exc()
                conn.rollback()
                conn.execute(
                    "UPDATE detections SET status = 'error', error = %s WHERE id = %s",
                    [f"{type(e).__name__}: {e}"[:1000], det_id],
                )
            conn.commit()


def run_batch_in_background(batch_id: str, investigation_id: str, mode: str) -> threading.Thread:
    t = threading.Thread(
        target=run_batch, args=(batch_id, investigation_id, mode), daemon=True, name=f"detections-{batch_id[:8]}"
    )
    t.start()
    return t


# ---------------------------------------------------------------- review


def slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:80]


def review(conn: psycopg.Connection, det_id: str, decision: str, reviewer: str, note: str) -> dict[str, Any]:
    """Approve (write the rule to detections/ as status: test) or reject. Only rules that passed can be approved."""
    init_schema(conn)
    det = conn.execute("SELECT * FROM detections WHERE id = %s", [det_id]).fetchone()
    if not det:
        raise LookupError("no such detection")
    if decision == "approve" and det["status"] not in ("passed", "approved"):
        raise ValueError("only rules that passed the replay test can be approved")
    path = None
    if decision == "approve":
        APPROVED_DIR.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        header = f"# Approved by {reviewer} on {stamp}." + (f" Note: {note}" if note else "") + "\n"
        body = re.sub(r"^status: \w+", "status: test", det["sigma_yaml"], count=1, flags=re.M)
        file = APPROVED_DIR / f"{slug(det['title'])}.yml"
        file.write_text(header + body)
        path = str(file.relative_to(ROOT))
    elif det["approved_path"]:  # rejecting a previously approved rule removes it from the rule set
        (ROOT / det["approved_path"]).unlink(missing_ok=True)
    conn.execute(
        "UPDATE detections SET status = %s, reviewer = %s, review_note = %s, approved_path = %s, reviewed_at = now() "
        "WHERE id = %s",
        ["approved" if decision == "approve" else "rejected", reviewer, note or None, path, det_id],
    )
    conn.commit()
    return conn.execute("SELECT * FROM detections WHERE id = %s", [det_id]).fetchone()


def listing(conn: psycopg.Connection, batch_id: str | None = None) -> list[dict[str, Any]]:
    """One batch, or (default) the latest batch plus every approved rule from earlier batches."""
    init_schema(conn)
    if batch_id:
        return conn.execute("SELECT * FROM detections WHERE batch_id = %s ORDER BY created_at", [batch_id]).fetchall()
    latest = conn.execute("SELECT batch_id FROM detections ORDER BY created_at DESC LIMIT 1").fetchone()
    approved = conn.execute("SELECT * FROM detections WHERE status = 'approved' ORDER BY reviewed_at").fetchall()
    batch = listing(conn, str(latest["batch_id"])) if latest else []
    seen = {d["id"] for d in batch}
    return batch + [d for d in approved if d["id"] not in seen]


def coverage(conn: psycopg.Connection, actor: str) -> dict[str, Any]:
    """Which of a threat group's ATT&CK techniques our approved (and tested) rules detect."""
    init_schema(conn)
    found = store.find_by_name(conn, actor, ["intrusion-set"], limit=1)
    if not found:
        raise LookupError(f"no threat group {actor!r}")
    used = conn.execute(
        "SELECT o.data->'external_references'->0->>'external_id' AS id, o.name, o.data->'kill_chain_phases' AS phases "
        "FROM stix_objects r JOIN stix_objects o ON o.id = r.target_ref WHERE r.source_ref = %s "
        "AND r.relationship_type = 'uses' AND o.type = 'attack-pattern' AND NOT r.revoked",
        [found[0]["id"]],
    ).fetchall()
    rules = conn.execute(
        "SELECT title, status, technique_ids FROM detections WHERE status IN ('approved', 'passed')"
    ).fetchall()
    by_technique: dict[str, dict[str, list[str]]] = {}
    for r in rules:
        for t in r["technique_ids"]:
            by_technique.setdefault(t, {"approved": [], "passed": []})[r["status"]].append(r["title"])
    techniques = []
    for u in sorted(used, key=lambda x: x["id"]):
        rules_for = by_technique.get(u["id"], {"approved": [], "passed": []})
        techniques.append(
            {
                "id": u["id"],
                "name": u["name"],
                "tactics": [p["phase_name"] for p in (u["phases"] or [])],
                "approved": sorted(set(rules_for["approved"])),
                "pending": sorted(set(rules_for["passed"])),
            }
        )
    return {
        "actor": found[0]["name"],
        "techniques": techniques,
        "total": len(techniques),
        "covered": sum(1 for t in techniques if t["approved"]),
        "pending": sum(1 for t in techniques if t["pending"] and not t["approved"]),
        "beyond_actor": sorted(set(by_technique) - {u["id"] for u in used}),
    }
