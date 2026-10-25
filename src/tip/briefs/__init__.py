"""Intelligence briefs: a technical brief for the security team and an executive brief for leadership.

Flow: facts computed from the investigation's cited evidence -> both briefs written (mock templates or Claude) ->
every cited item checked (real evidence, indicators present in it, known ATT&CK IDs, dollar figures from the facts)
-> in live mode one revision with the problems -> a person approves -> export as Markdown.
"""

import threading
import traceback
import uuid
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from tip import store
from tip.briefs import facts as factlib
from tip.briefs import models
from tip.briefs.writers import ClaudeWriter, MockWriter
from tip.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS briefs (
    id               uuid PRIMARY KEY,
    investigation_id uuid NOT NULL,
    mode             text NOT NULL,
    purpose          text NOT NULL DEFAULT 'analyst',
    status           text NOT NULL,       -- writing | ready | approved | rejected | failed
    facts            jsonb,
    technical        jsonb,
    executive        jsonb,
    verification     jsonb,
    revisions        integer NOT NULL DEFAULT 0,
    reviewer         text,
    review_note      text,
    usage            jsonb,
    error            text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    reviewed_at      timestamptz
);
"""


def init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()


def start(conn: psycopg.Connection, investigation_id: str, mode: str, purpose: str = "analyst") -> str:
    init_schema(conn)
    inv = conn.execute("SELECT status FROM investigations WHERE id = %s", [investigation_id]).fetchone()
    if not inv or inv["status"] != "done":
        raise ValueError("investigation not found or not finished")
    brief_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO briefs (id, investigation_id, mode, purpose, status) VALUES (%s, %s, %s, %s, 'writing')",
        [brief_id, investigation_id, mode, purpose],
    )
    conn.commit()
    return brief_id


def run(brief_id: str) -> None:
    """Write, check and (live) revise one pair of briefs. Never raises: failures are stored on the row."""
    with store.connect() as conn:
        row = conn.execute("SELECT * FROM briefs WHERE id = %s", [brief_id]).fetchone()
        writer = ClaudeWriter() if row["mode"] == "live" else MockWriter()
        try:
            inv = conn.execute("SELECT * FROM investigations WHERE id = %s", [row["investigation_id"]]).fetchone()
            facts = factlib.compute(conn, inv)
            dets = (
                conn.execute(
                    "SELECT id, title, status FROM detections WHERE investigation_id = %s "
                    "AND status IN ('passed', 'approved') ORDER BY created_at",
                    [row["investigation_id"]],
                ).fetchall()
                if _has_detections(conn)
                else []
            )
            # one rule per title: re-drafting the same investigation repeats them
            dets = list({d["title"]: d for d in dets}.values())
            allowed = factlib.ledger(inv) | {f"det:{d['id']}" for d in dets}
            known = {
                r["ext"]
                for r in conn.execute(
                    "SELECT data->'external_references'->0->>'external_id' AS ext FROM stix_objects "
                    "WHERE type = 'attack-pattern' AND NOT revoked"
                ).fetchall()
            }
            logs_path = inv.get("logs") or str(settings().logs_db)
            briefs = writer.write(conn, facts, inv["report"], dets)
            check = models.verify(conn, briefs, facts, allowed, logs_path, known)
            revisions = 0
            if not check["passed"] and row["mode"] == "live":
                briefs = writer.revise(briefs, check)
                check = models.verify(conn, briefs, facts, allowed, logs_path, known)
                revisions = 1
            conn.execute(
                "UPDATE briefs SET status = 'ready', facts = %s, technical = %s, executive = %s, verification = %s, "
                "revisions = %s, usage = %s WHERE id = %s",
                [
                    Jsonb(facts),
                    Jsonb(briefs["technical"]),
                    Jsonb(briefs["executive"]),
                    Jsonb(check),
                    revisions,
                    Jsonb(writer.usage()),
                    brief_id,
                ],
            )
        except Exception as e:  # recorded for the UI; traceback to the server log
            traceback.print_exc()
            conn.rollback()
            conn.execute(
                "UPDATE briefs SET status = 'failed', error = %s, usage = %s WHERE id = %s",
                [f"{type(e).__name__}: {e}"[:1000], Jsonb(writer.usage()), brief_id],
            )
        conn.commit()


def _has_detections(conn: psycopg.Connection) -> bool:
    return conn.execute("SELECT to_regclass('detections') IS NOT NULL AS ok").fetchone()["ok"]


def run_in_background(brief_id: str) -> threading.Thread:
    t = threading.Thread(target=run, args=(brief_id,), daemon=True, name=f"brief-{brief_id[:8]}")
    t.start()
    return t


def get(conn: psycopg.Connection, brief_id: str) -> dict[str, Any] | None:
    init_schema(conn)
    return conn.execute("SELECT * FROM briefs WHERE id = %s", [brief_id]).fetchone()


def latest_for(conn: psycopg.Connection, investigation_id: str) -> dict[str, Any] | None:
    init_schema(conn)
    return conn.execute(
        "SELECT * FROM briefs WHERE investigation_id = %s AND purpose = 'analyst' ORDER BY created_at DESC LIMIT 1",
        [investigation_id],
    ).fetchone()


def review(conn: psycopg.Connection, brief_id: str, decision: str, reviewer: str, note: str) -> dict[str, Any]:
    brief = get(conn, brief_id)
    if not brief:
        raise LookupError("no such brief")
    if decision == "approve" and brief["status"] not in ("ready", "approved"):
        raise ValueError("the brief isn't ready")
    if decision == "approve" and brief["verification"]["rejected"]:
        raise ValueError("fix or remove the rejected items before approving")
    conn.execute(
        "UPDATE briefs SET status = %s, reviewer = %s, review_note = %s, reviewed_at = now() WHERE id = %s",
        ["approved" if decision == "approve" else "rejected", reviewer, note or None, brief_id],
    )
    conn.commit()
    return get(conn, brief_id)


# ---------------------------------------------------------------- Markdown export


def _cite(ids: list[str]) -> str:
    return f" [{', '.join(ids)}]" if ids else ""


def markdown(brief: dict[str, Any], audience: str) -> str:
    status = "APPROVED" if brief["status"] == "approved" else "DRAFT - not approved"
    approved = f" by {brief['reviewer']}" if brief["status"] == "approved" else ""
    footer = (
        f"\n---\n*{status}{approved}. Generated by threat-intelligence-ai-platform ({brief['mode']} mode) from "
        f"investigation {brief['investigation_id']}. Bracketed IDs are the evidence behind each statement.*\n"
    )
    if audience == "executive":
        e = brief["executive"]
        lines = [
            f"# {e['headline']}",
            "",
            f"**Assessment.** {e['assessment']}",
            "",
            f"**Confidence: {e['confidence']}.** {e['confidence_basis']}",
            "",
            "## What happened",
        ]
        lines += [f"- {p['text']}{_cite(p['evidence_ids'])}" for p in e["key_points"]]
        lines += ["", "## Impact"] + [f"- {p['text']}{_cite(p['evidence_ids'])}" for p in e["impact"]]
        lines += ["", "## Decisions needed"] + [f"1. {d}" for d in e["decisions_needed"]]
        lines += ["", "## Next 24 hours"] + [f"- {n}" for n in e["next_24_hours"]]
        return "\n".join(lines) + "\n" + footer
    t = brief["technical"]
    lines = [
        f"# {t['title']}",
        "",
        t["summary"],
        "",
        "## Timeline (UTC)",
        "",
        "| When | What | ATT&CK | Evidence |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {x['when'][:16].replace('T', ' ')} | {x['what']} | {', '.join(x['technique_ids'])} | "
        f"{', '.join(x['evidence_ids'][:4])} |"
        for x in t["timeline"]
    ]
    lines += ["", "## Indicators", "", "| Type | Value | Context |", "|---|---|---|"]
    lines += [f"| {i['type']} | `{i['value']}` | {i['context']} |" for i in t["indicators"]]
    lines += ["", "## ATT&CK techniques", ""] + [
        f"- **{x['technique_id']} {x['name']}**: {x['how_used']}" for x in t["techniques"]
    ]
    if t["detections"]:
        lines += ["", "## Detections", ""] + [f"- {d['text']}" for d in t["detections"]]
    lines += ["", "## Actions", ""] + [f"1. {a}" for a in t["actions"]]
    if t["open_questions"]:
        lines += ["", "## Open questions", ""] + [f"- {q}" for q in t["open_questions"]]
    return "\n".join(lines) + "\n" + footer
