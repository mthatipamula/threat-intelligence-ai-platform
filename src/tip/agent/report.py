"""The investigation report the agent must produce, and the checks it must pass before anyone sees it as accepted.

The schema forces the shape (findings with evidence IDs, ATT&CK techniques, affected people and machines). The
verifier then checks the substance against what actually happened in this run:
  1. every finding cites at least one piece of evidence;
  2. every cited ID was returned by a tool during this investigation (catches invented or recycled IDs);
  3. every ATT&CK technique ID exists;
  4. people and hosts named as affected appear in the cited log events (catches claims bolted onto real evidence);
  5. the time given falls within the span of the cited log events.
A finding that fails any check is kept but marked rejected, with the reasons, so a reviewer sees what the AI tried to
claim and why it wasn't accepted.
"""

from datetime import datetime, timedelta
from typing import Any, Literal

import duckdb
import psycopg
from pydantic import BaseModel, Field

from tip.agent.tools import LOG_TABLES, is_event_id


class Finding(BaseModel):
    title: str = Field(description="Short headline, e.g. 'Malicious npm package ran on a developer laptop'")
    what_happened: str = Field(description="Plain-English account of what the cited evidence shows")
    when: str = Field(description="ISO 8601 UTC time of the earliest cited event")
    technique_ids: list[str] = Field(description="MITRE ATT&CK technique IDs, e.g. ['T1059.007']")
    severity: Literal["critical", "high", "medium", "low"]
    affected: list[str] = Field(description="User names and host names involved")
    evidence_ids: list[str] = Field(description="Event IDs, STIX IDs or report chunk IDs returned by the tools")


class ContextStatement(BaseModel):
    statement: str = Field(description="Background from threat intelligence or reports, e.g. who uses this technique")
    evidence_ids: list[str]


class InvestigationReport(BaseModel):
    verdict: Literal["confirmed-compromise", "suspicious-activity", "no-evidence-found"]
    confidence: Literal["high", "moderate", "low"]
    summary: str = Field(description="Three to five sentences for an executive reader")
    findings: list[Finding] = Field(description="In time order")
    context: list[ContextStatement]
    recommended_actions: list[str]
    open_questions: list[str] = Field(description="What the evidence does not answer yet")


def _event_rows(logs_path: str, ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch cited log events (any table) by event ID."""
    if not ids:
        return {}
    out: dict[str, dict[str, Any]] = {}
    with duckdb.connect(logs_path, read_only=True) as con:
        con.execute("SET TimeZone = 'UTC'")
        for table in LOG_TABLES:
            cur = con.execute(f"SELECT * FROM {table} WHERE event_id IN (SELECT unnest(?))", [ids])
            cols = [d[0] for d in cur.description]
            for row in cur.fetchall():
                rec = dict(zip(cols, row, strict=True))
                out[rec["event_id"]] = rec
    return out


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def verify(report: dict[str, Any], ledger: set[str], pg: psycopg.Connection, logs_path: str) -> dict[str, Any]:
    """Check each finding and context statement. Returns per-item status, reasons, and totals."""
    known_techniques = {
        r["ext"]
        for r in pg.execute(
            "SELECT data->'external_references'->0->>'external_id' AS ext FROM stix_objects "
            "WHERE type = 'attack-pattern' AND NOT revoked"
        ).fetchall()
    }
    all_event_ids = [i for f in report.get("findings", []) for i in f.get("evidence_ids", []) if is_event_id(i)]
    events = _event_rows(logs_path, all_event_ids)

    findings = []
    for f in report.get("findings", []):
        problems: list[str] = []
        cited = f.get("evidence_ids", [])
        if not cited:
            problems.append("cites no evidence")
        unseen = [i for i in cited if i not in ledger]
        if unseen:
            problems.append(f"cites evidence no tool returned in this investigation: {', '.join(unseen[:5])}")
        bad_tech = [t for t in f.get("technique_ids", []) if t.upper() not in known_techniques]
        if bad_tech:
            problems.append(f"unknown ATT&CK technique: {', '.join(bad_tech)}")
        cited_events = [events[i] for i in cited if i in events]
        if cited_events:
            people = {
                str(e.get(k))
                for e in cited_events
                for k in ("user_name", "host", "principal", "initiated_by", "account_id")
                if e.get(k)
            }
            not_in_evidence = [a for a in f.get("affected", []) if not any(a.lower() in p.lower() for p in people)]
            if not_in_evidence:
                problems.append(f"names {', '.join(not_in_evidence)} but no cited event involves them")
            when = _parse_time(f.get("when", ""))
            times = [e["ts"] for e in cited_events]
            if when is None:
                problems.append(f"time {f.get('when')!r} is not an ISO timestamp")
            elif not (min(times) - timedelta(minutes=5) <= when <= max(times) + timedelta(minutes=5)):
                problems.append(
                    f"time {f.get('when')} is outside the cited events ({min(times):%Y-%m-%d %H:%M} to "
                    f"{max(times):%Y-%m-%d %H:%M} UTC)"
                )
        findings.append({"status": "rejected" if problems else "accepted", "problems": problems})

    context = []
    for c in report.get("context", []):
        cited = c.get("evidence_ids", [])
        problems = ["cites no source"] if not cited else []
        unseen = [i for i in cited if i not in ledger]
        if unseen:
            problems.append(f"cites sources no tool returned: {', '.join(unseen[:5])}")
        context.append({"status": "rejected" if problems else "accepted", "problems": problems})

    accepted = sum(1 for f in findings if f["status"] == "accepted")
    return {
        "findings": findings,
        "context": context,
        "accepted": accepted,
        "rejected": len(findings) - accepted,
        "context_rejected": sum(1 for c in context if c["status"] == "rejected"),
        "passed": accepted == len(findings) and all(c["status"] == "accepted" for c in context),
    }
