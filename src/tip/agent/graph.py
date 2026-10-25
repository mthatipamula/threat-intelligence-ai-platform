"""Investigation workflow (LangGraph): investigate -> draft -> verify -> [revise -> verify] -> done.

The graph makes the control flow explicit and testable: the model never decides whether its own report is accepted.
Verification is plain code; a rejected draft goes back to the model once (live mode) with the reasons, and whatever
still fails stays visibly rejected.

Each investigation is a row in Postgres (status, live progress, tool trace, report, verification, token usage), so
the API and UI can follow it while it runs and show it afterwards.
"""

import threading
import traceback
import uuid
from dataclasses import asdict
from typing import Any, TypedDict

import psycopg
from langgraph.graph import END, START, StateGraph
from psycopg.types.json import Jsonb

from tip import store
from tip.agent.brains import Brain, ClaudeBrain, MockBrain
from tip.agent.report import verify
from tip.agent.tools import Toolbox

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id           uuid PRIMARY KEY,
    question     text NOT NULL,
    mode         text NOT NULL,
    status       text NOT NULL,          -- queued | investigating | drafting | verifying | revising | done | failed
    progress     jsonb NOT NULL DEFAULT '[]',
    trace        jsonb NOT NULL DEFAULT '[]',
    report       jsonb,
    verification jsonb,
    revisions    integer NOT NULL DEFAULT 0,
    usage        jsonb,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);
-- added in step 4: prompt-injection warnings, and runs made by the evaluation (kept out of the analyst's history)
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS injection_warnings jsonb NOT NULL DEFAULT '[]';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'analyst';
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS logs text;
"""
MAX_REVISIONS = 1


class State(TypedDict, total=False):
    question: str
    report: dict[str, Any]
    verification: dict[str, Any]
    revisions: int


def init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()


class Recorder:
    """Writes progress to the investigation's row as it happens (own connection: the run is on a worker thread)."""

    def __init__(self, conn: psycopg.Connection, run_id: str):
        self.conn, self.run_id = conn, run_id

    def update(self, **fields: Any) -> None:
        sets = ", ".join(f"{k} = %({k})s" for k in fields)
        params = {k: Jsonb(v) if isinstance(v, (dict, list)) else v for k, v in fields.items()}
        self.conn.execute(f"UPDATE investigations SET {sets} WHERE id = %(id)s", {**params, "id": self.run_id})
        self.conn.commit()

    def progress(self, line: str) -> None:
        self.conn.execute(
            "UPDATE investigations SET progress = progress || %s WHERE id = %s", [Jsonb([line]), self.run_id]
        )
        self.conn.commit()


def build_graph(brain: Brain, tools: Toolbox, rec: Recorder, logs_path: str):
    def investigate(state: State) -> State:
        rec.update(status="investigating")
        brain.investigate(state["question"], tools, rec.progress)
        rec.update(trace=[asdict(c) for c in tools.trace])
        return {}

    def draft(state: State) -> State:
        rec.update(status="drafting")
        rec.progress("drafting the report")
        return {"report": brain.draft(state["question"], tools), "revisions": 0}

    def check(state: State) -> State:
        rec.update(status="verifying")
        result = verify(state["report"], tools.ledger, tools.pg, logs_path)
        rec.progress(f"verification: {result['accepted']} findings accepted, {result['rejected']} rejected")
        return {"verification": result}

    def revise(state: State) -> State:
        rec.update(status="revising")
        rec.progress("sending rejected findings back to the model")
        report = brain.revise(state["report"], state["verification"], tools)
        rec.update(trace=[asdict(c) for c in tools.trace])
        return {"report": report, "revisions": state["revisions"] + 1}

    def after_check(state: State) -> str:
        if state["verification"]["passed"] or not brain.can_revise or state["revisions"] >= MAX_REVISIONS:
            return END
        return "revise"

    g = StateGraph(State)
    g.add_node("investigate", investigate)
    g.add_node("draft", draft)
    g.add_node("verify", check)
    g.add_node("revise", revise)
    g.add_edge(START, "investigate")
    g.add_edge("investigate", "draft")
    g.add_edge("draft", "verify")
    g.add_conditional_edges("verify", after_check, {"revise": "revise", END: END})
    g.add_edge("revise", "verify")
    return g.compile()


def start(conn: psycopg.Connection, question: str, mode: str, purpose: str = "analyst", logs: str | None = None) -> str:
    init_schema(conn)
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO investigations (id, question, mode, status, purpose, logs) VALUES (%s, %s, %s, 'queued', %s, %s)",
        [run_id, question, mode, purpose, logs],
    )
    conn.commit()
    return run_id


def run(run_id: str, question: str, mode: str, dsn: str | None = None, logs_path: str | None = None) -> None:
    """Run one investigation to completion, recording everything. Never raises: failures are stored on the row."""
    from tip.config import settings

    logs_path = logs_path or str(settings().logs_db)
    with store.connect(dsn) as pg, store.connect(dsn) as rec_conn:
        rec = Recorder(rec_conn, run_id)
        brain: Brain = ClaudeBrain() if mode == "live" else MockBrain()
        tools = Toolbox(pg, logs_path)
        try:
            final = build_graph(brain, tools, rec, logs_path).invoke({"question": question})
            rec.update(
                status="done",
                report=final["report"],
                verification=final["verification"],
                revisions=final.get("revisions", 0),
                usage=brain.usage(),
                trace=[asdict(c) for c in tools.trace],
                injection_warnings=tools.injection_warnings,
                finished_at="now",
            )
        except Exception as e:  # recorded for the UI; the traceback goes to the server log
            traceback.print_exc()
            rec.update(
                status="failed",
                error=f"{type(e).__name__}: {e}"[:1000],
                usage=brain.usage(),
                trace=[asdict(c) for c in tools.trace],
                finished_at="now",
            )


def run_in_background(run_id: str, question: str, mode: str) -> threading.Thread:
    t = threading.Thread(target=run, args=(run_id, question, mode), daemon=True, name=f"investigation-{run_id[:8]}")
    t.start()
    return t


def get(conn: psycopg.Connection, run_id: str) -> dict[str, Any] | None:
    init_schema(conn)
    return conn.execute("SELECT * FROM investigations WHERE id = %s", [run_id]).fetchone()


def recent(conn: psycopg.Connection, limit: int = 20) -> list[dict[str, Any]]:
    init_schema(conn)
    return conn.execute(
        "SELECT id, question, mode, status, created_at, finished_at, verification->'accepted' AS accepted, "
        "verification->'rejected' AS rejected, report->>'verdict' AS verdict, "
        "jsonb_array_length(injection_warnings) AS injection_warnings FROM investigations "
        "WHERE purpose = 'analyst' ORDER BY created_at DESC LIMIT %s",
        [limit],
    ).fetchall()
