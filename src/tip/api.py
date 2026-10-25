"""HTTP API for the review console (and anyone else). Serves the built web UI from web/dist when it exists."""

import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from typing import Annotated, Any, Literal

import duckdb
import psycopg
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from tip import library, store
from tip.agent import graph
from tip.agent.brains import MODEL
from tip.agent.tools import LOG_TABLES, is_event_id, is_stix_id
from tip.config import ROOT, settings

app = FastAPI(title="Threat Intelligence AI Platform", version="0.2.0")
WEB_DIST = ROOT / "web" / "dist"


def db() -> Iterator[psycopg.Connection]:
    with store.connect() as conn:
        yield conn


DB = Annotated[psycopg.Connection, Depends(db)]


def _clean(text: str | None) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text).strip()


def live_available() -> bool:
    """Live mode needs Anthropic credentials: an API key, or a profile from `ant auth login`."""
    if settings().anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return True
    if shutil.which("ant"):
        status = subprocess.run(["ant", "auth", "status"], capture_output=True, text=True, timeout=10)
        return status.returncode == 0 and "no active" not in status.stdout.lower()
    return False


@app.get("/api/config")
def config() -> dict[str, Any]:
    return {"live_available": live_available(), "model": MODEL}


@app.get("/api/overview")
def overview(conn: DB) -> dict[str, Any]:
    library.init_schema(conn)
    with duckdb.connect(str(settings().logs_db), read_only=True) as logs:
        counts = {t: logs.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in LOG_TABLES}
        span = logs.execute("SELECT min(ts)::VARCHAR, max(ts)::VARCHAR FROM auth_events").fetchone()
        employees = logs.execute("SELECT count(*) FROM employees").fetchone()[0]
    return {
        "intel": store.stats(conn),
        "collection_runs": store.last_runs(conn),
        "library": library.stats(conn),
        "logs": {
            "tables": counts,
            "from": span[0],
            "to": span[1],
            "employees": employees,
            "company": "Meridian Exchange",
        },
    }


@app.get("/api/actors/{name}")
def actor(name: str, conn: DB) -> dict[str, Any]:
    found = store.find_by_name(conn, name, ["intrusion-set"], limit=1)
    if not found:
        raise HTTPException(404, f"No threat group matching {name!r}")
    obj = store.get(conn, found[0]["id"])
    rows = conn.execute(
        """
        SELECT o.type, o.name, o.data->'external_references'->0->>'external_id' AS ref,
               o.data->'external_references'->0->>'url' AS url, o.data->'kill_chain_phases' AS phases
          FROM stix_objects r JOIN stix_objects o ON o.id = r.target_ref
         WHERE r.source_ref = %(id)s AND r.relationship_type = 'uses' AND NOT r.revoked
        UNION ALL
        SELECT o.type, o.name, o.data->'external_references'->0->>'external_id',
               o.data->'external_references'->0->>'url', NULL
          FROM stix_objects r JOIN stix_objects o ON o.id = r.source_ref
         WHERE r.target_ref = %(id)s AND r.relationship_type = 'attributed-to' AND NOT r.revoked
        """,
        {"id": obj["id"]},
    ).fetchall()
    tactics: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        if r["type"] == "attack-pattern":
            for phase in r["phases"] or []:
                tactics.setdefault(phase["phase_name"], []).append({"id": r["ref"], "name": r["name"], "url": r["url"]})
    ref = obj["external_references"][0]
    return {
        "id": obj["id"],
        "name": obj["name"],
        "attack_id": ref.get("external_id"),
        "url": ref.get("url"),
        "aliases": obj.get("aliases", []),
        "description": _clean(obj.get("description")),
        "campaigns": [{"id": r["ref"], "name": r["name"], "url": r["url"]} for r in rows if r["type"] == "campaign"],
        "software": sorted({r["name"] for r in rows if r["type"] in ("malware", "tool")}),
        "tactics": [{"tactic": t, "techniques": sorted(v, key=lambda x: x["id"])} for t, v in tactics.items()],
        "technique_count": sum(1 for r in rows if r["type"] == "attack-pattern"),
    }


@app.get("/api/signals")
def signals(conn: DB) -> dict[str, Any]:
    library.init_schema(conn)
    lookalikes = conn.execute(
        "SELECT observable_value AS domain, data->'x_tip_resolved_ips' AS ips, data->'labels' AS labels, last_seen "
        "FROM stix_objects WHERE source = 'lookalike' AND type = 'indicator' AND NOT revoked "
        "ORDER BY observable_value LIMIT 50"
    ).fetchall()
    chains = conn.execute(
        "SELECT chain, count(*) AS addresses FROM stix_objects, jsonb_array_elements_text(data->'x_tip_chains') chain "
        "WHERE source = 'ofac' GROUP BY chain ORDER BY addresses DESC"
    ).fetchall()
    kev = conn.execute(
        "SELECT name AS cve, data->'x_cisa_kev'->>'vendor' AS vendor, data->'x_cisa_kev'->>'product' AS product, "
        "data->'x_cisa_kev'->>'date_added' AS added, data->'labels' ? 'ransomware' AS ransomware "
        "FROM stix_objects WHERE source = 'cisa-kev' AND type = 'vulnerability' "
        "ORDER BY data->'x_cisa_kev'->>'date_added' DESC, name DESC LIMIT 8"
    ).fetchall()
    advisories = conn.execute(
        "SELECT id, title, source, url, published FROM documents WHERE kind = 'advisory' ORDER BY published DESC"
    ).fetchall()
    return {
        "lookalike_domains": lookalikes,
        "watched_domains": settings().watched_domains,
        "sanctioned_addresses_by_chain": chains,
        "known_exploited": kev,
        "advisories": advisories,
    }


class InvestigationRequest(BaseModel):
    question: str = Field(min_length=5, max_length=500)
    mode: Literal["mock", "live"] = "mock"


@app.post("/api/investigations", status_code=202)
def start_investigation(req: InvestigationRequest, conn: DB) -> dict[str, str]:
    if req.mode == "live" and not live_available():
        raise HTTPException(400, "Live mode needs ANTHROPIC_API_KEY in .env (or `ant auth login`). Use mock mode.")
    run_id = graph.start(conn, req.question, req.mode)
    graph.run_in_background(run_id, req.question, req.mode)
    return {"id": run_id}


@app.get("/api/investigations")
def list_investigations(conn: DB) -> list[dict[str, Any]]:
    return graph.recent(conn)


@app.get("/api/investigations/{run_id}")
def get_investigation(run_id: str, conn: DB) -> dict[str, Any]:
    try:
        row = graph.get(conn, run_id)
    except psycopg.errors.InvalidTextRepresentation:
        row = None
    if not row:
        raise HTTPException(404, "No such investigation")
    return row


@app.get("/api/evidence/{evidence_id:path}")
def evidence(evidence_id: str, conn: DB) -> dict[str, Any]:
    """The raw record behind a citation: a log event, a STIX object or a report passage."""
    if is_event_id(evidence_id):
        with duckdb.connect(str(settings().logs_db), read_only=True) as logs:
            logs.execute("SET TimeZone = 'UTC'")
            for table in LOG_TABLES:
                cur = logs.execute(f"SELECT * FROM {table} WHERE event_id = ?", [evidence_id])
                row = cur.fetchone()
                if row:
                    rec = dict(zip([d[0] for d in cur.description], row, strict=True))
                    return {
                        "kind": "log",
                        "table": table,
                        "record": {k: str(v) if v is not None else None for k, v in rec.items()},
                    }
    elif is_stix_id(evidence_id):
        obj = store.get(conn, evidence_id)
        if obj:
            refs = obj.get("external_references") or []
            return {
                "kind": "intel",
                "type": obj["type"],
                "name": obj.get("name"),
                "description": _clean(obj.get("description"))[:1500],
                "url": refs[0].get("url") if refs else None,
                "record": obj,
            }
    elif "#" in evidence_id:
        library.init_schema(conn)
        chunk = library.get_chunk(conn, evidence_id)
        if chunk:
            return {**chunk, "doc_kind": chunk["kind"], "kind": "report"}
    raise HTTPException(404, f"No evidence {evidence_id!r}")


# ---------------------------------------------------------------- the built UI (npm run build in web/)

if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        file = (WEB_DIST / path).resolve()
        inside = file.is_relative_to(WEB_DIST.resolve())  # never serve anything outside web/dist (../ tricks)
        return FileResponse(file if path and inside and file.is_file() else WEB_DIST / "index.html")
