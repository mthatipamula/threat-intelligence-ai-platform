"""`tip` command line: set up the store, collect intelligence, generate logs, and query both."""

import json
from typing import Annotated

import duckdb
import typer
from rich.console import Console
from rich.table import Table

from tip import briefs, collectors, detections, evals, library, store
from tip.agent import graph
from tip.config import settings
from tip.logs import generator

app = typer.Typer(no_args_is_help=True, help="Threat intelligence AI platform")
db_app = typer.Typer(no_args_is_help=True, help="STIX store database")
intel_app = typer.Typer(no_args_is_help=True, help="Query collected threat intelligence")
logs_app = typer.Typer(no_args_is_help=True, help="Synthetic internal logs (the SIEM stand-in)")
library_app = typer.Typer(no_args_is_help=True, help="Report library for RAG (advisories, ATT&CK, internal docs)")
detections_app = typer.Typer(no_args_is_help=True, help="Sigma detections: draft, test, review")
app.add_typer(db_app, name="db")
app.add_typer(intel_app, name="intel")
app.add_typer(logs_app, name="logs")
app.add_typer(library_app, name="library")
app.add_typer(detections_app, name="detections")
console = Console()


def _table(rows: list[dict], title: str | None = None) -> None:
    if not rows:
        console.print("[dim](no rows)[/dim]")
        return
    t = Table(title=title, show_lines=False)
    for col in rows[0]:
        t.add_column(str(col), overflow="fold")
    for r in rows:
        t.add_row(*["" if v is None else str(v) for v in r.values()])
    console.print(t)


@db_app.command("init")
def db_init() -> None:
    """Create the STIX store tables (safe to rerun)."""
    with store.connect() as conn:
        store.init_schema(conn)
    console.print("STIX store ready.")


@app.command()
def collect(
    names: Annotated[
        list[str] | None, typer.Argument(help=f"Collectors to run: {', '.join(collectors.COLLECTORS)}")
    ] = None,
) -> None:
    """Collect OSINT into the STIX store. With no names, runs all (ATT&CK first, so others can link to it)."""
    chosen = names or list(collectors.COLLECTORS)
    unknown = set(chosen) - set(collectors.COLLECTORS)
    if unknown:
        raise typer.BadParameter(f"unknown collector(s): {', '.join(sorted(unknown))}")
    failed = False
    with store.connect() as conn:
        store.init_schema(conn)
        for name in chosen:
            with console.status(f"collecting {name}..."):
                status, written, summary = collectors.run(conn, name)
            colour = {"ok": "green", "skipped": "yellow", "failed": "red"}[status]
            console.print(f"[{colour}]{status:7}[/{colour}] {name:10} {written:>7} objects  {summary}")
            failed |= status == "failed"
    raise typer.Exit(1 if failed else 0)


@intel_app.command("stats")
def intel_stats() -> None:
    """Objects per source and type, and each collector's last run."""
    with store.connect() as conn:
        _table(store.stats(conn), "STIX objects")
        _table(store.last_runs(conn), "Last collection runs")


@intel_app.command("search")
def intel_search(text: str, type_: Annotated[str | None, typer.Option("--type")] = None) -> None:
    """Find objects by name or alias, e.g. `tip intel search lazarus --type intrusion-set`."""
    with store.connect() as conn:
        _table(store.find_by_name(conn, text, [type_] if type_ else None))


@intel_app.command("show")
def intel_show(name_or_id: str, full: bool = False) -> None:
    """One object and everything it's related to, e.g. `tip intel show "Lazarus Group"`."""
    with store.connect() as conn:
        obj = store.get(conn, name_or_id)
        if obj is None:
            matches = store.find_by_name(conn, name_or_id, limit=1)
            obj = store.get(conn, matches[0]["id"]) if matches else None
        if obj is None:
            console.print(f"Nothing found for {name_or_id!r}")
            raise typer.Exit(1)
        if full:
            console.print_json(json.dumps(obj))
        else:
            refs = [r.get("external_id") or r.get("url") for r in obj.get("external_references", [])][:3]
            console.print(f"[bold]{obj.get('name')}[/bold]  ({obj['type']}, {obj['id']})")
            console.print(f"aliases: {', '.join(obj.get('aliases') or obj.get('x_mitre_aliases') or []) or '-'}")
            console.print(f"references: {', '.join(r for r in refs if r) or '-'}")
            console.print((obj.get("description") or "")[:600])
        _table(store.related(conn, obj["id"]), "Relationships")


@intel_app.command("lookup")
def intel_lookup(value: str) -> None:
    """Is this domain, IP, hash, URL or wallet address in our intelligence?"""
    with store.connect() as conn:
        rows = store.lookup_observable(conn, value)
    _table(rows) if rows else console.print(f"No intelligence on {value}")


@logs_app.command("generate")
def logs_generate(seed: int = 7, days: int = 7) -> None:
    """Generate the synthetic Meridian Exchange logs (with the hidden attack) into data/logs.duckdb."""
    counts = generator.generate(settings().data_dir / "logs", settings().logs_db, seed=seed, days=days)
    _table([{"table": k, "rows": v} for k, v in counts.items()], "data/logs.duckdb")


@logs_app.command("sql")
def logs_sql(query: str, limit: int = 50) -> None:
    """Run read-only SQL against the logs, e.g. `tip logs sql "SELECT * FROM auth_events LIMIT 5"`."""
    with duckdb.connect(str(settings().logs_db), read_only=True) as con:
        con.execute("SET TimeZone = 'UTC'")  # log timestamps are UTC; don't show them in the laptop's zone
        cur = con.execute(query)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchmany(limit)]
    _table(rows)


@logs_app.command("baseline")
def logs_baseline() -> None:
    """Generate a fresh normal-only week (no attack) for testing detections against false alarms."""
    counts = generator.generate(
        settings().data_dir / "baseline",
        settings().baseline_db,
        seed=generator.BASELINE_SEED,
        start=generator.BASELINE_START,
        with_attack=False,
    )
    _table([{"table": k, "rows": v} for k, v in counts.items()], "data/baseline.duckdb")


@detections_app.command("draft")
def detections_draft(
    investigation: Annotated[str | None, typer.Option(help="Investigation id (default: the latest finished)")] = None,
    live: Annotated[bool, typer.Option(help="Use Claude instead of the mock templates")] = False,
) -> None:
    """Draft and replay-test a rule for each behaviour in an investigation's verified findings."""
    with store.connect() as conn:
        if investigation is None:
            row = conn.execute(
                "SELECT id FROM investigations WHERE status = 'done' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                raise typer.BadParameter("no finished investigation: run `tip investigate` first")
            investigation = str(row["id"])
        batch = detections.start_batch(conn, investigation)
    with console.status("drafting and testing rules..."):
        detections.run_batch(batch, investigation, "live" if live else "mock")
    with store.connect() as conn:
        rows = detections.listing(conn, batch)
    _table(
        [
            {
                "status": d["status"],
                "rule": d["title"],
                "caught": (d["test"] or {}).get("attack_events_caught"),
                "false alarms": (d["test"] or {}).get("false_alarms"),
                "fresh week": (d["test"] or {}).get("fresh_week_alarms"),
                "attempts": len(d["attempts"]),
                "id": str(d["id"])[:8],
            }
            for d in rows
        ],
        f"Batch {batch}",
    )


@detections_app.command("test")
def detections_test(path: str) -> None:
    """Convert and replay-test any Sigma rule file, e.g. `tip detections test detections/my_rule.yml`."""
    from pathlib import Path

    result = detections.evaluate(Path(path).read_text())
    t = result["test"]
    console.print(
        f"[bold]{result['title']}[/bold]: {t['verdict']} {('- ' + '; '.join(t['reasons'])) if t['reasons'] else ''}"
    )
    console.print({k: t.get(k) for k in ("table", "attack_events_caught", "false_alarms", "fresh_week_alarms")})
    translations = result["translations"]
    for target in ("sql", "spl", "kql"):
        console.print(f"[bold]{target.upper()}[/bold]\n{translations[target] or translations['errors'].get(target)}")


@detections_app.command("review")
def detections_review(detection_id: str, approve: bool = True, reviewer: str = "analyst", note: str = "") -> None:
    """Approve (writes detections/<rule>.yml) or reject (--no-approve) a tested rule. Accepts an id prefix."""
    with store.connect() as conn:
        detections.init_schema(conn)
        row = conn.execute("SELECT id FROM detections WHERE id::text LIKE %s", [detection_id + "%"]).fetchone()
        if not row:
            raise typer.BadParameter("no such detection")
        d = detections.review(conn, str(row["id"]), "approve" if approve else "reject", reviewer, note)
    console.print(f"{d['status']}: {d['title']}" + (f" -> {d['approved_path']}" if d["approved_path"] else ""))


@app.command()
def brief(
    investigation: Annotated[str | None, typer.Option(help="Investigation id (default: the latest finished)")] = None,
    live: Annotated[bool, typer.Option(help="Use Claude instead of the mock templates")] = False,
    audience: Annotated[str, typer.Option(help="executive or technical")] = "executive",
) -> None:
    """Write and check both briefs for an investigation, and print one as Markdown."""
    with store.connect() as conn:
        if investigation is None:
            row = conn.execute(
                "SELECT id FROM investigations WHERE status = 'done' AND purpose = 'analyst' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                raise typer.BadParameter("no finished investigation: run `tip investigate` first")
            investigation = str(row["id"])
        brief_id = briefs.start(conn, investigation, "live" if live else "mock")
    with console.status("writing and checking briefs..."):
        briefs.run(brief_id)
    with store.connect() as conn:
        row = briefs.get(conn, brief_id)
    if row["status"] != "ready":
        console.print(f"[red]{row['status']}[/red]: {row['error']}")
        raise typer.Exit(1)
    console.print(briefs.markdown(row, audience))
    v = row["verification"]
    console.print(
        f"{v['accepted']} cited items accepted, {v['rejected']} rejected; warnings: {v['warnings'] or 'none'}"
    )


@app.command(name="eval")
def evaluate(live: Annotated[bool, typer.Option(help="Use Claude (costs money)")] = False) -> None:
    """Run the evaluation (accuracy, no-attack week, prompt injection, detections, briefs) and print the gates."""
    mode = "live" if live else "mock"
    with store.connect() as conn:
        run_id = evals.start(conn, mode)
    with console.status(f"evaluating ({mode})..."):
        evals.run(run_id, mode)
    with store.connect() as conn:
        row = evals.get(conn, run_id)
    if row["status"] != "done":
        console.print(f"[red]failed[/red]: {row['error']}")
        raise typer.Exit(1)
    _table(
        [
            {"gate": g["label"], "status": g["status"], "value": g["value"], "threshold": g["threshold"]}
            for g in row["results"]["gates"]
        ],
        f"Evaluation ({mode})",
    )
    console.print(f"Cost: ${row['results']['cost_usd']}. Run id {run_id}")


def readiness() -> dict[str, object]:
    """What a demo needs, and whether it's there."""
    from tip.api import WEB_DIST, live_available

    out: dict[str, object] = {"database": False, "intel_objects": 0, "library_chunks": 0}
    try:
        with store.connect() as conn:
            store.init_schema(conn)
            library.init_schema(conn)
            out["database"] = True
            out["intel_objects"] = conn.execute("SELECT count(*) AS n FROM stix_objects").fetchone()["n"]
            out["library_chunks"] = conn.execute("SELECT count(*) AS n FROM chunks").fetchone()["n"]
    except Exception as e:  # report, don't crash: doctor exists to explain what's missing
        out["database_error"] = str(e).split("\n")[0]
    out["logs"] = settings().logs_db.exists()
    out["baseline"] = settings().baseline_db.exists()
    out["web_built"] = (WEB_DIST / "index.html").exists()
    out["live_mode"] = live_available()
    return out


@app.command()
def doctor(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Check everything the demo needs: database, intelligence, logs, report library, built UI, live mode."""
    r = readiness()
    if as_json:
        console.print_json(json.dumps(r))
        return
    checks = [
        ("Postgres reachable", r["database"], "docker compose up -d --wait"),
        ("Threat intelligence collected", int(r["intel_objects"]) > 1000, "./tip collect"),
        ("Report library built", int(r["library_chunks"]) > 0, "./tip library build"),
        ("Synthetic logs", r["logs"], "./tip logs generate"),
        ("Fresh normal week", r["baseline"], "./tip logs baseline"),
        ("Web UI built", r["web_built"], "(cd web && npm install && npm run build)"),
        ("Live mode (Claude)", r["live_mode"], "optional: add ANTHROPIC_API_KEY to .env"),
    ]
    for label, ok, fix in checks:
        mark = "[green]✓[/green]" if ok else "[red]✕[/red]"
        console.print(f"{mark} {label}" + ("" if ok else f"  [dim]→ {fix}[/dim]"))


@app.command()
def reset(yes: Annotated[bool, typer.Option("--yes", help="Don't ask")] = False) -> None:
    """Clear demo history: investigations, detection drafts, briefs, evaluation runs, approved rule files."""
    from tip import briefs, evals
    from tip.agent import graph as agent_graph
    from tip.config import ROOT

    if not yes and not typer.confirm("Delete all investigations, detections, briefs and evaluation runs?"):
        raise typer.Exit(1)
    with store.connect() as conn:
        for init in (agent_graph.init_schema, detections.init_schema, briefs.init_schema, evals.init_schema):
            init(conn)
        conn.execute("TRUNCATE investigations, detections, briefs, eval_runs")
        conn.commit()
    removed = [p.name for p in (ROOT / "detections").glob("*.yml")]
    for name in removed:
        (ROOT / "detections" / name).unlink()
    console.print(f"Cleared. Removed {len(removed)} approved rule file(s).")


@library_app.command("build")
def library_build() -> None:
    """Fetch advisories, load internal docs and ATT&CK write-ups, chunk and embed them (first run downloads the "
    "model)."""
    with store.connect() as conn, console.status("building the report library..."):
        counts = library.build(conn)
    console.print(counts)
    with store.connect() as conn:
        _table(library.stats(conn), "Report library")


@library_app.command("search")
def library_search(query: str, limit: int = 5) -> None:
    """Hybrid (semantic + keyword) search, e.g. `tip library search "fake recruiter coding test"`."""
    with store.connect() as conn:
        rows = library.search(conn, query, limit=limit)
    _table([{"chunk": r["id"], "score": r["score"], "title": r["title"], "text": r["text"][:160]} for r in rows])


@app.command()
def investigate(
    question: str, live: Annotated[bool, typer.Option(help="Use Claude instead of mock mode")] = False
) -> None:
    """Run an investigation in the terminal, e.g. `tip investigate "Are we affected by fake job interview attacks?"`."""
    mode = "live" if live else "mock"
    with store.connect() as conn:
        run_id = graph.start(conn, question, mode)
    with console.status(f"investigating ({mode})..."):
        graph.run(run_id, question, mode)
    with store.connect() as conn:
        r = graph.get(conn, run_id)
    if r["status"] != "done":
        console.print(f"[red]{r['status']}[/red]: {r['error']}")
        raise typer.Exit(1)
    report, check = r["report"], r["verification"]
    console.print(f"[bold]{report['verdict']}[/bold] (confidence {report['confidence']})\n{report['summary']}\n")
    _table(
        [
            {
                "status": c["status"],
                "when": f["when"][:16],
                "severity": f["severity"],
                "finding": f["title"],
                "evidence": ", ".join(f["evidence_ids"][:4]),
                "problems": "; ".join(c["problems"]),
            }
            for f, c in zip(report["findings"], check["findings"], strict=True)
        ],
        "Findings",
    )
    console.print(f"{check['accepted']} accepted, {check['rejected']} rejected. Usage: {r['usage']}. Run id {run_id}")


@app.command()
def serve(port: int = 8000, reload: bool = False) -> None:
    """Start the API (and the built web UI, if web/dist exists) on http://localhost:PORT."""
    import uvicorn

    uvicorn.run("tip.api:app", host="127.0.0.1", port=port, reload=reload)


if __name__ == "__main__":
    app()
