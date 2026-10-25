"""`tip` command line: set up the store, collect intelligence, generate logs, and query both."""

import json
from typing import Annotated

import duckdb
import typer
from rich.console import Console
from rich.table import Table

from tip import collectors, store
from tip.config import settings
from tip.logs import generator

app = typer.Typer(no_args_is_help=True, help="Threat intelligence AI platform")
db_app = typer.Typer(no_args_is_help=True, help="STIX store database")
intel_app = typer.Typer(no_args_is_help=True, help="Query collected threat intelligence")
logs_app = typer.Typer(no_args_is_help=True, help="Synthetic internal logs (the SIEM stand-in)")
app.add_typer(db_app, name="db")
app.add_typer(intel_app, name="intel")
app.add_typer(logs_app, name="logs")
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


if __name__ == "__main__":
    app()
