"""Collector registry. Each run is recorded in collection_runs, so failures are visible rather than silent."""

from collections.abc import Callable

import psycopg

from tip import store
from tip.collectors import attack, kev, lookalike, ofac, threatfox
from tip.collectors.base import Collected
from tip.config import settings


def _attack_malware(conn: psycopg.Connection) -> dict[str, str]:
    """ATT&CK malware names and aliases (lower-cased) -> STIX id, for linking ThreatFox families."""
    rows = conn.execute(
        "SELECT id, name, data->'x_mitre_aliases' AS aliases FROM stix_objects "
        "WHERE type = 'malware' AND source = 'mitre-attack' AND NOT revoked"
    ).fetchall()
    out: dict[str, str] = {}
    for r in rows:
        for alias in [r["name"], *(r["aliases"] or [])]:
            out.setdefault(alias.lower(), r["id"])
    return out


COLLECTORS: dict[str, Callable[[psycopg.Connection], Collected]] = {
    "attack": lambda conn: attack.collect(),
    "kev": lambda conn: kev.collect(),
    "ofac": lambda conn: ofac.collect(),
    "threatfox": lambda conn: threatfox.collect(_attack_malware(conn)),
    "lookalike": lambda conn: lookalike.collect(settings().watched_domains),
}

SOURCE_OF = {
    "attack": "mitre-attack",
    "kev": "cisa-kev",
    "ofac": "ofac",
    "threatfox": "threatfox",
    "lookalike": "lookalike",
}


def run(conn: psycopg.Connection, name: str) -> tuple[str, int, str]:
    """Run one collector and store its objects. Returns (status, objects written, summary)."""
    run_id = store.start_run(conn, name)
    try:
        result = COLLECTORS[name](conn)
        if result.skipped:
            store.finish_run(conn, run_id, "skipped", 0, result.summary)
            return "skipped", 0, result.summary
        written = store.upsert(conn, result.objects, SOURCE_OF[name])
        store.finish_run(conn, run_id, "ok", written, result.summary)
        return "ok", written, result.summary
    except Exception as e:  # recorded, then reported; one failing feed shouldn't stop the others
        conn.rollback()
        store.finish_run(conn, run_id, "failed", 0, f"{type(e).__name__}: {e}"[:500])
        return "failed", 0, f"{type(e).__name__}: {e}"
