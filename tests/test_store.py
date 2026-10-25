import uuid
from datetime import timedelta

import psycopg
import pytest

from tip import stix, store
from tip.config import settings


@pytest.fixture
def conn():
    """A throwaway schema in the compose Postgres, so tests never touch collected data."""
    try:
        c = psycopg.connect(settings().dsn, row_factory=psycopg.rows.dict_row, connect_timeout=3)
    except (psycopg.OperationalError, RuntimeError):
        pytest.skip("Postgres not running (docker compose up -d)")
    schema = f"test_{uuid.uuid4().hex[:8]}"
    c.execute(f"CREATE SCHEMA {schema}")
    c.execute(f"SET search_path TO {schema}")
    store.init_schema(c)
    yield c
    c.rollback()
    c.execute(f"DROP SCHEMA {schema} CASCADE")
    c.commit()
    c.close()


pytestmark = pytest.mark.db


def test_upsert_is_idempotent_and_keeps_the_newest_version(conn):
    ind = stix.indicator(
        "lookalike", "domain-name", "c0inbase.com", name="old", description="d", indicator_types=["anomalous-activity"]
    )
    assert store.upsert(conn, [ind], "lookalike") == 1
    store.upsert(conn, [ind], "lookalike")
    assert conn.execute("SELECT count(*) AS n FROM stix_objects").fetchone()["n"] == 1

    newer = ind.new_version(name="new", modified=ind.modified + timedelta(seconds=1))
    store.upsert(conn, [newer], "lookalike")
    older = stix.to_dict(ind) | {"name": "stale", "modified": "2000-01-01T00:00:00.000Z"}
    store.upsert(conn, [older], "lookalike")
    assert store.get(conn, ind.id)["name"] == "new"


def test_lookup_and_relationships(conn):
    actor = {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": "intrusion-set--c93fccb1-e8e8-42cf-ae33-2ad1d183913a",
        "name": "Lazarus Group",
        "aliases": ["Diamond Sleet"],
        "created": "2017-05-31T21:31:45.629Z",
        "modified": "2025-04-16T20:37:16.840Z",
        "external_references": [{"source_name": "mitre-attack", "external_id": "G0032"}],
    }
    wallet = stix.indicator(
        "ofac",
        "crypto-wallet",
        "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
        name="w",
        description="d",
        indicator_types=["attribution"],
        labels=["sanctioned"],
    )
    rel = stix.relationship("ofac", wallet.id, "indicates", actor["id"])
    store.upsert(conn, [actor, wallet, rel], "test")

    hit = store.lookup_observable(conn, "0x098b716b8aaf21512996dc57eb0615e2383e2f96")
    assert [h["id"] for h in hit] == [wallet.id]
    assert store.find_by_name(conn, "diamond sleet")[0]["name"] == "Lazarus Group"
    rels = store.related(conn, actor["id"])
    assert [(r["relationship_type"], r["direction"], r["id"]) for r in rels] == [("indicates", "in", wallet.id)]


def test_collection_runs_are_recorded(conn):
    run = store.start_run(conn, "kev")
    store.finish_run(conn, run, "ok", 3, "fine")
    assert store.last_runs(conn)[0]["status"] == "ok"
