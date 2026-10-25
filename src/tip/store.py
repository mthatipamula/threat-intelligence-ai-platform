"""STIX 2.1 store in Postgres.

Every STIX object (including relationships) is one row: the full object as JSONB plus a few extracted columns for
fast lookups. Relationship endpoints and indicator values are generated columns, so they can't drift from the JSON.
Upserts keep the newest `modified` version and record when each object was first and last seen.
"""

from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from tip.config import settings
from tip.stix import to_dict

SCHEMA = """
CREATE TABLE IF NOT EXISTS stix_objects (
    id          text PRIMARY KEY,
    type        text NOT NULL,
    name        text,
    created     timestamptz,
    modified    timestamptz NOT NULL,
    revoked     boolean NOT NULL DEFAULT false,
    source      text NOT NULL,
    data        jsonb NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    source_ref  text GENERATED ALWAYS AS (data->>'source_ref') STORED,
    target_ref  text GENERATED ALWAYS AS (data->>'target_ref') STORED,
    relationship_type text GENERATED ALWAYS AS (data->>'relationship_type') STORED,
    observable_type   text GENERATED ALWAYS AS (data->'x_tip_observable'->>'type') STORED,
    observable_value  text GENERATED ALWAYS AS (lower(data->'x_tip_observable'->>'value')) STORED
);
CREATE INDEX IF NOT EXISTS stix_by_type ON stix_objects (type);
CREATE INDEX IF NOT EXISTS stix_by_name ON stix_objects (lower(name));
CREATE INDEX IF NOT EXISTS stix_rel_source ON stix_objects (source_ref) WHERE source_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS stix_rel_target ON stix_objects (target_ref) WHERE target_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS stix_observable ON stix_objects (observable_value) WHERE observable_value IS NOT NULL;
CREATE INDEX IF NOT EXISTS stix_data ON stix_objects USING gin (data jsonb_path_ops);

CREATE TABLE IF NOT EXISTS collection_runs (
    id          bigserial PRIMARY KEY,
    collector   text NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    status      text NOT NULL DEFAULT 'running',
    objects     integer NOT NULL DEFAULT 0,
    detail      text
);
"""

UPSERT = """
INSERT INTO stix_objects (id, type, name, created, modified, revoked, source, data)
VALUES (%(id)s, %(type)s, %(name)s, %(created)s, %(modified)s, %(revoked)s, %(source)s, %(data)s)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, created = EXCLUDED.created, modified = EXCLUDED.modified, revoked = EXCLUDED.revoked,
    source = EXCLUDED.source, data = EXCLUDED.data, last_seen = now()
WHERE EXCLUDED.modified >= stix_objects.modified
"""


@contextmanager
def connect(dsn: str | None = None):
    with psycopg.connect(dsn or settings().dsn, row_factory=dict_row) as conn:
        yield conn


def init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()


def _row(obj: dict[str, Any], source: str) -> dict[str, Any]:
    modified = obj.get("modified") or obj.get("created")
    return {
        "id": obj["id"],
        "type": obj["type"],
        "name": obj.get("name"),
        "created": obj.get("created"),
        "modified": modified,
        "revoked": bool(obj.get("revoked", False)),
        "source": source,
        "data": Jsonb(obj),
    }


def upsert(conn: psycopg.Connection, objects: Iterable[Any], source: str, batch: int = 1000) -> int:
    """Insert or update STIX objects (stix2 objects or dicts). Returns how many were written."""
    rows, written = [], 0
    with conn.cursor() as cur:
        for obj in objects:
            rows.append(_row(to_dict(obj), source))
            if len(rows) >= batch:
                cur.executemany(UPSERT, rows)
                written += len(rows)
                rows = []
        if rows:
            cur.executemany(UPSERT, rows)
            written += len(rows)
    conn.commit()
    return written


def start_run(conn: psycopg.Connection, collector: str) -> int:
    run_id = conn.execute("INSERT INTO collection_runs (collector) VALUES (%s) RETURNING id", [collector]).fetchone()[
        "id"
    ]
    conn.commit()
    return run_id


def finish_run(conn: psycopg.Connection, run_id: int, status: str, objects: int, detail: str | None = None) -> None:
    conn.execute(
        "UPDATE collection_runs SET finished_at = now(), status = %s, objects = %s, detail = %s WHERE id = %s",
        [status, objects, detail, run_id],
    )
    conn.commit()


# ---------------------------------------------------------------- queries


def stats(conn: psycopg.Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT source, type, count(*) AS objects, max(last_seen) AS last_seen FROM stix_objects "
        "GROUP BY source, type ORDER BY source, objects DESC"
    ).fetchall()


def last_runs(conn: psycopg.Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT DISTINCT ON (collector) collector, status, objects, started_at, finished_at, detail "
        "FROM collection_runs ORDER BY collector, started_at DESC"
    ).fetchall()


def get(conn: psycopg.Connection, stix_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT data FROM stix_objects WHERE id = %s", [stix_id]).fetchone()
    return row["data"] if row else None


def find_by_name(conn: psycopg.Connection, text: str, types: list[str] | None = None, limit: int = 20) -> list[dict]:
    """Objects whose name or ATT&CK aliases match (case-insensitive substring)."""
    sql = (
        "SELECT id, type, name, source FROM stix_objects WHERE NOT revoked AND type <> 'relationship' "
        "AND (name ILIKE %(q)s OR EXISTS (SELECT 1 FROM jsonb_array_elements_text("
        "coalesce(data->'aliases', data->'x_mitre_aliases', '[]'::jsonb)) a WHERE a ILIKE %(q)s))"
    )
    params: dict[str, Any] = {"q": f"%{text}%", "limit": limit}
    if types:
        sql += " AND type = ANY(%(types)s)"
        params["types"] = types
    sql += " ORDER BY (lower(name) = lower(%(exact)s)) DESC, length(name) LIMIT %(limit)s"
    params["exact"] = text
    return conn.execute(sql, params).fetchall()


def related(conn: psycopg.Connection, stix_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Relationships in either direction, with the object on the other end."""
    return conn.execute(
        """
        SELECT r.relationship_type, 'out' AS direction, o.type, o.data->'external_references'->0->>'external_id' AS ref,
               o.name, o.id
          FROM stix_objects r JOIN stix_objects o ON o.id = r.target_ref
         WHERE r.source_ref = %(id)s AND NOT r.revoked
        UNION ALL
        SELECT r.relationship_type, 'in', o.type, o.data->'external_references'->0->>'external_id', o.name, o.id
          FROM stix_objects r JOIN stix_objects o ON o.id = r.source_ref
         WHERE r.target_ref = %(id)s AND NOT r.revoked
        ORDER BY 1, 3, 4, 5 LIMIT %(limit)s
        """,
        {"id": stix_id, "limit": limit},
    ).fetchall()


def lookup_observable(conn: psycopg.Connection, value: str) -> list[dict[str, Any]]:
    """Exact (case-insensitive) match of a domain, IP, hash, URL or wallet address against stored indicators."""
    return conn.execute(
        "SELECT id, name, source, observable_type, data->'labels' AS labels, data->'confidence' AS confidence, "
        "data->'external_references'->0->>'url' AS reference FROM stix_objects "
        "WHERE observable_value = lower(%s) AND NOT revoked",
        [value],
    ).fetchall()
