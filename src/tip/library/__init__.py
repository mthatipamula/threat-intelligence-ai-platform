"""Report library for RAG: public advisories, ATT&CK write-ups and Meridian's own incident history and runbooks.

Documents are split into passages (chunks) of a few paragraphs. Each chunk is stored with an embedding (pgvector) and a
full-text index, and searched both ways at once: semantic search finds passages that mean the same thing in different
words ("fake job offer" ~ "recruitment lure"), keyword search finds exact terms (T-numbers, "TraderTraitor", port
1224). The two rankings are merged with reciprocal rank fusion. Chunk IDs (doc-id#n) are what the agent cites.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
import psycopg
from bs4 import BeautifulSoup
from pgvector.psycopg import register_vector

from tip.collectors.base import fetch
from tip.library.embed import DIMENSIONS, embedder

INTERNAL_DIR = Path(__file__).parent / "internal"

# Public-domain US government reporting on North Korean operations against crypto companies.
ADVISORIES = [
    {
        "id": "cisa-aa22-108a",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a",
        "source": "CISA, FBI, US Treasury",
        "published": "2022-04-18",
    },
    {
        "id": "fbi-psa240903",
        "url": "https://www.ic3.gov/PSA/2024/PSA240903",
        "source": "FBI",
        "published": "2024-09-03",
    },
    {
        "id": "fbi-psa250226",
        "url": "https://www.ic3.gov/PSA/2025/PSA250226",
        "source": "FBI",
        "published": "2025-02-26",
    },
]
# ATT&CK objects worth a passage of their own: DPRK groups and campaigns, plus techniques seen in Meridian's logs.
ATTACK_TECHNIQUES = [
    "T1566.003",
    "T1204.002",
    "T1059.007",
    "T1105",
    "T1059.006",
    "T1555.003",
    "T1539",
    "T1041",
    "T1550.004",
    "T1555.006",
    "T1098.001",
    "T1657",
]

SCHEMA = f"""
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS documents (
    id        text PRIMARY KEY,
    title     text NOT NULL,
    kind      text NOT NULL,          -- advisory | attack | internal
    source    text NOT NULL,
    url       text,
    published date,
    sha256    text NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    id        text PRIMARY KEY,        -- <document id>#<n>
    doc_id    text NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    ordinal   integer NOT NULL,
    text      text NOT NULL,
    embedding vector({DIMENSIONS}) NOT NULL,
    tsv       tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED
);
CREATE INDEX IF NOT EXISTS chunks_embedding ON chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS chunks_tsv ON chunks USING gin (tsv);
"""


@dataclass
class Document:
    id: str
    title: str
    kind: str
    source: str
    url: str | None
    published: date | None
    text: str


def init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA)
    conn.commit()
    register_vector(conn)


# ---------------------------------------------------------------- loading documents


def html_to_text(html: str) -> tuple[str, str]:
    """(title, text) from an advisory page: the <main> content, one line per paragraph, list item or heading."""
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.find("h1") or soup.title).get_text(" ", strip=True)
    main = soup.select_one("main") or soup.body or soup
    for junk in main.select("nav, script, style, form, footer, .usa-banner, .c-page-title__share"):
        junk.decompose()
    lines, seen = [], set()
    for el in main.find_all(["h1", "h2", "h3", "h4", "p", "li", "td"]):
        if el.find(["p", "li"]):  # a container; its children are emitted on their own
            continue
        text = re.sub(r"\s+", " ", el.get_text(" ", strip=True)).strip()
        if len(text) > 2 and text not in seen:
            seen.add(text)
            lines.append(f"## {text}" if el.name in ("h2", "h3", "h4") else text)
    return title.split(" | ")[0].strip(), "\n".join(lines)


def advisories() -> list[Document]:
    docs = []
    for a in ADVISORIES:
        html = fetch(a["url"], f"{a['id']}.html", max_age_hours=24 * 30).read_text(errors="replace")
        title, text = html_to_text(html)
        title = re.sub(r"^Internet Crime Complaint Center \(IC3\)\s*", "", title) or a["id"]
        docs.append(
            Document(a["id"], title, "advisory", a["source"], a["url"], date.fromisoformat(a["published"]), text)
        )
    return docs


def internal() -> list[Document]:
    docs = []
    for path in sorted(INTERNAL_DIR.glob("*.md")):
        raw = path.read_text()
        meta = dict(re.findall(r'^(\w+): "?(.*?)"?$', raw.split("---")[1], re.M))
        body = raw.split("---", 2)[2].strip()
        docs.append(
            Document(
                path.stem,
                meta["title"],
                "internal",
                "Meridian Exchange (synthetic)",
                None,
                date.fromisoformat(meta["published"]),
                body,
            )
        )
    return docs


def attack_documents(conn: psycopg.Connection) -> list[Document]:
    """ATT&CK descriptions from the STIX store: North Korean groups and campaigns, and the techniques we hunt for."""
    rows = conn.execute(
        """
        SELECT id, type, name, data->>'description' AS description,
               data->'external_references'->0->>'external_id' AS ext, data->'external_references'->0->>'url' AS url
          FROM stix_objects
         WHERE source = 'mitre-attack' AND NOT revoked AND (
               (type IN ('intrusion-set', 'campaign') AND data->>'description' ~* 'north korea|dprk|lazarus')
            OR (type = 'attack-pattern' AND data->'external_references'->0->>'external_id' = ANY(%s)))
        """,
        [ATTACK_TECHNIQUES],
    ).fetchall()
    docs = []
    for r in rows:
        text = re.sub(r"\(Citation:[^)]*\)", "", r["description"] or "")
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text).strip()  # markdown links -> their text
        docs.append(
            Document(
                f"attack-{r['ext'].lower()}",
                f"ATT&CK {r['ext']}: {r['name']}",
                "attack",
                "MITRE ATT&CK",
                r["url"],
                None,
                f"{r['name']} ({r['ext']}, {r['type']}).\n{text}",
            )
        )
    return docs


def chunk(text: str, max_chars: int = 1400) -> list[str]:
    """Paragraph-aligned passages of up to max_chars, each starting with the most recent heading for context."""
    out, current, heading = [], "", ""
    for para in [p.strip() for p in text.split("\n") if p.strip()]:
        if para.startswith("## ") or para.startswith("# "):
            heading = para.lstrip("# ")
            if current:
                out.append(current)
                current = ""
            continue
        if current and len(current) + len(para) > max_chars:
            out.append(current)
            current = ""
        current = (current + "\n" + para) if current else (f"[{heading}] {para}" if heading else para)
    if current:
        out.append(current)
    return out


# ---------------------------------------------------------------- building and searching


def ingest(conn: psycopg.Connection, docs: list[Document]) -> int:
    """Store documents and their chunks; unchanged documents (same content hash) are skipped. Returns chunks written."""
    init_schema(conn)
    written = 0
    for doc in docs:
        digest = hashlib.sha256(f"{doc.title}\n{doc.text}".encode()).hexdigest()
        existing = conn.execute("SELECT sha256 FROM documents WHERE id = %s", [doc.id]).fetchone()
        if existing and existing["sha256"] == digest:
            continue
        passages = chunk(doc.text)
        vectors = embedder().embed([f"{doc.title}\n{p}" for p in passages])
        conn.execute("DELETE FROM documents WHERE id = %s", [doc.id])
        conn.execute(
            "INSERT INTO documents (id, title, kind, source, url, published, sha256) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            [doc.id, doc.title, doc.kind, doc.source, doc.url, doc.published, digest],
        )
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO chunks (id, doc_id, ordinal, text, embedding) VALUES (%s, %s, %s, %s, %s)",
                [(f"{doc.id}#{i}", doc.id, i, p, v) for i, (p, v) in enumerate(zip(passages, vectors, strict=True))],
            )
        written += len(passages)
    conn.commit()
    return written


def build(conn: psycopg.Connection) -> dict[str, int]:
    init_schema(conn)
    counts = {}
    for kind, loader in [("advisory", advisories), ("internal", internal), ("attack", lambda: attack_documents(conn))]:
        docs = loader()
        counts[kind] = len(docs)
        counts[f"{kind}_chunks_written"] = ingest(conn, docs)
    return counts


def search(
    conn: psycopg.Connection, query: str, limit: int = 5, kinds: list[str] | None = None
) -> list[dict[str, Any]]:
    """Hybrid search: semantic (cosine) and keyword (full text) rankings merged with reciprocal rank fusion."""
    register_vector(conn)
    vector = np.asarray(embedder().embed([query])[0], dtype=np.float32)
    kind_filter = "AND d.kind = ANY(%(kinds)s)" if kinds else ""
    return conn.execute(
        f"""
        WITH semantic AS (
            SELECT c.id, row_number() OVER (ORDER BY c.embedding <=> %(v)s) AS rank
              FROM chunks c JOIN documents d ON d.id = c.doc_id WHERE true {kind_filter}
             ORDER BY c.embedding <=> %(v)s LIMIT 30),
        keyword AS (  -- any of the query's words, ranked by how well they match
            SELECT c.id, row_number() OVER (ORDER BY ts_rank_cd(c.tsv, query.q) DESC) AS rank
              FROM chunks c JOIN documents d ON d.id = c.doc_id,
                   (SELECT replace(plainto_tsquery('english', %(q)s)::text, '&', '|')::tsquery AS q) query
             WHERE c.tsv @@ query.q {kind_filter}
             ORDER BY ts_rank_cd(c.tsv, query.q) DESC LIMIT 30),
        fused AS (
            SELECT id, sum(1.0 / (60 + rank)) AS score, count(*) AS matched_by
              FROM (SELECT * FROM semantic UNION ALL SELECT * FROM keyword) both_lists GROUP BY id)
        SELECT c.id, d.title, d.kind, d.source, d.url, d.published, c.text, round(f.score::numeric, 5) AS score,
               f.matched_by
          FROM fused f JOIN chunks c ON c.id = f.id JOIN documents d ON d.id = c.doc_id
         ORDER BY f.score DESC LIMIT %(limit)s
        """,
        {"v": vector, "q": query, "kinds": kinds, "limit": limit},
    ).fetchall()


def get_chunk(conn: psycopg.Connection, chunk_id: str) -> dict[str, Any] | None:
    return conn.execute(
        "SELECT c.id, c.text, d.id AS doc_id, d.title, d.kind, d.source, d.url, d.published "
        "FROM chunks c JOIN documents d ON d.id = c.doc_id WHERE c.id = %s",
        [chunk_id],
    ).fetchone()


def stats(conn: psycopg.Connection) -> list[dict[str, Any]]:
    return conn.execute(
        "SELECT d.kind, count(DISTINCT d.id) AS documents, count(c.id) AS chunks FROM documents d "
        "LEFT JOIN chunks c ON c.doc_id = d.id GROUP BY d.kind ORDER BY d.kind"
    ).fetchall()


__all__ = ["build", "search", "get_chunk", "stats", "Document", "chunk", "html_to_text", "ingest", "init_schema"]
