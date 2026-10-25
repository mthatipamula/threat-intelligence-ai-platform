"""Shared plumbing for collectors: cached downloads and a common result shape."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from tip.config import settings

USER_AGENT = "threat-intelligence-ai-platform/0.1 (+https://github.com/mthatipamula/threat-intelligence-ai-platform)"


@dataclass
class Collected:
    """What a collector produced: STIX objects to store, plus a one-line summary for the run log."""

    objects: list[Any] = field(default_factory=list)
    summary: str = ""
    skipped: bool = False


def fetch(url: str, cache_name: str, max_age_hours: float = 24, timeout: float = 120) -> Path:
    """Download `url` into the cache unless a copy younger than `max_age_hours` exists. Returns the cached path."""
    path = settings().cache_dir / cache_name
    if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
        return path
    with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        response = client.get(url)
        response.raise_for_status()
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(response.content)
    tmp.replace(path)  # never leave a half-written cache file behind
    return path
