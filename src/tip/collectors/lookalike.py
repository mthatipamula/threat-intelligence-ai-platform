"""Lookalike domains for watched brands: typosquats and impersonation names that are registered and resolve.

Generates candidates the way phishing crews pick them (dropped/doubled/swapped letters, look-alike characters,
"-login"/"-support"/"-careers" words, other TLDs, Cyrillic homoglyphs), then resolves them in DNS. A resolving domain
is only a lead: brands often register their own typos defensively, so every hit is low-confidence and "needs-triage".
crt.sh (certificate transparency search) can add certificate history, but it is often slow, so it's opt-in.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver
import httpx

from tip import stix
from tip.collectors.base import USER_AGENT, Collected

HOMOGLYPHS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "m": ["rn"],
    "w": ["vv"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5"],
}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у"}
KEYWORDS = [
    "login",
    "signin",
    "secure",
    "verify",
    "support",
    "help",
    "wallet",
    "app",
    "careers",
    "jobs",
    "recovery",
    "kyc",
]
TLDS = ["com", "net", "org", "io", "co", "app", "xyz", "info", "online", "site", "us", "pro"]


def candidates(domain: str) -> dict[str, str]:
    """Lookalike domain -> how it was made (the technique), excluding the domain itself."""
    name, _, tld = domain.lower().partition(".")
    out: dict[str, str] = {}

    def add(label: str, kind: str, suffix: str = tld) -> None:
        candidate = f"{label}.{suffix}"
        if label and candidate != domain and candidate not in out:
            out[candidate] = kind

    for i in range(len(name)):
        add(name[:i] + name[i + 1 :], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2 :], "transposition")
        for glyph in HOMOGLYPHS.get(name[i], []):
            add(name[:i] + glyph + name[i + 1 :], "homoglyph")
        if name[i] in CYRILLIC:
            unicode_label = name[:i] + CYRILLIC[name[i]] + name[i + 1 :]
            add(unicode_label.encode("idna").decode("ascii"), "idn-homoglyph")
    for word in KEYWORDS:
        add(f"{name}-{word}", "keyword")
        add(f"{word}-{name}", "keyword")
        add(f"{name}{word}", "keyword")
    for other in TLDS:
        if other != tld:
            add(name, "tld-swap", other)
    return out


def resolve(domain: str, timeout: float = 3.0) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        return sorted(r.to_text() for r in resolver.resolve(domain, "A"))
    except (dns.exception.DNSException, UnicodeError):
        return []


def crtsh_names(brand: str, retries: int = 3) -> set[str]:
    """Certificate names containing the brand label, from crt.sh (best effort; empty set when it's unavailable)."""
    label = brand.partition(".")[0]
    for _ in range(retries):
        try:
            r = httpx.get(
                "https://crt.sh/",
                params={"q": f"%{label}%", "output": "json", "exclude": "expired"},
                timeout=60,
                headers={"User-Agent": USER_AGENT},
            )
            if r.status_code == 200:
                names = {n.strip().lower().lstrip("*.") for e in r.json() for n in e.get("name_value", "").split("\n")}
                return {n for n in names if label in n and not n.endswith(brand)}
        except (httpx.HTTPError, ValueError):
            pass
    return set()


def to_indicator(brand: str, domain: str, kind: str, ips: list[str]) -> Any:
    return stix.indicator(
        "lookalike",
        "domain-name",
        domain,
        name=f"Lookalike of {brand}: {domain}",
        description=(
            f"Registered domain resembling {brand} ({kind}), resolving to {', '.join(ips) or 'no A record'}. "
            "Unverified: may be a defensive registration by the brand owner."
        ),
        indicator_types=["anomalous-activity"],
        labels=["lookalike", "needs-triage", f"brand:{brand}", f"technique:{kind}"],
        confidence=30,
        reference_url=f"https://crt.sh/?q={domain}",
        extra={"x_tip_resolved_ips": ips},
    )


def collect(brands: list[str], use_crtsh: bool = False, workers: int = 48) -> Collected:
    objects: list[Any] = [stix.identity("lookalike")]
    lines = []
    for brand in brands:
        cands = candidates(brand)
        if use_crtsh:
            for name in crtsh_names(brand):
                cands.setdefault(name, "certificate-transparency")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            resolved = dict(zip(cands, pool.map(resolve, cands), strict=True))
        hits = {d: ips for d, ips in resolved.items() if ips}
        objects += [to_indicator(brand, d, cands[d], ips) for d, ips in sorted(hits.items())]
        lines.append(f"{brand}: {len(hits)} of {len(cands)} candidates resolve")
    return Collected(objects, "; ".join(lines))
