"""Brief formats and the checks every brief must pass before a person can approve it."""

import re
from typing import Any, Literal

import psycopg
from pydantic import BaseModel, Field

from tip.briefs import facts as factlib

# ICD 203 (US intelligence community analytic standards) words for likelihood. Assessments should use them rather than
# vague words ("possibly", "might"), so readers know how sure the analyst is.
ESTIMATIVE = [
    "almost no chance",
    "very unlikely",
    "unlikely",
    "roughly even chance",
    "likely",
    "very likely",
    "almost certainly",
    "remote",
    "highly improbable",
    "improbable",
    "probable",
    "highly probable",
    "nearly certain",
]


class Cited(BaseModel):
    text: str
    evidence_ids: list[str] = Field(description="Evidence IDs from the investigation (or det:<id> for a detection)")


class TimelineEntry(BaseModel):
    when: str = Field(description="ISO 8601 UTC")
    what: str
    technique_ids: list[str]
    evidence_ids: list[str]


class Indicator(BaseModel):
    type: Literal["ip", "domain", "url", "sha256", "wallet", "file", "account"]
    value: str
    context: str = Field(description="What it is, e.g. 'C2 server for the second stage'")
    evidence_ids: list[str]


class TechniqueUse(BaseModel):
    technique_id: str
    name: str
    how_used: str
    evidence_ids: list[str]


class TechnicalBrief(BaseModel):
    title: str
    summary: str
    timeline: list[TimelineEntry]
    indicators: list[Indicator]
    techniques: list[TechniqueUse]
    detections: list[Cited] = Field(description="Detection rules drafted for this, citing det:<id>")
    actions: list[str]
    open_questions: list[str]


class ExecutiveBrief(BaseModel):
    headline: str = Field(description="Bottom line up front: one sentence")
    assessment: str = Field(
        description="Two or three sentences using ICD 203 likelihood words (likely, almost certainly)"
    )
    confidence: Literal["high", "moderate", "low"]
    confidence_basis: str = Field(description="Why that confidence, in one sentence")
    key_points: list[Cited] = Field(description="Three to five plain-English points, no jargon")
    impact: list[Cited] = Field(description="Business impact: money, customers, legal and regulatory exposure")
    decisions_needed: list[str] = Field(description="What leadership must decide or approve now")
    next_24_hours: list[str]


class BriefSet(BaseModel):
    technical: TechnicalBrief
    executive: ExecutiveBrief


MONEY = re.compile(r"\$\s?([\d,]+(?:\.\d+)?)\s*(million|m\b|k\b|thousand|billion|bn\b)?", re.IGNORECASE)
SCALE = {"million": 1e6, "m": 1e6, "k": 1e3, "thousand": 1e3, "billion": 1e9, "bn": 1e9}


def dollar_amounts(text: str) -> list[float]:
    out = []
    for number, unit in MONEY.findall(text):
        value = float(number.replace(",", ""))
        out.append(value * SCALE.get((unit or "").lower(), 1))
    return out


def verify(
    pg: psycopg.Connection,
    briefs: dict[str, Any],
    facts: dict[str, Any],
    allowed: set[str],
    logs_path: str,
    known_techniques: set[str],
) -> dict[str, Any]:
    """Check every cited item: real evidence, indicators present in it, known techniques, dollar figures from facts."""
    texts = factlib.event_text(pg, logs_path, sorted({i for i in allowed if not i.startswith("det:")}))
    figures = factlib.money_figures(facts)
    items: list[dict[str, Any]] = []

    def check(section: str, label: str, cited: list[str], extra: list[str]) -> None:
        problems = list(extra)
        if not cited:
            problems.append("cites no evidence")
        unknown = [i for i in cited if i not in allowed]
        if unknown:
            problems.append(f"cites evidence that isn't part of this investigation: {', '.join(unknown[:4])}")
        items.append(
            {
                "section": section,
                "item": label[:120],
                "status": "rejected" if problems else "accepted",
                "problems": problems,
            }
        )

    def money_problems(text: str) -> list[str]:
        bad = [
            a
            for a in dollar_amounts(text)
            if not any(
                abs(a - f) <= max(0.02 * f, 1.0)
                or abs(a - round(f, -3)) <= 0.02 * f
                or abs(a - round(f, -5)) <= 0.03 * f
                for f in figures
            )
        ]
        return [f"dollar figure ${a:,.0f} isn't in the computed facts" for a in bad]

    tech, exe = briefs["technical"], briefs["executive"]
    for t in tech["timeline"]:
        unknown = [x for x in t["technique_ids"] if x.upper() not in known_techniques]
        check(
            "technical.timeline",
            t["what"],
            t["evidence_ids"],
            [f"unknown ATT&CK technique {', '.join(unknown)}"] if unknown else [],
        )
    for ind in tech["indicators"]:
        present = any(ind["value"].lower() in texts.get(i, "") for i in ind["evidence_ids"])
        check(
            "technical.indicators",
            f"{ind['type']} {ind['value']}",
            ind["evidence_ids"],
            [] if present else [f"{ind['value']} does not appear in the evidence it cites"],
        )
    for t in tech["techniques"]:
        bad = [] if t["technique_id"].upper() in known_techniques else [f"unknown ATT&CK technique {t['technique_id']}"]
        check("technical.techniques", f"{t['technique_id']} {t['name']}", t["evidence_ids"], bad)
    for d in tech["detections"]:
        check("technical.detections", d["text"], d["evidence_ids"], [])
    for section in ("key_points", "impact"):
        for c in exe[section]:
            check(f"executive.{section}", c["text"], c["evidence_ids"], money_problems(c["text"]))

    warnings = []
    for field in ("headline", "assessment"):
        for p in money_problems(exe[field]):
            warnings.append(f"executive.{field}: {p}")
    if not any(w in exe["assessment"].lower() for w in ESTIMATIVE):
        warnings.append("executive.assessment uses no ICD 203 likelihood word (e.g. likely, almost certainly)")
    accepted = sum(1 for i in items if i["status"] == "accepted")
    return {
        "items": items,
        "accepted": accepted,
        "rejected": len(items) - accepted,
        "warnings": warnings,
        "passed": accepted == len(items) and not warnings,
    }
