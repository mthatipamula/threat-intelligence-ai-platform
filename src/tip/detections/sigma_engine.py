"""Sigma rules: parse, validate, and convert to Splunk (SPL), Microsoft Sentinel (KQL) and our DuckDB log store (SQL).

Sigma is the vendor-neutral format for detection rules: write the logic once, convert it to each SIEM's language.
Rules use either Sigma's standard log categories (process_creation, file_access, network_connection) with standard
field names, or this company's own log sources (product: meridian, service: <table>) with our column names.

Each target needs a "processing pipeline" saying how Sigma's fields and log sources map onto its data:
  * DuckDB (ours): standard fields -> our columns, log source -> table (pySigma's SQLite backend, adapted to DuckDB)
  * Sentinel: Microsoft's ASIM normalised tables (imProcessCreate, imNetworkSession...), or <Name>_CL custom tables
  * Splunk: field names as written (a real deployment would add its CIM field mapping)
Every conversion parses the rule afresh: pySigma pipelines modify the parsed rule in place.
"""

from dataclasses import dataclass, field
from typing import Any, ClassVar

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)

# Standard Sigma categories this company's telemetry can answer, and how they map onto our tables.
STANDARD = {
    "process_creation": {
        "table": "endpoint_events",
        "where": {"action": "process_start"},
        "fields": {
            "Image": "process",
            "ParentImage": "parent_process",
            "CommandLine": "command_line",
            "User": "user_name",
            "Computer": "host",
            "Hashes": "sha256",
        },
    },
    "file_access": {
        "table": "endpoint_events",
        "where": {"action": "file_read"},
        "fields": {
            "TargetFilename": "file_path",
            "Image": "process",
            "ParentImage": "parent_process",
            "User": "user_name",
            "Computer": "host",
        },
    },
    "network_connection": {
        "table": "network_events",
        "where": {},
        "fields": {
            "Image": "process",
            "User": "user_name",
            "Computer": "host",
            "SourceIp": "src_ip",
            "DestinationIp": "dest_ip",
            "DestinationPort": "dest_port",
            "DestinationHostname": "dest_domain",
            "BytesSent": "bytes_out",
            "BytesReceived": "bytes_in",
        },
    },
}
# Our own log sources: product meridian, service = table name, fields = column names.
CUSTOM = ["auth_events", "endpoint_events", "network_events", "cloud_audit", "wallet_withdrawals"]
SENTINEL_TABLES = {
    "auth_events": "MeridianAuth_CL",
    "endpoint_events": "MeridianEndpoint_CL",
    "network_events": "MeridianProxy_CL",
    "cloud_audit": "MeridianCloudAudit_CL",
    "wallet_withdrawals": "MeridianWithdrawals_CL",
}

SCHEMA_GUIDE = """Supported log sources and fields (anything else will not convert):
- logsource {category: process_creation, product: macos}: Image, ParentImage, CommandLine, User, Computer, Hashes
  (Image/ParentImage hold process names such as node, curl, python3 - use endswith)
- logsource {category: file_access, product: macos}: TargetFilename, Image, ParentImage, User, Computer
- logsource {category: network_connection, product: macos}: Image, User, Computer, SourceIp, DestinationIp,
  DestinationPort, DestinationHostname (null when connecting to a raw IP), BytesSent, BytesReceived
- logsource {product: meridian, service: auth_events}: user_name, app, outcome, mfa_method, src_ip, country, asn,
  session_id, user_agent
- logsource {product: meridian, service: network_events}: host, user_name, process, dest_domain, dest_ip, dest_port,
  bytes_out, bytes_in, category (proxy category, e.g. newly-registered)
- logsource {product: meridian, service: cloud_audit}: principal, principal_type (federated-user|assumed-role),
  action (e.g. secretsmanager:GetSecretValue, iam:CreateAccessKey), resource, src_ip, user_agent, outcome
- logsource {product: meridian, service: wallet_withdrawals}: account_id, initiated_by, channel, asset, chain,
  amount, usd_value, to_address, status, risk_score"""


class DuckDBBackend(sqliteBackend):
    """pySigma's SQLite backend adjusted for DuckDB: Sigma matching is case-insensitive (ILIKE), DuckDB regex syntax,
    double-quoted identifiers, and the table taken from the pipeline state."""

    name: ClassVar[str] = "DuckDB backend"
    startswith_expression: ClassVar[str] = "{field} ILIKE '{value}%' ESCAPE '\\'"
    endswith_expression: ClassVar[str] = "{field} ILIKE '%{value}' ESCAPE '\\'"
    contains_expression: ClassVar[str] = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = "{field} ILIKE '{value}' ESCAPE '\\'"
    re_expression: ClassVar[str] = "regexp_matches({field}, '{regex}')"

    def escape_and_quote_field(self, field: str) -> str:
        """Quote every column in standard SQL double quotes (the SQLite backend uses MySQL backticks)."""
        return '"' + field.replace('"', '""') + '"'


def duckdb_pipeline() -> ProcessingPipeline:
    items: list[ProcessingItem] = []
    for category, spec in STANDARD.items():

        def when(
            category: str = category,
        ) -> list[LogsourceCondition]:  # a fresh condition per item (pySigma binds each)
            return [LogsourceCondition(category=category)]

        items += [
            ProcessingItem(
                SetStateTransformation("table", spec["table"]), rule_conditions=when(), identifier=f"{category}-table"
            ),
            ProcessingItem(
                FieldMappingTransformation(spec["fields"]), rule_conditions=when(), identifier=f"{category}-fields"
            ),
        ]
        if spec["where"]:
            items.append(
                ProcessingItem(
                    AddConditionTransformation(spec["where"]), rule_conditions=when(), identifier=f"{category}-where"
                )
            )
    for table in CUSTOM:
        items.append(
            ProcessingItem(
                SetStateTransformation("table", table),
                rule_conditions=[LogsourceCondition(product="meridian", service=table)],
                identifier=f"meridian-{table}",
            )
        )
    return ProcessingPipeline(name="Meridian Exchange logs (DuckDB)", priority=20, items=items)


@dataclass
class Converted:
    sql: str | None = None
    spl: str | None = None
    kql: str | None = None
    table: str | None = None
    errors: dict[str, str] = field(default_factory=dict)


def parse(yaml_text: str) -> SigmaCollection:
    """Parse and validate. Raises SigmaError (or ValueError) with a readable message for bad rules."""
    collection = SigmaCollection.from_yaml(yaml_text)
    if len(collection.rules) != 1:
        raise ValueError(f"expected exactly one rule, found {len(collection.rules)}")
    if collection.errors:
        raise ValueError("; ".join(str(e) for e in collection.errors))
    return collection


def target_table(yaml_text: str) -> str | None:
    rule = parse(yaml_text).rules[0]
    if rule.logsource.product == "meridian":
        return rule.logsource.service if rule.logsource.service in CUSTOM else None
    return STANDARD.get(rule.logsource.category or "", {}).get("table")


def convert(yaml_text: str) -> Converted:
    out = Converted()
    try:
        out.table = target_table(yaml_text)
    except (SigmaError, ValueError) as e:
        out.errors["sigma"] = str(e)
        return out
    if out.table is None:
        out.errors["logsource"] = "unsupported log source; see the supported list"
    targets: dict[str, Any] = {
        "sql": lambda: DuckDBBackend(duckdb_pipeline()).convert(parse(yaml_text))[0],
        "spl": lambda: SplunkBackend().convert(parse(yaml_text))[0],
        "kql": lambda: KustoBackend(_sentinel_pipeline(yaml_text)).convert(parse(yaml_text))[0],
    }
    for name, fn in targets.items():
        try:
            setattr(out, name, fn())
        except Exception as e:  # each target can fail independently; report, don't abort the others
            out.errors[name] = f"{type(e).__name__}: {e}"[:400]
    return out


def _sentinel_pipeline(yaml_text: str) -> ProcessingPipeline:
    rule = parse(yaml_text).rules[0]
    custom = rule.logsource.product == "meridian"
    return sentinel_asim_pipeline(query_table=SENTINEL_TABLES.get(rule.logsource.service or "") if custom else None)
