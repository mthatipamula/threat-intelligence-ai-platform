# threat-intelligence-ai-platform

AI-assisted threat intelligence for a crypto exchange. The platform:
- collects OSINT and internal signals and maps them to MITRE ATT&CK;
- investigates with an AI agent that has to cite evidence for every claim;
- turns intelligence into tested Sigma detections (SPL, KQL, SQL);
- writes briefs for engineers and executives, with a human approving each step.

> Portfolio project. "Meridian Exchange" and all of its logs are synthetic. Threat intelligence comes from public
> sources (MITRE ATT&CK, CISA, OFAC). No live malware, no real company data.

## Roadmap

| Step | What | Status |
|---|---|---|
| 1 | Local stack, OSINT collection, STIX 2.1 store, synthetic logs with a hidden attack | **done** |
| 2 | Investigation agent (LangGraph): tools, RAG over reports, cited findings | next |
| 3 | Detection engineering: Sigma → SPL / KQL / SQL, replay-tested against the logs | |
| 4 | Intelligence briefs (technical and executive), evals, prompt-injection tests | |
| 5 | Review console (React): evidence beside each claim, approve or reject | |
| 6 | Go lookalike-domain watcher on Certificate Transparency logs; MISP sync | |

## Architecture (step 1)

```
OSINT feeds                                     STIX 2.1 store (Postgres)
  MITRE ATT&CK (groups, techniques, malware) ─┐   one row per object, JSONB + extracted columns
  CISA Known Exploited Vulnerabilities       ─┤   relationships and indicator values as generated columns
  OFAC sanctioned crypto addresses           ─┼─► deterministic IDs: re-collecting updates, never duplicates
  abuse.ch ThreatFox (optional, free key)    ─┤   every object: created_by_ref + source URL (for citations)
  Lookalike domains (typosquats, DNS)        ─┘   collection_runs: status of every run

Synthetic internal logs (DuckDB, the SIEM stand-in)
  auth_events · endpoint_events · network_events · cloud_audit · wallet_withdrawals
  scenario_events: the answer key (each attack event, its step and ATT&CK technique)
```

## Run it

Requires Docker and [uv](https://docs.astral.sh/uv/).

```bash
./scripts/init-env.sh        # .env with a random database password (never printed)
docker compose up -d --wait  # Postgres (pgvector) on localhost:5433
uv sync                      # dependencies
./tip collect                # all collectors; about 15 seconds after the first ATT&CK download
./tip logs generate          # 7 days of synthetic logs with the hidden attack
uv run pytest                # 16 tests (database tests skip when Postgres isn't running)
```

To enable ThreatFox, add a free key from https://auth.abuse.ch to `.env` as `ABUSECH_AUTH_KEY`.

### Try it

```bash
./tip intel stats                                              # objects per source, last run of each collector
./tip intel show "Lazarus Group"                               # aliases, campaigns, techniques (with T-numbers)
./tip intel search "dream job" --type campaign
./tip intel lookup 0x098B716B8Aaf21512996dC57EB0615e2383E2f96 # OFAC-sanctioned (Lazarus, Ronin bridge theft)
./tip logs sql "SELECT strftime(ts,'%a %H:%M') t, step, technique_id, description FROM scenario_events ORDER BY ts"
```

## Intelligence sources

| Source | Becomes | Notes |
|---|---|---|
| [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) | groups, techniques, tactics, malware, tools, campaigns and their relationships | Native STIX 2.1, about 21,000 objects; revoked and deprecated entries dropped |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `vulnerability` per CVE | Labelled `known-exploited`, plus `ransomware` where CISA says so |
| [OFAC SDN crypto addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) | `indicator` per address | One indicator per address, listing every chain it's sanctioned on |
| [abuse.ch ThreatFox](https://threatfox.abuse.ch) | `indicator` per IOC | Linked to ATT&CK malware by family name, so IOCs connect to threat actors |
| Lookalike domains | `indicator` per registered lookalike | Typo, homoglyph, keyword and TLD variants that resolve in DNS. Low confidence and `needs-triage`, since brands register their own typos |

Crypto wallets have no standard STIX observable, so wallet indicators use the custom `x-crypto-wallet` type, which the
spec allows.

## The synthetic attack

Meridian Exchange has 60 employees and about 25,000 events over 7 days. One intrusion is hidden in normal activity,
modelled on public reporting about DPRK "Contagious Interview" and TraderTraitor operations against crypto companies:

| Step | Technique | What happens |
|---|---|---|
| 1 | T1566.003 | A platform engineer opens a fake recruiter's page after a LinkedIn message |
| 2-3 | T1204.002, T1059.007 | They clone the "coding assessment"; `npm install` runs a JavaScript loader |
| 4-5 | T1105, T1059.006 | The loader downloads a Python backdoor from the C2 on port 1224 |
| 6-8 | T1555.003, T1539, T1041 | The backdoor steals the MetaMask vault and Chrome cookies, then exfiltrates 48 MB |
| 9 | T1550.004 | That night the stolen session is replayed from attacker infrastructure, with no MFA prompt |
| 10-11 | T1555.006, T1098.001 | The attacker reads the hot-wallet API key from Secrets Manager and creates a new access key |
| 12 | T1657 | Withdrawals via the stolen key, including 1.85M USDT to a real OFAC-sanctioned Lazarus address |

The benign activity deliberately resembles the attack, so detections have to be precise:
- other engineers run `npm`, `node` and `curl` every day;
- the withdrawals service reads the same secret routinely, from inside the VPC;
- travelling executives sign in from abroad, with MFA.

`scenario_events` records every attack event's ID and technique, so later steps can measure a detection's precision and
recall instead of claiming it works. All IPs and domains are reserved test values (RFC 5737, `.example`, `.test`).

## Layout

```
src/tip/
  config.py            settings from .env
  stix.py              building STIX objects: deterministic IDs, source identities, indicator patterns
  store.py             Postgres STIX store: schema, upsert, search, relationships, observable lookup
  collectors/          attack, kev, ofac, threatfox, lookalike (+ cached downloads)
  logs/generator.py    synthetic Meridian Exchange logs and the attack answer key
  cli.py               the `./tip` commands
tests/                 parsing, STIX validity, generator answer key, store (in a throwaway schema)
```

**Why `./tip` and not an installed command:** on a Mac whose Desktop syncs to iCloud, macOS flags everything inside
`.venv` as hidden. Python skips hidden `.pth` files, which breaks editable installs. So `uv` installs only the
dependencies, and `./tip` and pytest run the code from `src/`.
