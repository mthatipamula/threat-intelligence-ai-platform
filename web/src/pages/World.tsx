import { useEffect, useState } from 'react';
import { api, type Actor, type Overview, type Signals } from '../api';
import { Explainer } from '../components/Explainer';
import { Term } from '../components/Term';

// Attack lifecycle order (ATT&CK v20 split Defense Evasion into Stealth and Defense Impairment).
const TACTIC_ORDER = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
  'privilege-escalation', 'stealth', 'defense-impairment', 'defense-evasion', 'credential-access', 'discovery',
  'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
const tacticRank = (t: string) => (TACTIC_ORDER.indexOf(t) + 1 || TACTIC_ORDER.length + 1);
const ACTORS = [
  { name: 'Contagious Interview', why: 'ATT&CK\u2019s name for the fake job-interview campaigns aimed at developers. The malware it lists, BeaverTail and InvisibleFerret, is what the attack in our logs imitates.' },
  { name: 'Lazarus Group', why: 'The umbrella North Korean group behind many of the largest crypto thefts. Operation Dream Job is its long-running fake job-offer campaign.' },
];
const pretty = (s: string) => s.replace(/-/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

/** Screen 1: what's happening in the world - the threat actor, warning signs, and where the intelligence comes from. */
export function World() {
  const [actor, setActor] = useState<Actor | null>(null);
  const [signals, setSignals] = useState<Signals | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fullBio, setFullBio] = useState(false);
  const [openTactic, setOpenTactic] = useState<string | null>('initial-access');
  const [actorName, setActorName] = useState(ACTORS[0].name);

  useEffect(() => {
    Promise.all([api.signals(), api.overview()])
      .then(([s, o]) => { setSignals(s); setOverview(o); })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(() => {
    api.actor(actorName).then((a) => { setActor(a); setFullBio(false); }).catch((e: Error) => setError(e.message));
  }, [actorName]);

  if (error) return <p className="error">Could not load intelligence: {error}. Is the API running (./tip serve)?</p>;
  if (!actor || !signals || !overview) return <p className="muted">Loading intelligence…</p>;

  const tactics = [...actor.tactics].sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic));
  const intelTotal = overview.intel.reduce((n, r) => n + r.objects, 0);
  const sanctionedTotal = signals.sanctioned_addresses_by_chain.reduce((n, r) => n + r.addresses, 0);
  const maxChain = Math.max(...signals.sanctioned_addresses_by_chain.map((c) => c.addresses));

  return (
    <div className="page">
      <header className="page-head">
        <div className="eyebrow">Step 1 · Intelligence</div>
        <h1>What’s happening in the world</h1>
        <p className="lede">Who is targeting crypto exchanges, how they operate, and early warning signs.</p>
      </header>

      <Explainer>
        <p>
          Before asking “are we affected?”, an analyst needs to know <b>who</b> is attacking companies like ours and
          <b> how</b>. This screen is built automatically from public sources (<Term name="OSINT" />): the{' '}
          <Term name="ATT&CK" /> catalogue, US government advisories and the <Term name="OFAC" /> sanctions list.
        </p>
        <p>
          The headline threat for crypto exchanges is North Korea’s state hackers: the <Term name="Lazarus Group" /> umbrella,
          and the group <Term name="ATT&CK" /> calls <b>Contagious Interview</b>, whose way in is a fake job interview for an
          engineer. Switch between them on the card below. The warning signs on the right are things to watch:
          domains impersonating the exchange, wallets we must never pay, and software flaws being exploited right now.
        </p>
      </Explainer>

      <div className="grid two">
        <section className="card actor">
          <div className="segmented actor-switch" role="radiogroup" aria-label="Threat group">
            {ACTORS.map((a) => (
              <button key={a.name} role="radio" aria-checked={actorName === a.name} className={actorName === a.name ? 'on' : ''}
                onClick={() => setActorName(a.name)}>{a.name}</button>
            ))}
          </div>
          <p className="muted small why">{ACTORS.find((a) => a.name === actorName)?.why}</p>
          <div className="card-head">
            <div>
              <div className="eyebrow">Threat actor · <a href={actor.url} target="_blank" rel="noreferrer">{actor.attack_id}</a></div>
              <h2>{actor.name}</h2>
            </div>
            <span className="badge critical">North Korea · state-sponsored</span>
          </div>
          <div className="chips">{actor.aliases.filter((a) => a !== actor.name).map((a) => <span key={a} className="chip">{a}</span>)}</div>
          <p className={fullBio ? '' : 'clamp'}>{actor.description}</p>
          <button className="link" onClick={() => setFullBio(!fullBio)}>{fullBio ? 'Show less' : 'Read more'}</button>

          {actor.campaigns.length > 0 && (
            <>
              <h3>Known campaigns</h3>
              <ul className="plain">
                {actor.campaigns.map((c) => (
                  <li key={c.id}>
                    <a href={c.url} target="_blank" rel="noreferrer">{c.name}</a> <span className="muted">({c.id})</span>
                    {c.name.includes('Dream Job') && <span className="muted"> — fake job offers to engineers</span>}
                  </li>
                ))}
              </ul>
            </>
          )}

          <h3>How they operate <span className="muted">· {actor.technique_count} <Term name="technique">techniques</Term> by <Term name="tactic">goal</Term></span></h3>
          <div className="tactics">
            {tactics.map((t) => (
              <div key={t.tactic} className={`tactic ${openTactic === t.tactic ? 'open' : ''}`}>
                <button onClick={() => setOpenTactic(openTactic === t.tactic ? null : t.tactic)} aria-expanded={openTactic === t.tactic}>
                  <span>{pretty(t.tactic)}</span><span className="count">{t.techniques.length}</span>
                </button>
                {openTactic === t.tactic && (
                  <ul className="plain techniques">
                    {t.techniques.map((x) => (
                      <li key={x.id}><a className="mono" href={x.url} target="_blank" rel="noreferrer">{x.id}</a> {x.name}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
          <h3>Malware and tools</h3>
          <div className="chips small">{actor.software.slice(0, 30).map((s) => <span key={s} className="chip">{s}</span>)}
            {actor.software.length > 30 && <span className="muted">+{actor.software.length - 30} more</span>}
          </div>
        </section>

        <div className="stack">
          <section className="card">
            <h2>Warning signs</h2>
            <h3><Term name="lookalike">Lookalike domains</Term> of {signals.watched_domains.join(', ')} <span className="muted">· {signals.lookalike_domains.length} found</span></h3>
            <p className="muted small">Found two ways: typo variants that resolve in DNS, and new TLS certificates spotted by the
              live <Term name="certificate transparency">certificate-transparency</Term> watcher (often before the site is used).
              Leads, not verdicts: brands register their own typos too. Each needs triage.{' '}
              <a href="/api/misp/lookalikes">Download as a MISP event</a>.</p>
            <div className="scroll">
              <table className="data">
                <thead><tr><th>Domain</th><th>How it imitates</th><th>Found by</th></tr></thead>
                <tbody>
                  {signals.lookalike_domains.map((d) => (
                    <tr key={d.domain}>
                      <td className="mono">{d.domain}</td>
                      <td>{(d.labels.find((l) => l.startsWith('technique:')) ?? '').replace('technique:', '').replace(/-/g, ' ')}</td>
                      <td className="small">{d.labels.includes('sample')
                        ? <span className="muted">replayed sample</span>
                        : d.found_by === 'ct-watcher' && d.ct
                        ? <span title={`Certificate for ${d.ct.name}, issued by ${d.ct.issuer}, valid from ${d.ct.not_before}`}>
                            <span className="badge high">new certificate</span> {d.ct.log}</span>
                        : <span className="mono">DNS · {(d.ips ?? []).slice(0, 1).join(', ')}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <h3><Term name="OFAC" /> sanctioned crypto addresses <span className="muted">· {sanctionedTotal.toLocaleString()}</span></h3>
            <p className="muted small">Every withdrawal is screened against these. Paying one is a sanctions violation.</p>
            <div className="bars">
              {signals.sanctioned_addresses_by_chain.slice(0, 8).map((c) => (
                <div key={c.chain} className="bar-row" title={`${c.addresses} ${c.chain} addresses`}>
                  <span className="mono">{c.chain}</span>
                  <span className="bar"><span style={{ width: `${(c.addresses / maxChain) * 100}%` }} /></span>
                  <span className="num">{c.addresses}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h3>Government advisories</h3>
            <ul className="plain">
              {signals.advisories.map((a) => (
                <li key={a.id}><a href={a.url} target="_blank" rel="noreferrer">{a.title}</a><div className="muted small">{a.source} · {a.published}</div></li>
              ))}
            </ul>
            <h3>Newly <Term name="KEV">exploited vulnerabilities</Term></h3>
            <ul className="plain small">
              {signals.known_exploited.slice(0, 5).map((k) => (
                <li key={k.cve}><span className="mono">{k.cve}</span> {k.vendor} {k.product} <span className="muted">· {k.added}</span>{k.ransomware && <span className="badge high">ransomware</span>}</li>
              ))}
            </ul>
          </section>
        </div>
      </div>

      <section className="card sources">
        <h3>Where this comes from</h3>
        <div className="stats">
          <div><b>{intelTotal.toLocaleString()}</b><span><Term name="STIX" /> intelligence objects</span></div>
          <div><b>{overview.library.reduce((n, l) => n + l.documents, 0)}</b><span>reports and runbooks for <Term name="RAG" /></span></div>
          <div><b>{Object.values(overview.logs.tables).reduce((a, b) => a + b, 0).toLocaleString()}</b><span>internal log events · {overview.logs.employees} employees</span></div>
          <div><b>{overview.logs.from.slice(0, 10)} → {overview.logs.to.slice(0, 10)}</b><span>log window (synthetic)</span></div>
        </div>
      </section>
    </div>
  );
}
