import { useCallback, useEffect, useRef, useState } from 'react';
import { api, detectionsApi, type Config, type Coverage, type Detection, type InvestigationSummary } from '../api';
import { Explainer } from '../components/Explainer';
import { Term } from '../components/Term';

const CODE_TABS = [
  { id: 'sigma', label: 'Sigma (source)' },
  { id: 'spl', label: 'Splunk SPL' },
  { id: 'kql', label: 'Sentinel KQL' },
  { id: 'sql', label: 'Our logs (SQL)' },
] as const;
type CodeTab = (typeof CODE_TABS)[number]['id'];
const STATUS: Record<Detection['status'], { label: string; tone: string }> = {
  drafting: { label: 'Drafting…', tone: 'low' }, passed: { label: 'Passed test', tone: 'ok' },
  failed: { label: 'Failed test', tone: 'critical' }, approved: { label: 'Approved', tone: 'ok' },
  rejected: { label: 'Rejected', tone: 'low' }, error: { label: 'Error', tone: 'critical' },
};
const reviewerKey = 'tip.reviewer';
const readReviewer = () => { try { return localStorage.getItem(reviewerKey) ?? ''; } catch { return ''; } };

/** Screen 3: how do we catch this next time? Drafted Sigma rules, replay-tested, reviewed by a person. */
export function Detections() {
  const [config, setConfig] = useState<Config | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [investigationId, setInvestigationId] = useState('');
  const [mode, setMode] = useState<'mock' | 'live'>('mock');
  const [rules, setRules] = useState<Detection[]>([]);
  const [batch, setBatch] = useState<string | null>(null);
  const [reviewer, setReviewer] = useState(readReviewer);
  const [error, setError] = useState<string | null>(null);
  const [actors, setActors] = useState<string[]>([]);
  const [actor, setActor] = useState('Contagious Interview');
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const timer = useRef<number | null>(null);

  const refreshCoverage = useCallback((a: string) => detectionsApi.coverage(a).then(setCoverage).catch(() => {}), []);
  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    api.investigations().then((list) => {
      const done = list.filter((i) => i.status === 'done');
      setInvestigations(done);
      if (done[0]) setInvestigationId(done[0].id);
    }).catch((e: Error) => setError(e.message));
    detectionsApi.list().then(setRules).catch(() => {});
    detectionsApi.coverageActors().then(setActors).catch(() => {});
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, []);
  useEffect(() => { refreshCoverage(actor); }, [actor, refreshCoverage]);
  useEffect(() => { try { localStorage.setItem(reviewerKey, reviewer); } catch { /* storage unavailable */ } }, [reviewer]);

  const follow = useCallback((batchId: string) => {
    const poll = () => detectionsApi.list(batchId).then((r) => {
      setRules(r);
      const busy = r.length === 0 || r.some((d) => d.status === 'drafting');
      if (busy) timer.current = window.setTimeout(poll, 700);
      else refreshCoverage(actor);
    }, (e: Error) => setError(e.message));
    poll();
  }, [actor, refreshCoverage]);

  const draft = async () => {
    setError(null);
    try {
      const { batch_id } = await detectionsApi.draft(investigationId, mode);
      setBatch(batch_id);
      setRules([]);
      follow(batch_id);
    } catch (e) { setError((e as Error).message); }
  };

  const onReviewed = (updated: Detection) => {
    setRules((rs) => rs.map((r) => (r.id === updated.id ? updated : r)));
    refreshCoverage(actor);
  };

  const drafting = batch !== null && (rules.length === 0 || rules.some((r) => r.status === 'drafting'));
  const counts = rules.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r.status]: (acc[r.status] ?? 0) + 1 }), {});

  return (
    <div className="page">
      <header className="page-head">
        <div className="eyebrow">Step 3 · Detection engineering</div>
        <h1>How do we catch this next time?</h1>
        <p className="lede">Turn each verified finding into a detection rule, test it against real logs, and let a person approve it.</p>
      </header>

      <Explainer>
        <p>
          An investigation tells us what happened once. A <b>detection rule</b> makes sure we notice automatically if it
          happens again, with different attacker servers or a different employee. Rules are written in <Term name="Sigma" />,
          which converts to whichever <Term name="SIEM" /> a company runs: <Term name="SPL" /> for Splunk, <Term name="KQL" /> for
          Microsoft Sentinel, and SQL for this demo’s log store.
        </p>
        <p>
          AI drafts are not trusted blindly. Each rule gets a <Term name="replay test" />: it must catch the attack’s events,
          and stay quiet on this week’s normal activity <i>and</i> on a fresh week it has never seen (too many{' '}
          <Term name="false alarm">false alarms</Term> and analysts stop reading the alerts). Only rules that pass can be
          approved; approved rules are saved as files in the repository (<Term name="detection-as-code" />). Watch the
          “person reads a secret” rule: its first draft fails as too noisy and the revised one passes.
        </p>
        <p className="muted small">Caveat: synthetic normal activity is tidier than a real company’s, so a pass here means “deploy in test mode and watch”, not “proven quiet in production”.</p>
      </Explainer>

      <section className="card ask">
        <div className="ask-row">
          <label className="field">
            <span className="eyebrow">From investigation</span>
            <select value={investigationId} onChange={(e) => setInvestigationId(e.target.value)}>
              {investigations.length === 0 && <option value="">Run an investigation on screen 2 first</option>}
              {investigations.map((i) => (
                <option key={i.id} value={i.id}>
                  {new Date(i.created_at).toLocaleString()} · {i.mode} · {i.accepted ?? 0} verified findings
                </option>
              ))}
            </select>
          </label>
          <div className="segmented" role="radiogroup" aria-label="Mode">
            <button role="radio" aria-checked={mode === 'mock'} className={mode === 'mock' ? 'on' : ''} onClick={() => setMode('mock')}>Mock (free)</button>
            <button role="radio" aria-checked={mode === 'live'} className={mode === 'live' ? 'on' : ''} disabled={!config?.live_available}
              title={config?.live_available ? 'Claude writes each rule' : 'Add ANTHROPIC_API_KEY to .env to enable'} onClick={() => setMode('live')}>Live (Claude)</button>
          </div>
          <label className="field small-field">
            <span className="eyebrow">Reviewer</span>
            <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="Your name" maxLength={80} />
          </label>
          <button className="primary" onClick={draft} disabled={!investigationId || drafting}>
            {drafting ? 'Drafting and testing…' : 'Draft detection rules'}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
        {rules.length > 0 && (
          <p className="muted small summary-line">
            {rules.length} rules · {counts.passed ?? 0} passed · {counts.failed ?? 0} failed · {counts.approved ?? 0} approved
            {counts.rejected ? ` · ${counts.rejected} rejected` : ''}{counts.drafting ? ` · ${counts.drafting} drafting` : ''}
          </p>
        )}
      </section>

      {coverage && (
        <section className="card coverage">
          <div className="card-head">
            <div>
              <div className="eyebrow">ATT&amp;CK coverage</div>
              <h2>Can we detect {coverage.actor}?</h2>
            </div>
            <select value={actor} onChange={(e) => setActor(e.target.value)} aria-label="Threat group">
              {actors.map((a) => <option key={a}>{a}</option>)}
            </select>
          </div>
          <p>
            Approved rules detect <b>{coverage.covered}</b> of the <b>{coverage.total}</b> <Term name="technique">techniques</Term>{' '}
            ATT&amp;CK lists for this group{coverage.pending > 0 && <>; <b>{coverage.pending}</b> more are covered by rules that passed but await approval</>}.
          </p>
          <div className="coverage-bar" role="img" aria-label={`${coverage.covered} approved, ${coverage.pending} pending, of ${coverage.total}`}>
            <span className="approved" style={{ width: `${(coverage.covered / coverage.total) * 100}%` }} />
            <span className="pending" style={{ width: `${(coverage.pending / coverage.total) * 100}%` }} />
          </div>
          <div className="legend small"><span><i className="dot approved" />approved</span><span><i className="dot pending" />passed, awaiting approval</span><span><i className="dot none" />no rule yet</span></div>
          <div className="technique-grid">
            {coverage.techniques.map((t) => {
              const state = t.approved.length ? 'approved' : t.pending.length ? 'pending' : 'none';
              return (
                <a key={t.id} className={`tech ${state}`} href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noreferrer"
                  title={`${t.id} ${t.name}${state !== 'none' ? `\nRules: ${[...t.approved, ...t.pending].join('; ')}` : ''}`}>
                  <span className="mono">{t.id}</span> {t.name}
                </a>
              );
            })}
          </div>
          {coverage.beyond_actor.length > 0 && (
            <p className="muted small">Also covered, from our own incident but not (yet) listed for this group in ATT&amp;CK: {coverage.beyond_actor.join(', ')}.</p>
          )}
        </section>
      )}

      {rules.map((r) => <RuleCard key={r.id} rule={r} reviewer={reviewer} onReviewed={onReviewed} />)}

    </div>
  );
}

function RuleCard({ rule, reviewer, onReviewed }: { rule: Detection; reviewer: string; onReviewed: (d: Detection) => void }) {
  const [tab, setTab] = useState<CodeTab>('sigma');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const status = STATUS[rule.status];
  const t = rule.test;

  if (rule.status === 'drafting') {
    return <section className="card rule drafting"><h3>{rule.finding}<span className="spinner" aria-hidden /></h3><p className="muted small">Drafting a rule and replay-testing it…</p></section>;
  }
  if (rule.status === 'error') {
    return <section className="card rule"><h3>{rule.finding}</h3><p className="error">{rule.error}</p></section>;
  }
  const code = tab === 'sigma' ? rule.sigma_yaml : rule.translations?.[tab] ?? rule.translations?.errors?.[tab] ?? '';

  const decide = async (decision: 'approve' | 'reject') => {
    setBusy(true); setError(null);
    try { onReviewed(await detectionsApi.review(rule.id, decision, reviewer || 'analyst', note)); setNote(''); }
    catch (e) { setError((e as Error).message); }
    setBusy(false);
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(code ?? ''); setCopied(true); window.setTimeout(() => setCopied(false), 1200); } catch { /* clipboard blocked */ }
  };

  return (
    <section className={`card rule status-${rule.status}`}>
      <div className="card-head">
        <div>
          <div className="eyebrow">From finding: {rule.finding}</div>
          <h3 className="rule-title">{rule.title}</h3>
        </div>
        <div className="badges">
          {rule.level && <span className={`badge ${rule.level === 'critical' ? 'critical' : rule.level === 'high' ? 'high' : rule.level === 'medium' ? 'medium' : 'low'}`}>{rule.level}</span>}
          <span className={`badge status ${status.tone}`}>{status.label}</span>
        </div>
      </div>
      <p>{rule.description}</p>
      <div className="meta">
        {rule.technique_ids.map((id) => (
          <a key={id} className="chip technique mono" href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`} target="_blank" rel="noreferrer">{id}</a>
        ))}
        {rule.translations?.table && <span className="chip">logs: {rule.translations.table}</span>}
        <span className="chip">{rule.mode === 'live' ? 'drafted by Claude' : 'mock draft'}</span>
      </div>

      {t && t.attack_events_caught !== undefined && (
        <div className="test-grid">
          <div className={t.attack_events_caught! > 0 ? 'good' : 'bad'}>
            <b>{t.attack_events_caught}</b><span>attack events caught{t.expected_for_techniques ? ` · ${t.caught_of_expected} of ${t.expected_for_techniques} for its techniques` : ''}</span>
          </div>
          <div className={t.false_alarms! > 2 ? 'bad' : 'good'}>
            <b>{t.false_alarms}</b><span>false alarms this week · {t.scanned?.toLocaleString()} events scanned</span>
          </div>
          <div className={t.fresh_week_alarms! > 2 ? 'bad' : 'good'}>
            <b>{t.fresh_week_alarms}</b><span>alerts on a fresh normal week · {t.fresh_week_scanned?.toLocaleString()} events</span>
          </div>
        </div>
      )}
      {t?.verdict === 'failed' && <ul className="reasons">{t.reasons.map((r) => <li key={r}>✕ {r}</li>)}</ul>}

      {rule.attempts.length > 1 && (
        <div className="attempts">
          <div className="eyebrow">Draft history</div>
          <ol>
            {rule.attempts.map((a, i) => (
              <li key={i} className={a.verdict}>
                <b>{a.verdict === 'passed' ? '✓ passed' : '✕ failed'}</b> {a.note && <span>— {a.note}</span>}
                {a.reasons.length > 0 && <div className="small muted">{a.reasons.join('; ')}</div>}
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="code-tabs" role="tablist">
        {CODE_TABS.map((c) => (
          <button key={c.id} role="tab" aria-selected={tab === c.id} className={tab === c.id ? 'on' : ''} onClick={() => setTab(c.id)}>{c.label}</button>
        ))}
        <button className="ghost copy" onClick={copy} aria-label="Copy code">{copied ? 'Copied' : 'Copy'}</button>
      </div>
      <pre className="code">{code}</pre>

      {t?.sample_attack_hits && t.sample_attack_hits.length > 0 && (
        <details className="samples">
          <summary className="small">Show the attack events it caught</summary>
          <table className="data small">
            <tbody>{t.sample_attack_hits.map((h) => (
              <tr key={h.event_id}><td className="mono">{h.event_id}</td><td className="mono">{h.ts?.slice(0, 16)}</td>
                <td>{Object.entries(h).filter(([k]) => !['event_id', 'ts'].includes(k)).map(([k, v]) => `${k}=${v}`).join('  ')}</td></tr>
            ))}</tbody>
          </table>
        </details>
      )}

      {rule.status === 'approved' || rule.status === 'rejected' ? (
        <p className={`review-result ${rule.status}`}>
          {rule.status === 'approved' ? '✓ Approved' : '✕ Rejected'} by {rule.reviewer}
          {rule.review_note && <> — “{rule.review_note}”</>}
          {rule.approved_path && <> · saved as <code>{rule.approved_path}</code></>}
          <button className="link" onClick={() => decide(rule.status === 'approved' ? 'reject' : 'approve')} disabled={busy || (rule.status === 'rejected' && t?.verdict !== 'passed')}>
            {rule.status === 'approved' ? 'Withdraw' : 'Approve instead'}
          </button>
        </p>
      ) : (
        <div className="review">
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Review note (optional), e.g. deploy in test mode for 2 weeks" maxLength={500} />
          <button className="secondary" onClick={() => decide('reject')} disabled={busy}>Reject</button>
          <button className="primary" onClick={() => decide('approve')} disabled={busy || rule.status !== 'passed'}
            title={rule.status !== 'passed' ? 'Only rules that pass the replay test can be approved' : undefined}>Approve</button>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
