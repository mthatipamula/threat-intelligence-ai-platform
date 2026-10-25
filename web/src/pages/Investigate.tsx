import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type Config, type Investigation, type InvestigationSummary } from '../api';
import { EvidenceChip, EvidenceDrawer } from '../components/Evidence';
import { Explainer } from '../components/Explainer';
import { Term } from '../components/Term';

const SUGGESTED = [
  'Are we affected by North Korean fake job interview attacks against crypto engineers?',
  'Did anything in our logs touch sanctioned wallets or known malicious infrastructure this week?',
];
const VERDICT: Record<string, { label: string; tone: string }> = {
  'confirmed-compromise': { label: 'Confirmed compromise', tone: 'critical' },
  'suspicious-activity': { label: 'Suspicious activity', tone: 'high' },
  'no-evidence-found': { label: 'No evidence found', tone: 'ok' },
};
const STATUS_TEXT: Record<string, string> = {
  queued: 'Queued', investigating: 'Searching logs and intelligence', drafting: 'Writing the report',
  verifying: 'Checking every citation', revising: 'Sending rejected findings back', done: 'Done', failed: 'Failed',
};
const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString('en-US', { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', hour12: false }) + ' UTC';

/** Screen 2: are we affected? Runs an AI investigation and shows a cited, verified attack timeline. */
export function Investigate() {
  const [config, setConfig] = useState<Config | null>(null);
  const [question, setQuestion] = useState(SUGGESTED[0]);
  const [mode, setMode] = useState<'mock' | 'live'>('mock');
  const [run, setRun] = useState<Investigation | null>(null);
  const [history, setHistory] = useState<InvestigationSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const refreshHistory = useCallback(() => api.investigations().then(setHistory).catch(() => {}), []);
  useEffect(() => { api.config().then(setConfig).catch(() => {}); refreshHistory(); }, [refreshHistory]);
  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current); }, []);

  const follow = useCallback((id: string) => {
    if (timer.current) window.clearTimeout(timer.current);
    const poll = () => api.investigation(id).then((r) => {
      setRun(r);
      if (r.status === 'done' || r.status === 'failed') refreshHistory();
      else timer.current = window.setTimeout(poll, 800);
    }, (e: Error) => setError(e.message));
    poll();
  }, [refreshHistory]);

  const start = async () => {
    setError(null);
    setRun(null);
    try {
      const { id } = await api.investigate(question, mode);
      follow(id);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const running = run && !['done', 'failed'].includes(run.status);
  const report = run?.report;
  const checks = run?.verification;
  const accepted = report && checks ? report.findings.map((f, i) => ({ f, c: checks.findings[i] })).filter((x) => x.c.status === 'accepted') : [];
  const rejected = report && checks ? report.findings.map((f, i) => ({ f, c: checks.findings[i] })).filter((x) => x.c.status === 'rejected') : [];
  const verdict = report ? VERDICT[report.verdict] ?? { label: report.verdict, tone: 'high' } : null;

  return (
    <div className="page">
      <header className="page-head">
        <div className="eyebrow">Step 2 · Investigation</div>
        <h1>Are we affected?</h1>
        <p className="lede">An AI agent searches our logs and intelligence. Every finding must cite evidence, and code checks the citations.</p>
      </header>

      <Explainer>
        <p>
          Ask a question in plain English. The AI agent works like an analyst: it runs reviewed <b>hunts</b> (searches for
          known attacker behaviour), checks our logs against threat intelligence, builds a timeline for anyone involved,
          and reads advisories and our past incident reports (<Term name="RAG" />).
        </p>
        <p>
          The AI is not trusted blindly. Every finding must point to the exact log line, intelligence record or report
          passage that proves it (click any grey chip to see it). A <Term name="verifier" /> then rejects anything citing
          evidence the tools never returned. <b>Mock mode</b> is free and repeatable, and it includes one deliberately
          unsupported claim so you can see the verifier reject it. <b>Live mode</b> uses Claude ({config?.model ?? '…'}).
        </p>
      </Explainer>

      <section className="card ask">
        <label htmlFor="question" className="eyebrow">Question</label>
        <textarea id="question" rows={2} value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={500} />
        <div className="ask-row">
          <div className="chips">
            {SUGGESTED.map((s) => <button key={s} className="chip suggestion" onClick={() => setQuestion(s)}>{s}</button>)}
          </div>
          <div className="segmented" role="radiogroup" aria-label="Mode">
            <button role="radio" aria-checked={mode === 'mock'} className={mode === 'mock' ? 'on' : ''} onClick={() => setMode('mock')}>Mock (free)</button>
            <button role="radio" aria-checked={mode === 'live'} className={mode === 'live' ? 'on' : ''} disabled={!config?.live_available}
              title={config?.live_available ? 'Claude decides which tools to use' : 'Add ANTHROPIC_API_KEY to .env to enable'} onClick={() => setMode('live')}>
              Live (Claude)
            </button>
          </div>
          <button className="primary" onClick={start} disabled={!!running || question.trim().length < 5}>
            {running ? 'Investigating…' : 'Investigate'}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {run && (
        <section className="card progress">
          <div className="card-head">
            <h3>{STATUS_TEXT[run.status] ?? run.status}{running && <span className="spinner" aria-hidden />}</h3>
            <span className="muted small">{run.mode === 'live' ? 'Claude' : 'mock playbook'} · {run.trace.length || run.progress.length} steps</span>
          </div>
          <ol className="progress-list" start={Math.max(1, run.progress.length - 5)}>{run.progress.slice(-6).map((p, i) => <li key={i} className="mono small">{p}</li>)}</ol>
          {run.status === 'failed' && <p className="error">{run.error}</p>}
        </section>
      )}

      {report && checks && verdict && (
        <>
          <section className={`card verdict ${verdict.tone}`}>
            <div className="card-head">
              <div>
                <div className="eyebrow">Verdict · confidence {report.confidence}</div>
                <h2>{verdict.label}</h2>
              </div>
              <div className="verify-score" title="Findings that passed the citation check">
                <b>{checks.accepted}</b>/<span>{checks.accepted + checks.rejected}</span>
                <small>findings verified</small>
              </div>
            </div>
            <p className="summary">{report.summary}</p>
          </section>

          <section className="card">
            <h2>Attack timeline</h2>
            <p className="muted small">Each step is backed by the cited evidence. <Term name="ATT&CK" /> IDs name the attacker technique.</p>
            <ol className="timeline">
              {accepted.map(({ f }) => (
                <li key={f.title} className={`sev-${f.severity}`}>
                  <div className="when mono">{fmtTime(f.when)}</div>
                  <div className="what">
                    <div className="title-row"><h4>{f.title}</h4><span className={`badge ${f.severity}`}>{f.severity}</span></div>
                    <p>{f.what_happened}</p>
                    <div className="meta">
                      {f.technique_ids.map((t) => (
                        <a key={t} className="chip technique mono" href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noreferrer">{t}</a>
                      ))}
                      {f.affected.map((a) => <span key={a} className="chip who">{a}</span>)}
                    </div>
                    <div className="meta"><span className="muted small">Evidence</span>{f.evidence_ids.map((id) => <EvidenceChip key={id} id={id} onOpen={setEvidence} />)}</div>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          {rejected.length > 0 && (
            <section className="card rejected">
              <h2>Rejected by the verifier <span className="muted">· not part of the findings</span></h2>
              <p className="muted small">The AI tried to claim these, but the evidence doesn’t back them. They are shown, not hidden, so a reviewer sees what was filtered out.</p>
              {rejected.map(({ f, c }) => (
                <div key={f.title} className="rejected-item">
                  <h4>✕ {f.title}</h4>
                  <p>{f.what_happened}</p>
                  <ul>{c.problems.map((p) => <li key={p}>{p}</li>)}</ul>
                </div>
              ))}
            </section>
          )}

          <div className="grid two">
            <section className="card">
              <h3>Recommended actions</h3>
              <ol>{report.recommended_actions.map((a) => <li key={a}>{a}</li>)}</ol>
              <h3>Open questions</h3>
              <ul>{report.open_questions.map((q) => <li key={q}>{q}</li>)}</ul>
            </section>
            <section className="card">
              <h3>Threat intelligence context</h3>
              {report.context.map((c, i) => (
                <div key={i} className="context-item">
                  <p>{c.statement}</p>
                  <div className="meta">{checks.context[i]?.status === 'rejected' && <span className="badge critical">rejected</span>}
                    {c.evidence_ids.map((id) => <EvidenceChip key={id} id={id} onOpen={setEvidence} />)}</div>
                </div>
              ))}
            </section>
          </div>

          <details className="card how">
            <summary><h3>How the AI worked · {run!.trace.length} tool calls{run!.usage && run!.mode === 'live' && ` · ${run!.usage.input_tokens.toLocaleString()} in / ${run!.usage.output_tokens.toLocaleString()} out tokens · ≈$${run!.usage.estimated_cost_usd.toFixed(2)}`}</h3></summary>
            <table className="data">
              <thead><tr><th>#</th><th>Tool</th><th>Input</th><th>Result</th></tr></thead>
              <tbody>
                {run!.trace.map((t, i) => (
                  <tr key={i}>
                    <td>{i + 1}</td>
                    <td className="mono">{t.tool}</td>
                    <td className="mono small">{Object.keys(t.input).length ? JSON.stringify(t.input) : '—'}</td>
                    <td className="small">{t.error ? <span className="error">{t.error}</span> : t.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {run!.revisions > 0 && <p className="muted small">The report was revised {run!.revisions} time(s) after the verifier rejected findings.</p>}
          </details>
        </>
      )}

      {history.length > 0 && (
        <section className="card">
          <h3>Recent investigations</h3>
          <table className="data clickable">
            <thead><tr><th>When</th><th>Question</th><th>Mode</th><th>Verdict</th><th>Verified</th></tr></thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} onClick={() => follow(h.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && follow(h.id)}>
                  <td className="small">{new Date(h.created_at).toLocaleString()}</td>
                  <td>{h.question}</td>
                  <td>{h.mode}</td>
                  <td>{h.verdict ? VERDICT[h.verdict]?.label ?? h.verdict : h.status}</td>
                  <td>{h.accepted ?? '–'}{h.rejected ? <span className="muted"> ({h.rejected} rejected)</span> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <EvidenceDrawer id={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}
