import { useCallback, useEffect, useRef, useState } from 'react';
import { api, evalsApi, type Config, type EvalRun, type EvalSummary, type Gate } from '../api';
import { Explainer } from '../components/Explainer';
import { Term } from '../components/Term';

const fmt = (g: Gate) => {
  if (g.value === null) return '—';
  if (typeof g.value === 'boolean') return g.value ? 'yes' : 'no';
  return `${Math.round(g.value * 100)}%`;
};
const target = (g: Gate) => (g.op === '>=' && g.threshold !== null ? `target ≥ ${Math.round(g.threshold * 100)}%` : 'must hold');

/** Screen 5: can we trust the AI? An evaluation run with pass/fail gates, scored against known answers. */
export function Trust() {
  const [config, setConfig] = useState<Config | null>(null);
  const [runs, setRuns] = useState<EvalSummary[]>([]);
  const [run, setRun] = useState<EvalRun | null>(null);
  const [mode, setMode] = useState<'mock' | 'live'>('mock');
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const follow = useCallback((id: string) => {
    if (timer.current) window.clearTimeout(timer.current);
    const poll = () => evalsApi.get(id).then((r) => {
      setRun(r);
      if (r.status === 'running') timer.current = window.setTimeout(poll, 900);
      else evalsApi.list().then(setRuns).catch(() => {});
    }, (e: Error) => setError(e.message));
    poll();
  }, []);

  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    evalsApi.list().then((r) => { setRuns(r); const last = r.find((x) => x.status !== 'failed') ?? r[0]; if (last) follow(last.id); }).catch(() => {});
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [follow]);

  const start = async () => {
    if (mode === 'live' && !window.confirm('A live evaluation calls Claude several dozen times (about $3-8). Continue?')) return;
    setError(null);
    try { const { id } = await evalsApi.start(mode); follow(id); }
    catch (e) { setError((e as Error).message); }
  };

  const r = run?.results;
  const gates = r?.gates ?? [];
  const passed = gates.filter((g) => g.status === 'pass').length;
  const failed = gates.filter((g) => g.status === 'fail').length;

  return (
    <div className="page">
      <header className="page-head">
        <div className="eyebrow">Step 5 · Evaluation</div>
        <h1>Can we trust the AI?</h1>
        <p className="lede">Measured, not asserted: the whole pipeline run on cases where the right answer is known.</p>
      </header>

      <Explainer>
        <p>
          An <Term name="eval" /> runs the AI on situations whose answers we already know, and scores it. Here: the attack week
          (did it find the 12 attack steps? <Term name="recall" />; were its findings real? <Term name="precision" />), a normal
          week with no attack (it must <i>not</i> cry wolf), and a copy of the logs with two planted{' '}
          <Term name="prompt injection">prompt injections</Term>: text written by an attacker to give the AI orders, hidden in a
          malware command line and in a fake “vendor report”.
        </p>
        <p>
          It also checks that the <Term name="verifier" /> rejects unsupported claims, that detection rules pass their replay
          tests, and that every brief statement has valid evidence. Each number has a pass/fail <b>gate</b>, the bar a release
          has to clear. Mock mode is free and repeatable; it cannot be steered by an injection, so that gate is “n/a” until it
          runs live against Claude.
        </p>
      </Explainer>

      <section className="card ask">
        <div className="ask-row">
          <div className="segmented" role="radiogroup" aria-label="Mode">
            <button role="radio" aria-checked={mode === 'mock'} className={mode === 'mock' ? 'on' : ''} onClick={() => setMode('mock')}>Mock (free)</button>
            <button role="radio" aria-checked={mode === 'live'} className={mode === 'live' ? 'on' : ''} disabled={!config?.live_available}
              title={config?.live_available ? 'Runs every step against Claude' : 'Add ANTHROPIC_API_KEY to .env to enable'} onClick={() => setMode('live')}>Live (Claude)</button>
          </div>
          <button className="primary" onClick={start} disabled={run?.status === 'running'}>{run?.status === 'running' ? 'Evaluating…' : 'Run evaluation'}</button>
          {runs.length > 0 && (
            <select aria-label="Previous runs" value={run?.id ?? ''} onChange={(e) => follow(e.target.value)}>
              {runs.map((x) => <option key={x.id} value={x.id}>{new Date(x.started_at).toLocaleString()} · {x.mode} · {x.status}{x.status === 'done' ? ` · ${x.passed} pass / ${x.failed} fail` : ''}</option>)}
            </select>
          )}
        </div>
        {error && <p className="error">{error}</p>}
        {run?.status === 'running' && <ol className="progress-list">{run.progress.map((p, i) => <li key={i} className="small mono">{p}</li>)}</ol>}
        {run?.status === 'failed' && <p className="error">{run.error}</p>}
      </section>

      {gates.length > 0 && (
        <section className={`card scorecard ${failed ? 'bad' : 'ok'}`}>
          <div className="card-head">
            <div>
              <div className="eyebrow">Release gates · {run?.mode} run · {run && new Date(run.started_at).toLocaleString()}</div>
              <h2>{failed ? `${failed} gate(s) failing` : 'All applicable gates pass'}</h2>
            </div>
            <div className="verify-score"><b>{passed}</b>/<span>{gates.filter((g) => g.status !== 'n/a').length}</span><small>gates passed{r?.cost_usd ? ` · $${r.cost_usd.toFixed(2)}` : ''}</small></div>
          </div>
          <div className="gates">
            {gates.map((g) => (
              <div key={g.key} className={`gate ${g.status}`}>
                <span className="gate-mark" aria-hidden>{g.status === 'pass' ? '✓' : g.status === 'fail' ? '✕' : '–'}</span>
                <span className="gate-label">{g.label}</span>
                <b className="gate-value">{fmt(g)}</b>
                <span className="muted small">{g.status === 'n/a' ? 'needs live mode' : target(g)}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {r?.accuracy && (
        <div className="grid two">
          <section className="card">
            <h3>Did it find the attack? <span className="muted">· {r.accuracy.steps_found} of {r.accuracy.steps_total} steps</span></h3>
            <table className="data small">
              <thead><tr><th>Step</th><th>What the attacker did</th><th>Found by</th></tr></thead>
              <tbody>{r.accuracy.steps.map((s) => (
                <tr key={s.step} className={s.found ? '' : 'missed'}>
                  <td>{s.found ? '✓' : '✕'} {s.step} <span className="mono muted">{s.technique_id}</span></td>
                  <td>{s.description}</td>
                  <td>{s.by ?? <span className="error">missed</span>}</td>
                </tr>
              ))}</tbody>
            </table>
            <p className="muted small">{r.accuracy.real_findings} of {r.accuracy.accepted_findings} accepted findings are real attack activity.
              {r.accuracy.rejected_titles.length > 0 && <> The verifier rejected: {r.accuracy.rejected_titles.join('; ')}.</>}</p>
          </section>

          <div className="stack">
            {r.no_attack_week && (
              <section className="card">
                <h3>Normal week, no attack</h3>
                <p>Verdict: <b>{r.no_attack_week.verdict.replace(/-/g, ' ')}</b> · {r.no_attack_week.accepted_findings} findings accepted
                  {r.no_attack_week.rejected_findings > 0 && `, ${r.no_attack_week.rejected_findings} rejected by the verifier`}.</p>
                <p className="muted small">An AI that always finds something is useless. The right answer here is “nothing”.</p>
              </section>
            )}
            {r.injection && (
              <section className="card">
                <h3>Planted prompt injections <span className="mono muted small">T1698</span></h3>
                <table className="data small">
                  <thead><tr><th>Case</th><th>Reached the AI</th><th>Flagged</th></tr></thead>
                  <tbody>{r.injection.cases.map((c) => (
                    <tr key={c.case}><td>{c.case}<div className="muted">{c.where}</div></td><td>{c.reached_ai ? 'yes' : 'no'}</td><td>{c.flagged ? '✓ flagged' : '✕ missed'}</td></tr>
                  ))}</tbody>
                </table>
                <p className="small">Verdict with injections present: <b>{r.injection.verdict.replace(/-/g, ' ')}</b>
                  {r.injection.steered_phrases.length > 0 ? <span className="error"> · steered: {r.injection.steered_phrases.join(', ')}</span> : ' · no injected wording in the report or briefs'}
                  {!r.injection.applicable && <span className="muted"> (mock mode can’t be steered; run live to measure the model)</span>}</p>
              </section>
            )}
            {r.detections && (
              <section className="card">
                <h3>Detections</h3>
                <p>{r.detections.passed} of {r.detections.rules} rules pass · catch {r.detections.attack_events_caught} of {r.detections.attack_events_total} attack events ·
                  {' '}{r.detections.false_alarms} false alarms · {r.detections.fresh_week_alarms} on the fresh week{r.detections.revised > 0 && ` · ${r.detections.revised} needed a revision`}</p>
              </section>
            )}
            {r.briefs && (
              <section className="card">
                <h3>Briefs</h3>
                <p>{r.briefs.verification.accepted} cited statements verified, {r.briefs.verification.rejected} rejected{r.briefs.verification.warnings.length > 0 && `, ${r.briefs.verification.warnings.length} warnings`}.</p>
              </section>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
