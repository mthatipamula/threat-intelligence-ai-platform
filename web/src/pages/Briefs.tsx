import { useCallback, useEffect, useRef, useState } from 'react';
import { api, briefsApi, type Brief, type BriefItemCheck, type Cited, type Config, type InvestigationSummary } from '../api';
import { EvidenceChip, EvidenceDrawer } from '../components/Evidence';
import { Explainer } from '../components/Explainer';
import { Term } from '../components/Term';

const reviewerKey = 'tip.reviewer';
const readReviewer = () => { try { return localStorage.getItem(reviewerKey) ?? ''; } catch { return ''; } };
const usd = (n: number) => `$${(n / 1e6).toFixed(2)}M`;

/** Screen 4: tell leadership. Executive and technical briefs, every statement checked against the evidence. */
export function Briefs() {
  const [config, setConfig] = useState<Config | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [investigationId, setInvestigationId] = useState('');
  const [mode, setMode] = useState<'mock' | 'live'>('mock');
  const [brief, setBrief] = useState<Brief | null>(null);
  const [reviewer, setReviewer] = useState(readReviewer);
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    api.investigations().then((list) => {
      const done = list.filter((i) => i.status === 'done');
      setInvestigations(done);
      if (done[0]) setInvestigationId(done[0].id);
    }).catch((e: Error) => setError(e.message));
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, []);
  useEffect(() => {
    if (!investigationId) return;
    briefsApi.latest(investigationId).then(setBrief).catch(() => setBrief(null));
  }, [investigationId]);
  useEffect(() => { try { localStorage.setItem(reviewerKey, reviewer); } catch { /* storage unavailable */ } }, [reviewer]);

  const follow = useCallback((id: string) => {
    const poll = () => briefsApi.get(id).then((b) => {
      setBrief(b);
      if (b.status === 'writing') timer.current = window.setTimeout(poll, 700);
    }, (e: Error) => setError(e.message));
    poll();
  }, []);

  const write = async () => {
    setError(null);
    try { const { id } = await briefsApi.write(investigationId, mode); setBrief(null); follow(id); }
    catch (e) { setError((e as Error).message); }
  };
  const decide = async (decision: 'approve' | 'reject') => {
    if (!brief) return;
    setError(null);
    try { setBrief(await briefsApi.review(brief.id, decision, reviewer || 'analyst', note)); setNote(''); }
    catch (e) { setError((e as Error).message); }
  };

  const checks = brief?.verification?.items ?? [];
  const checkFor = (section: string, text: string) => checks.find((c) => c.section === section && text.startsWith(c.item.slice(0, 60)));
  const e = brief?.executive;
  const t = brief?.technical;

  return (
    <div className="page">
      <header className="page-head">
        <div className="eyebrow">Step 4 · Reporting</div>
        <h1>Tell leadership</h1>
        <p className="lede">Two briefs from one investigation: one for the security team, one for the executives.</p>
      </header>

      <Explainer>
        <p>
          The same facts need two very different write-ups. The <b>executive brief</b> starts with the <Term name="BLUF" />,
          avoids jargon, puts the impact in dollars and says what leadership must decide. Its assessment uses the standard
          intelligence wording for likelihood (<Term name="ICD 203" />: “likely”, “very likely”), so “how sure are we?” has a
          precise answer. The <b>technical brief</b> gives the security team the timeline, the indicators to block and the
          attacker techniques.
        </p>
        <p>
          Money, counts and indicators are computed by code from the cited evidence, never by the AI. Every statement cites
          its evidence (click a chip), and a checker rejects any statement whose evidence isn’t real, any indicator that
          doesn’t appear in its evidence, and any dollar figure that isn’t in the computed facts. A person approves the
          briefs before they go anywhere; then they can be downloaded as Markdown.
        </p>
      </Explainer>

      <section className="card ask">
        <div className="ask-row">
          <label className="field">
            <span className="eyebrow">From investigation</span>
            <select value={investigationId} onChange={(ev) => setInvestigationId(ev.target.value)}>
              {investigations.length === 0 && <option value="">Run an investigation on screen 2 first</option>}
              {investigations.map((i) => (
                <option key={i.id} value={i.id}>{new Date(i.created_at).toLocaleString()} · {i.mode} · {i.accepted ?? 0} verified findings</option>
              ))}
            </select>
          </label>
          <div className="segmented" role="radiogroup" aria-label="Mode">
            <button role="radio" aria-checked={mode === 'mock'} className={mode === 'mock' ? 'on' : ''} onClick={() => setMode('mock')}>Mock (free)</button>
            <button role="radio" aria-checked={mode === 'live'} className={mode === 'live' ? 'on' : ''} disabled={!config?.live_available}
              title={config?.live_available ? 'Claude writes the briefs' : 'Add ANTHROPIC_API_KEY to .env to enable'} onClick={() => setMode('live')}>Live (Claude)</button>
          </div>
          <button className="primary" onClick={write} disabled={!investigationId || brief?.status === 'writing'}>
            {brief?.status === 'writing' ? 'Writing…' : brief ? 'Rewrite briefs' : 'Write briefs'}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
        {brief?.status === 'failed' && <p className="error">{brief.error}</p>}
      </section>

      {brief?.status === 'writing' && <section className="card"><h3>Writing and checking both briefs<span className="spinner" aria-hidden /></h3></section>}

      {brief && e && t && brief.verification && (
        <>
          <section className={`card check-summary ${brief.verification.passed ? 'ok' : 'bad'}`}>
            <div className="card-head">
              <div>
                <div className="eyebrow">Checks</div>
                <h3>{brief.verification.accepted} of {brief.verification.accepted + brief.verification.rejected} cited statements verified
                  {brief.verification.warnings.length > 0 && ` · ${brief.verification.warnings.length} warning(s)`}</h3>
              </div>
              <span className={`badge ${brief.status === 'approved' ? 'ok' : brief.status === 'rejected' ? 'critical' : 'low'}`}>
                {brief.status === 'approved' ? `Approved by ${brief.reviewer}` : brief.status === 'rejected' ? 'Rejected' : 'Draft · needs approval'}
              </span>
            </div>
            {brief.verification.warnings.map((w) => <p key={w} className="error small">⚠ {w}</p>)}
            {brief.verification.items.filter((i) => i.status === 'rejected').map((i) => (
              <p key={i.section + i.item} className="error small">✕ {i.section}: {i.item} — {i.problems.join('; ')}</p>
            ))}
            {brief.facts && (
              <div className="facts">
                <span><b>{usd(brief.facts.money.withdrawn_usd)}</b> withdrawn</span>
                <span><b>{usd(brief.facts.money.pending_usd)}</b> pending</span>
                <span><b>{usd(brief.facts.money.to_sanctioned_usd)}</b> to a sanctioned wallet</span>
                <span><b>{brief.facts.people.length}</b> account(s), <b>{brief.facts.hosts.length}</b> laptop(s)</span>
                {brief.facts.hours_first_to_last !== null && <span><b>{brief.facts.hours_first_to_last} h</b> first to last event</span>}
                <span className="muted small">computed from evidence, not by the AI</span>
              </div>
            )}
            <div className="review">
              <input value={reviewer} onChange={(ev) => setReviewer(ev.target.value)} placeholder="Reviewer" maxLength={80} className="reviewer-input" />
              <input value={note} onChange={(ev) => setNote(ev.target.value)} placeholder="Review note (optional)" maxLength={500} />
              <button className="secondary" onClick={() => decide('reject')}>Reject</button>
              <button className="primary" onClick={() => decide('approve')} disabled={brief.verification.rejected > 0}
                title={brief.verification.rejected > 0 ? 'Fix or remove rejected statements first' : undefined}>Approve</button>
            </div>
            <div className="downloads small">
              Download: <a href={briefsApi.markdownUrl(brief.id, 'executive')}>executive brief (.md)</a> ·{' '}
              <a href={briefsApi.markdownUrl(brief.id, 'technical')}>technical brief (.md)</a>
              {brief.status !== 'approved' && <span className="muted"> (marked DRAFT until approved)</span>}
              {' · '}<a href={`/api/misp/incident?investigation_id=${brief.investigation_id}`}>indicators as a MISP event (.json)</a>
              <span className="muted"> for sharing with industry partners (TLP:AMBER)</span>
            </div>
          </section>

          <div className="grid two briefs-grid">
            <article className="card brief executive">
              <div className="eyebrow">Executive brief · for the CEO and board</div>
              <h2 className="headline">{e.headline}</h2>
              <p className="assessment"><b>Assessment.</b> {e.assessment}</p>
              <p className="confidence"><span className={`badge ${e.confidence === 'high' ? 'ok' : e.confidence === 'moderate' ? 'medium' : 'low'}`}>{e.confidence} confidence</span> {e.confidence_basis}</p>
              {e.key_points.length > 0 && <><h3>What happened</h3><CitedList items={e.key_points} section="executive.key_points" checkFor={checkFor} onOpen={setEvidence} /></>}
              {e.impact.length > 0 && <><h3>Impact</h3><CitedList items={e.impact} section="executive.impact" checkFor={checkFor} onOpen={setEvidence} /></>}
              {e.decisions_needed.length > 0 && <><h3>Decisions needed now</h3><ol className="decisions">{e.decisions_needed.map((d) => <li key={d}>{d}</li>)}</ol></>}
              <h3>Next 24 hours</h3>
              <ul>{e.next_24_hours.map((n) => <li key={n}>{n}</li>)}</ul>
            </article>

            <article className="card brief technical">
              <div className="eyebrow">Technical brief · for the security team</div>
              <h2>{t.title}</h2>
              <p>{t.summary}</p>
              <h3>Timeline (UTC)</h3>
              <ol className="mini-timeline">
                {t.timeline.map((x) => (
                  <li key={x.when + x.what}>
                    <span className="mono small">{x.when.slice(5, 16).replace('T', ' ')}</span> {x.what}
                    <div className="meta">{x.technique_ids.map((id) => <span key={id} className="chip technique mono">{id}</span>)}
                      {x.evidence_ids.slice(0, 3).map((id) => <EvidenceChip key={id} id={id} onOpen={setEvidence} />)}</div>
                  </li>
                ))}
              </ol>
              <h3>Indicators to block and hunt for</h3>
              <table className="data small">
                <thead><tr><th>Type</th><th>Value</th><th>What it is</th><th></th></tr></thead>
                <tbody>{t.indicators.map((i) => {
                  const c = checkFor('technical.indicators', `${i.type} ${i.value}`);
                  return (
                    <tr key={i.type + i.value} className={c?.status === 'rejected' ? 'rejected-row' : ''}>
                      <td>{i.type}</td><td className="mono ioc">{i.value}</td><td>{i.context}</td>
                      <td>{i.evidence_ids.slice(0, 1).map((id) => <EvidenceChip key={id} id={id} onOpen={setEvidence} />)}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
              <h3>Attacker techniques (<Term name="ATT&CK" />)</h3>
              <ul className="plain small">{t.techniques.map((x) => <li key={x.technique_id}><span className="mono">{x.technique_id}</span> <b>{x.name}</b> — {x.how_used}</li>)}</ul>
              {t.detections.length > 0 && <><h3>Detections drafted</h3><ul className="small">{t.detections.map((d) => <li key={d.text}>{d.text}</li>)}</ul></>}
              <h3>Actions</h3>
              <ol className="small">{t.actions.map((a) => <li key={a}>{a}</li>)}</ol>
              {t.open_questions.length > 0 && <><h3>Open questions</h3><ul className="small">{t.open_questions.map((q) => <li key={q}>{q}</li>)}</ul></>}
            </article>
          </div>
        </>
      )}
      <EvidenceDrawer id={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}

function CitedList({ items, section, checkFor, onOpen }: {
  items: Cited[]; section: string; checkFor: (s: string, t: string) => BriefItemCheck | undefined; onOpen: (id: string) => void;
}) {
  return (
    <ul className="cited">
      {items.map((p) => {
        const c = checkFor(section, p.text);
        return (
          <li key={p.text} className={c?.status === 'rejected' ? 'rejected-row' : ''}>
            {p.text}
            <div className="meta">
              {c?.status === 'rejected' && <span className="badge critical">rejected: {c.problems.join('; ')}</span>}
              {p.evidence_ids.slice(0, 4).map((id) => <EvidenceChip key={id} id={id} onOpen={onOpen} />)}
              {p.evidence_ids.length > 4 && <span className="muted small">+{p.evidence_ids.length - 4}</span>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
