import { useEffect, useState } from 'react';
import { api, type Evidence } from '../api';

const KIND_LABEL: Record<string, string> = { log: 'Log event', intel: 'Threat intelligence', report: 'Report passage' };

export function evidenceKind(id: string): 'log' | 'intel' | 'report' {
  if (/^(auth|edr|net|cld|wdr)-\d+$/.test(id)) return 'log';
  if (id.includes('#')) return 'report';
  return 'intel';
}

/** A clickable citation. Opens the raw record it points to. */
export function EvidenceChip({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  const kind = evidenceKind(id);
  const label = kind === 'intel' ? `${id.split('--')[0]}…${id.slice(-6)}` : id;
  return (
    <button className={`chip evidence ${kind}`} onClick={() => onOpen(id)} title={`Open ${KIND_LABEL[kind].toLowerCase()} ${id}`}>
      {label}
    </button>
  );
}

/** Side panel showing the raw evidence behind a citation. */
export function EvidenceDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [data, setData] = useState<Evidence | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setData(null);
    setError(null);
    api.evidence(id).then(setData, (e: Error) => setError(e.message));
  }, [id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!id) return null;
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-label={`Evidence ${id}`} onClick={(e) => e.stopPropagation()}>
        <header>
          <div>
            <div className="eyebrow">{KIND_LABEL[evidenceKind(id)]}</div>
            <h3 className="mono">{id}</h3>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">✕</button>
        </header>
        {error && <p className="error">{error}</p>}
        {!data && !error && <p className="muted">Loading…</p>}
        {data?.kind === 'log' && (
          <>
            <p className="muted">From <code>{data.table}</code>. This is the exact record the AI cited.</p>
            <table className="kv">
              <tbody>
                {Object.entries(data.record).filter(([, v]) => v !== null).map(([k, v]) => (
                  <tr key={k}><th>{k}</th><td className="mono">{v}</td></tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {data?.kind === 'intel' && (
          <>
            <h4>{data.name}</h4>
            <p className="muted">{data.type}{data.url && <> · <a href={data.url} target="_blank" rel="noreferrer">source</a></>}</p>
            {data.description && <p>{data.description}</p>}
            <details><summary>Raw STIX object</summary><pre>{JSON.stringify(data.record, null, 2)}</pre></details>
          </>
        )}
        {data?.kind === 'report' && (
          <>
            <h4>{data.title}</h4>
            <p className="muted">
              {data.source}{data.published && ` · ${data.published}`}
              {data.url && <> · <a href={data.url} target="_blank" rel="noreferrer">original</a></>}
            </p>
            <blockquote>{data.text.replace(/^\[[^\]]*\]\s*/, '')}</blockquote>
          </>
        )}
      </aside>
    </div>
  );
}
