import { useState } from 'react';

/** "What this means" panel: the plain-English story of a screen, for non-specialist readers and demos. */
export function Explainer({ title = 'What this means', children }: { title?: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(true);
  return (
    <aside className={`explainer ${open ? 'open' : ''}`}>
      <button className="explainer-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span aria-hidden>💡</span> {title} <span className="chev" aria-hidden>{open ? '▾' : '▸'}</span>
      </button>
      {open && <div className="explainer-body">{children}</div>}
    </aside>
  );
}
