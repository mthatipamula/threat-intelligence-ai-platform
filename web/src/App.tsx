import { useEffect, useState } from 'react';
import { Briefs } from './pages/Briefs';
import { Detections } from './pages/Detections';
import { Investigate } from './pages/Investigate';
import { Trust } from './pages/Trust';
import { World } from './pages/World';

const SCREENS = [
  { id: 'world', n: 1, label: 'What’s happening', ready: true },
  { id: 'investigate', n: 2, label: 'Are we affected?', ready: true },
  { id: 'detections', n: 3, label: 'Catch it next time', ready: true },
  { id: 'briefs', n: 4, label: 'Tell leadership', ready: true },
  { id: 'trust', n: 5, label: 'Can we trust the AI?', ready: true },
] as const;
type ScreenId = (typeof SCREENS)[number]['id'];

const fromHash = (): ScreenId => {
  const id = window.location.hash.replace('#/', '') as ScreenId;
  return SCREENS.some((s) => s.id === id && s.ready) ? id : 'world';
};

export function App() {
  const [screen, setScreen] = useState<ScreenId>(fromHash);
  useEffect(() => {
    const onHash = () => setScreen(fromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden>◆</span>
          <div><b>Threat Intelligence AI Platform</b><span className="muted"> · Meridian Exchange (synthetic)</span></div>
        </div>
        <nav aria-label="Demo screens">
          {SCREENS.map((s) => (s.ready as boolean) ? (
            <a key={s.id} href={`#/${s.id}`} className={screen === s.id ? 'active' : ''} aria-current={screen === s.id ? 'page' : undefined}>
              <span className="step">{s.n}</span>{s.label}
            </a>
          ) : (
            <span key={s.id} className="soon" title={`Coming in build step ${'step' in s ? s.step : ''}`}><span className="step">{s.n}</span>{s.label}</span>
          ))}
        </nav>
      </header>
      <main>{{ world: <World />, investigate: <Investigate />, detections: <Detections />, briefs: <Briefs />, trust: <Trust /> }[screen]}</main>
      <footer className="muted small">
        Portfolio project. Intelligence from public sources (MITRE ATT&CK, CISA, FBI, OFAC); company logs are synthetic.
      </footer>
    </div>
  );
}
