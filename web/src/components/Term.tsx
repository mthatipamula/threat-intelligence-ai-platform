import { GLOSSARY } from '../glossary';

/** A jargon term with its plain-English definition on hover or keyboard focus. */
export function Term({ name, children }: { name: string; children?: React.ReactNode }) {
  const definition = GLOSSARY[name];
  if (!definition) return <>{children ?? name}</>;
  return (
    <span className="term" tabIndex={0} title={definition} aria-label={`${name}: ${definition}`}>
      {children ?? name}
    </span>
  );
}
