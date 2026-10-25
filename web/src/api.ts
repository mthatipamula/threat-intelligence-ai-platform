// Typed access to the Python API (src/tip/api.py).

export interface Config { live_available: boolean; model: string }

export interface Technique { id: string; name: string; url: string }
export interface Actor {
  id: string; name: string; attack_id: string; url: string; aliases: string[]; description: string;
  campaigns: { id: string; name: string; url: string }[]; software: string[];
  tactics: { tactic: string; techniques: Technique[] }[]; technique_count: number;
}

export interface Signals {
  lookalike_domains: { domain: string; ips: string[]; labels: string[] }[];
  watched_domains: string[];
  sanctioned_addresses_by_chain: { chain: string; addresses: number }[];
  known_exploited: { cve: string; vendor: string; product: string; added: string; ransomware: boolean }[];
  advisories: { id: string; title: string; source: string; url: string; published: string }[];
}

export interface Overview {
  intel: { source: string; type: string; objects: number }[];
  library: { kind: string; documents: number; chunks: number }[];
  logs: { tables: Record<string, number>; from: string; to: string; employees: number; company: string };
}

export interface Finding {
  title: string; what_happened: string; when: string; technique_ids: string[];
  severity: 'critical' | 'high' | 'medium' | 'low'; affected: string[]; evidence_ids: string[];
}
export interface Check { status: 'accepted' | 'rejected'; problems: string[] }
export interface Report {
  verdict: string; confidence: string; summary: string; findings: Finding[];
  context: { statement: string; evidence_ids: string[] }[]; recommended_actions: string[]; open_questions: string[];
}
export interface ToolCall { tool: string; input: Record<string, unknown>; evidence_ids: string[]; summary: string; error: string | null; at: string }
export interface Investigation {
  id: string; question: string; mode: 'mock' | 'live'; status: string; progress: string[]; trace: ToolCall[];
  report: Report | null; revisions: number; error: string | null;
  verification: { findings: Check[]; context: Check[]; accepted: number; rejected: number; passed: boolean } | null;
  usage: { model_calls: number; input_tokens: number; output_tokens: number; estimated_cost_usd: number; fallbacks: string[] } | null;
  created_at: string; finished_at: string | null;
}
export interface InvestigationSummary {
  id: string; question: string; mode: string; status: string; created_at: string; accepted: number | null;
  rejected: number | null; verdict: string | null;
}

export type Evidence =
  | { kind: 'log'; table: string; record: Record<string, string | null> }
  | { kind: 'intel'; type: string; name: string; description: string; url: string | null; record: Record<string, unknown> }
  | { kind: 'report'; id: string; title: string; text: string; source: string; url: string | null; published: string | null; doc_kind: string };

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, { headers: { 'Content-Type': 'application/json' }, ...init });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  config: () => call<Config>('/config'),
  overview: () => call<Overview>('/overview'),
  actor: (name: string) => call<Actor>(`/actors/${encodeURIComponent(name)}`),
  signals: () => call<Signals>('/signals'),
  investigations: () => call<InvestigationSummary[]>('/investigations'),
  investigation: (id: string) => call<Investigation>(`/investigations/${id}`),
  investigate: (question: string, mode: 'mock' | 'live') =>
    call<{ id: string }>('/investigations', { method: 'POST', body: JSON.stringify({ question, mode }) }),
  evidence: (id: string) => call<Evidence>(`/evidence/${encodeURIComponent(id)}`),
};
