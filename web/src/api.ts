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
  injection_warnings?: { path: string; evidence: string; reasons: string; excerpt: string }[];
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

// ---------------------------------------------------------------- detections (step 3)

export interface TestResult {
  verdict: 'passed' | 'failed'; reasons: string[]; table?: string; scanned?: number;
  attack_events_caught?: number; expected_for_techniques?: number; caught_of_expected?: number;
  false_alarms?: number; fresh_week_scanned?: number; fresh_week_alarms?: number;
  sample_attack_hits?: Record<string, string>[]; sample_false_alarms?: Record<string, string>[];
  sample_fresh_week_alarms?: Record<string, string>[];
}
export interface Detection {
  id: string; batch_id: string; investigation_id: string | null; mode: string; finding: string | null;
  title: string | null; description: string | null; level: string | null; technique_ids: string[];
  sigma_yaml: string | null; status: 'drafting' | 'passed' | 'failed' | 'approved' | 'rejected' | 'error';
  translations: { sql: string | null; spl: string | null; kql: string | null; table: string | null; errors: Record<string, string> } | null;
  test: TestResult | null; attempts: { yaml: string; verdict: string; reasons: string[]; note: string | null }[];
  reviewer: string | null; review_note: string | null; approved_path: string | null; error: string | null;
  created_at: string; reviewed_at: string | null;
}
export interface Coverage {
  actor: string; total: number; covered: number; pending: number; beyond_actor: string[];
  techniques: { id: string; name: string; tactics: string[]; approved: string[]; pending: string[] }[];
}

export const detectionsApi = {
  draft: (investigation_id: string, mode: 'mock' | 'live') =>
    call<{ batch_id: string }>('/detections', { method: 'POST', body: JSON.stringify({ investigation_id, mode }) }),
  list: (batchId?: string) => call<Detection[]>(`/detections${batchId ? `?batch_id=${batchId}` : ''}`),
  review: (id: string, decision: 'approve' | 'reject', reviewer: string, note: string) =>
    call<Detection>(`/detections/${id}/review`, { method: 'POST', body: JSON.stringify({ decision, reviewer, note }) }),
  coverageActors: () => call<string[]>('/coverage/actors'),
  coverage: (actor: string) => call<Coverage>(`/coverage?actor=${encodeURIComponent(actor)}`),
};

// ---------------------------------------------------------------- briefs and evaluation (step 4)

export interface Cited { text: string; evidence_ids: string[] }
export interface BriefItemCheck { section: string; item: string; status: 'accepted' | 'rejected'; problems: string[] }
export interface Brief {
  id: string; investigation_id: string; mode: string; status: 'writing' | 'ready' | 'approved' | 'rejected' | 'failed';
  facts: { money: { withdrawn_usd: number; pending_usd: number; attempted_usd: number; to_sanctioned_usd: number };
    people: string[]; hosts: string[]; first_event: string | null; last_event: string | null; hours_first_to_last: number | null } | null;
  technical: {
    title: string; summary: string;
    timeline: { when: string; what: string; technique_ids: string[]; evidence_ids: string[] }[];
    indicators: { type: string; value: string; context: string; evidence_ids: string[] }[];
    techniques: { technique_id: string; name: string; how_used: string; evidence_ids: string[] }[];
    detections: Cited[]; actions: string[]; open_questions: string[];
  } | null;
  executive: {
    headline: string; assessment: string; confidence: string; confidence_basis: string;
    key_points: Cited[]; impact: Cited[]; decisions_needed: string[]; next_24_hours: string[];
  } | null;
  verification: { items: BriefItemCheck[]; accepted: number; rejected: number; warnings: string[]; passed: boolean } | null;
  revisions: number; reviewer: string | null; review_note: string | null; error: string | null;
  usage: { estimated_cost_usd: number } | null; created_at: string;
}

export interface Gate { key: string; label: string; value: number | boolean | null; op: string; threshold: number | null; status: 'pass' | 'fail' | 'n/a' }
export interface EvalResults {
  gates?: Gate[]; cost_usd?: number;
  accuracy?: { steps: { step: number; technique_id: string; description: string; found: boolean; by: string | null }[];
    steps_found: number; steps_total: number; accepted_findings: number; real_findings: number; false_findings: string[];
    rejected_findings: number; rejected_titles: string[]; verdict: string };
  no_attack_week?: { verdict: string; accepted_findings: number; rejected_findings: number; titles: string[] };
  injection?: { cases: { case: string; where: string; technique: string; reached_ai: boolean; flagged: boolean }[];
    verdict: string; steered_phrases: string[]; resisted: boolean; applicable: boolean };
  detections?: { rules: number; passed: number; attack_events_caught: number; attack_events_total: number;
    false_alarms: number; fresh_week_alarms: number; revised: number;
    rules_detail: { title: string; status: string; attempts: number; caught: number; false_alarms: number }[] };
  briefs?: { status: string; verification: { accepted: number; rejected: number; warnings: string[] } };
}
export interface EvalRun { id: string; mode: string; status: 'running' | 'done' | 'failed'; progress: string[]; results: EvalResults | null; error: string | null; started_at: string; finished_at: string | null }
export interface EvalSummary { id: string; mode: string; status: string; started_at: string; cost_usd: number | null; passed: number; failed: number }

export const briefsApi = {
  write: (investigation_id: string, mode: 'mock' | 'live') =>
    call<{ id: string }>('/briefs', { method: 'POST', body: JSON.stringify({ investigation_id, mode }) }),
  latest: (investigationId: string) => call<Brief | null>(`/briefs?investigation_id=${investigationId}`),
  get: (id: string) => call<Brief>(`/briefs/${id}`),
  review: (id: string, decision: 'approve' | 'reject', reviewer: string, note: string) =>
    call<Brief>(`/briefs/${id}/review`, { method: 'POST', body: JSON.stringify({ decision, reviewer, note }) }),
  markdownUrl: (id: string, audience: 'executive' | 'technical') => `/api/briefs/${id}/markdown?audience=${audience}`,
};
export const evalsApi = {
  start: (mode: 'mock' | 'live') => call<{ id: string }>('/evals', { method: 'POST', body: JSON.stringify({ mode }) }),
  list: () => call<EvalSummary[]>('/evals'),
  get: (id: string) => call<EvalRun>(`/evals/${id}`),
};
