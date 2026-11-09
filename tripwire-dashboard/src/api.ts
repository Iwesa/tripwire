export type Decision = "allow" | "escalate" | "deny";
export interface Finding { rule: string; decision: Decision; detail: string }
export interface Verdict { decision: Decision; findings: Finding[] }
export interface Call { agent_id: string; tool: string; amount: string | null; currency: string; payee: string | null; agent_note?: string }
export interface AuditEntry { seq: number; ts: number; event: string; agent_id: string; hash: string; payload: Payload }
export interface Payload { call?: Call; verdict?: Verdict; by?: string; status?: string; ticket?: string; via?: string; result?: { id?: string } }
export interface Ticket { id: string; status: string; created: number; expires_at: number | null; resolved_by: string | null; call: Call; verdict: Verdict }
export interface Mandate {
  agent_id: string; task: string; currency: string; budget_total: string; per_tx_cap: string; approval_over: string;
  allowed_tools: string[]; allowed_payees: string[]; payee_mode: string; max_tx_per_hour: number; expires_at: number | null; revoked: boolean;
}
export interface AgentState { spent: string; remaining: string; tx_last_hour: number; revoked: boolean }
export interface Verify { ok: boolean; first_bad_seq: number | null; entries: number }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export function makeClient(base: string, token: string) {
  async function call<T>(path: string, init?: RequestInit): Promise<T> {
    let res: Response;
    try {
      res = await fetch(base.replace(/\/$/, "") + path, {
        ...init, headers: { "Content-Type": "application/json", "X-Admin-Token": token, ...(init?.headers ?? {}) },
      });
    } catch {
      throw new ApiError(0, "Can't reach the Tripwire API. Check the URL and that the server allows this origin (TRIPWIRE_CORS).");
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const hint = res.status === 401 || res.status === 403 ? "The admin token was rejected." : res.status === 503 ? "The server has no admin token configured." : "";
      throw new ApiError(res.status, `${hint} ${typeof body.detail === "string" ? body.detail : `HTTP ${res.status}`}`.trim());
    }
    return res.json() as Promise<T>;
  }
  return {
    health: () => call<{ ok: boolean; executor: string; judge: string }>("/health"),
    mandates: () => call<Mandate[]>("/mandates"),
    state: (id: string) => call<AgentState>(`/state/${encodeURIComponent(id)}`),
    revoke: (id: string) => call<{ revoked: boolean }>(`/mandates/${encodeURIComponent(id)}/revoke`, { method: "POST" }),
    approvals: () => call<Ticket[]>("/approvals"),
    resolve: (id: string, verb: "approve" | "deny") =>
      call<Ticket>(`/approvals/${id}/${verb}`, { method: "POST", body: JSON.stringify({ approver: "dashboard" }) }),
    audit: (limit = 200) => call<AuditEntry[]>(`/audit?limit=${limit}`),
    verify: () => call<Verify>("/audit/verify"),
  };
}
export type Client = ReturnType<typeof makeClient>;
