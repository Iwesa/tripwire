import { useCallback, useEffect, useRef, useState } from "react";
import { AgentState, ApiError, AuditEntry, Call, Client, Decision, Finding, Mandate, Ticket, Verify, makeClient } from "./api";

type Tab = "activity" | "approvals" | "agents" | "audit";
const LABEL: Record<Decision, string> = { allow: "Allowed", escalate: "Held for approval", deny: "Blocked" };
const money = (a: string | null, c = "USD") => (a == null ? "-" : `${Number(a).toLocaleString(undefined, { minimumFractionDigits: 2 })} ${c}`);
const when = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const msg = (e: unknown) => (e instanceof ApiError || e instanceof Error ? e.message : String(e));

function usePoll<T>(fn: () => Promise<T>, ms: number, on: boolean) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const ref = useRef(fn);
  ref.current = fn;
  const load = useCallback(async () => {
    try { setData(await ref.current()); setError(""); } catch (e) { setError(msg(e)); }
  }, []);
  useEffect(() => {
    if (!on) return;
    load();
    const t = setInterval(load, ms);
    return () => clearInterval(t);
  }, [on, ms, load]);
  return { data, error, reload: load };
}

function Findings({ items }: { items: Finding[] }) {
  const notable = items.filter((f) => f.decision !== "allow");
  if (!notable.length) return null;
  return (
    <ul className="findings">
      {notable.map((f, i) => (
        <li key={i} className={f.decision}><b>{f.rule.replace(/_/g, " ")}</b> {f.detail}</li>
      ))}
    </ul>
  );
}

function CallLine({ c }: { c: Call }) {
  return (
    <span className="callline">
      <span className="amt">{money(c.amount, c.currency)}</span> to <span className="payee">{c.payee ?? "no payee"}</span>
      <span className="muted"> via {c.tool.replace(/_/g, " ")} by {c.agent_id}</span>
    </span>
  );
}

function Activity({ entries }: { entries: AuditEntry[] }) {
  const rows = entries.filter((e) => ["tool_call_evaluated", "tool_call_executed", "approval_resolved", "mandate_revoked", "execution_failed"].includes(e.event)).slice().reverse();
  if (!rows.length) return <p className="empty">No agent activity yet. Run the demo agent and its payment attempts will appear here as they are decided.</p>;
  return (
    <ol className="feed">
      {rows.map((e) => {
        const p = e.payload;
        const d: Decision | null = e.event === "tool_call_evaluated" ? p.verdict?.decision ?? null : null;
        const tone = d ?? (e.event === "tool_call_executed" ? "allow" : e.event === "approval_resolved" ? (p.status === "approved" ? "allow" : "deny") : e.event === "mandate_revoked" || e.event === "execution_failed" ? "deny" : "allow");
        const title = d ? LABEL[d] : e.event === "tool_call_executed" ? "Paid" : e.event === "approval_resolved" ? (p.status === "approved" ? "Approved" : "Rejected") : e.event === "mandate_revoked" ? "Agent revoked" : "Payment failed";
        return (
          <li key={e.seq} className={`row ${tone}`}>
            <div className="rowhead"><strong>{title}</strong><time>{when(e.ts)}</time></div>
            {p.call ? <CallLine c={p.call} /> : <span className="muted">{e.agent_id}{p.by ? ` by ${p.by}` : ""}</span>}
            {p.result?.id && <span className="muted"> Payout reference {p.result.id}</span>}
            {p.verdict && <Findings items={p.verdict.findings} />}
          </li>
        );
      })}
    </ol>
  );
}

function Approvals({ api, tickets, reload }: { api: Client; tickets: Ticket[]; reload: () => void }) {
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const act = async (id: string, verb: "approve" | "deny") => {
    setBusy(id); setErr("");
    try { await api.resolve(id, verb); } catch (e) { setErr(msg(e)); }
    setBusy(""); reload();
  };
  const pending = tickets.filter((t) => t.status === "pending");
  const done = tickets.filter((t) => t.status !== "pending").slice(0, 8);
  return (
    <>
      {err && <p className="banner" role="alert">{err}</p>}
      {!pending.length && <p className="empty">Nothing is waiting for you. Payments above the auto-approve limit will stop here until you decide.</p>}
      <ol className="feed">
        {pending.map((t) => (
          <li key={t.id} className="row escalate">
            <div className="rowhead"><strong>{money(t.call.amount, t.call.currency)} waiting</strong>
              <time>{t.expires_at ? `expires ${new Date(t.expires_at * 1000).toLocaleString()}` : ""}</time></div>
            <CallLine c={t.call} />
            <Findings items={t.verdict.findings} />
            <div className="actions">
              <button className="primary" disabled={busy === t.id} onClick={() => act(t.id, "approve")}>Approve and pay</button>
              <button disabled={busy === t.id} onClick={() => act(t.id, "deny")}>Reject</button>
            </div>
          </li>
        ))}
      </ol>
      {done.length > 0 && (
        <section className="history"><h3>Recently decided</h3>
          <ul>{done.map((t) => (
            <li key={t.id}><span className={`tag ${t.status === "approved" ? "allow" : "deny"}`}>{t.status === "approved" ? "Approved" : t.resolved_by === "expired" ? "Expired" : "Rejected"}</span>
              {money(t.call.amount, t.call.currency)} to {t.call.payee} <span className="muted">by {t.resolved_by}</span></li>
          ))}</ul>
        </section>
      )}
    </>
  );
}

function SpendBar({ m, s }: { m: Mandate; s?: AgentState }) {
  const budget = Number(m.budget_total) || 1, spent = Number(s?.spent ?? 0);
  const pct = Math.min(100, (spent / budget) * 100);
  return (
    <div className="spend" role="img" aria-label={`${spent} of ${budget} ${m.currency} committed`}>
      <div className="track"><div className="fill" style={{ width: `${pct}%` }} /><div className="cap" style={{ left: `${Math.min(100, (Number(m.per_tx_cap) / budget) * 100)}%` }} title="Per-payment cap" /></div>
      <div className="figures"><span><b>{money(String(spent), m.currency)}</b> committed</span><span>{money(s?.remaining ?? m.budget_total, m.currency)} left</span><span>{s?.tx_last_hour ?? 0} of {m.max_tx_per_hour} payments this hour</span></div>
    </div>
  );
}

function Agents({ api }: { api: Client }) {
  const { data, error, reload } = usePoll(async () => {
    const ms = await api.mandates();
    const states = await Promise.all(ms.map((m) => api.state(m.agent_id).catch(() => undefined)));
    return ms.map((m, i) => ({ m, s: states[i] }));
  }, 4000, true);
  const [arm, setArm] = useState("");
  const [err, setErr] = useState("");
  const revoke = async (id: string) => {
    if (arm !== id) { setArm(id); return; }
    try { await api.revoke(id); setArm(""); reload(); } catch (e) { setErr(msg(e)); }
  };
  if (error) return <p className="banner" role="alert">{error}</p>;
  if (!data?.length) return <p className="empty">No agents have a mandate yet. Create one with the demo agent's setup command, then it will show here with its limits.</p>;
  return (
    <ul className="agents">
      {err && <p className="banner" role="alert">{err}</p>}
      {data.map(({ m, s }) => (
        <li key={m.agent_id} className={m.revoked ? "agent revoked" : "agent"}>
          <div className="agenthead"><h3>{m.agent_id}</h3>
            {m.revoked ? <span className="tag deny">Revoked</span> : (
              <button className={arm === m.agent_id ? "danger armed" : "danger"} onClick={() => revoke(m.agent_id)} onBlur={() => setArm("")}>
                {arm === m.agent_id ? "Confirm: stop all payments" : "Revoke agent"}</button>)}
          </div>
          <p className="task">{m.task}</p>
          <SpendBar m={m} s={s} />
          <dl>
            <dt>Auto-approves up to</dt><dd>{money(m.approval_over, m.currency)}</dd>
            <dt>Never pays more than</dt><dd>{money(m.per_tx_cap, m.currency)} each</dd>
            <dt>New payees</dt><dd>{m.payee_mode === "allowlist" ? "Blocked" : "Need your approval"}</dd>
            <dt>Approved payees</dt><dd>{m.allowed_payees.join(", ") || "none"}</dd>
            <dt>Tools</dt><dd>{m.allowed_tools.join(", ")}</dd>
          </dl>
        </li>
      ))}
    </ul>
  );
}

function Audit({ api, entries }: { api: Client; entries: AuditEntry[] }) {
  const [v, setV] = useState<Verify | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const run = useCallback(async () => {
    setBusy(true);
    try { setV(await api.verify()); setErr(""); } catch (e) { setErr(msg(e)); }
    setBusy(false);
  }, [api]);
  useEffect(() => { run(); }, [run]);
  return (
    <>
      <div className={`verdictbox ${v ? (v.ok ? "allow" : "deny") : ""}`}>
        <div>
          <strong>{!v ? "Checking the record..." : v.ok ? "The record is intact" : `The record was altered at entry ${v.first_bad_seq}`}</strong>
          <p className="muted">{v ? `${v.entries} entries, each signed and chained to the one before it.` : ""}{err}</p>
        </div>
        <button onClick={run} disabled={busy}>Check again</button>
      </div>
      <ol className="ledger">
        {entries.slice().reverse().slice(0, 60).map((e) => (
          <li key={e.seq}><span className="seq">{e.seq}</span><span>{e.event.replace(/_/g, " ")}</span><span className="muted">{e.agent_id}</span><code>{e.hash.slice(0, 12)}</code></li>
        ))}
      </ol>
    </>
  );
}

export default function App() {
  const [base, setBase] = useState(() => localStorage.getItem("tripwire.api") ?? "http://localhost:8000");
  const [token, setToken] = useState("");
  const [api, setApi] = useState<Client | null>(null);
  const [tab, setTab] = useState<Tab>("activity");
  const [connErr, setConnErr] = useState("");

  const connect = async () => {
    const c = makeClient(base, token);
    try { await c.health(); await c.mandates(); setApi(c); setConnErr(""); localStorage.setItem("tripwire.api", base); }
    catch (e) { setApi(null); setConnErr(msg(e)); }
  };
  const audit = usePoll(() => api!.audit(), 3000, !!api);
  const tickets = usePoll(() => api!.approvals(), 3000, !!api);
  const waiting = tickets.data?.filter((t) => t.status === "pending").length ?? 0;

  return (
    <div className="shell">
      <header>
        <h1>Tripwire</h1>
        <p className="lede">Every payment your AI agents try to make passes through here first.</p>
        <form className="connect" onSubmit={(e) => { e.preventDefault(); connect(); }}>
          <label>API address<input value={base} onChange={(e) => setBase(e.target.value)} spellCheck={false} /></label>
          <label>Admin token<input type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" placeholder="Kept in memory only" /></label>
          <button className="primary" type="submit">{api ? "Reconnect" : "Connect"}</button>
        </form>
        {connErr && <p className="banner" role="alert">{connErr}</p>}
      </header>
      {!api ? <p className="empty">Enter the API address and admin token to see what your agents are doing.</p> : (
        <>
          <nav role="tablist">
            {([["activity", "Activity"], ["approvals", `Approvals${waiting ? ` (${waiting})` : ""}`], ["agents", "Agents"], ["audit", "Audit record"]] as [Tab, string][]).map(([k, l]) => (
              <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>
            ))}
          </nav>
          <main>
            {(audit.error || tickets.error) && <p className="banner" role="alert">{audit.error || tickets.error}</p>}
            {tab === "activity" && <Activity entries={audit.data ?? []} />}
            {tab === "approvals" && <Approvals api={api} tickets={tickets.data ?? []} reload={tickets.reload} />}
            {tab === "agents" && <Agents api={api} />}
            {tab === "audit" && <Audit api={api} entries={audit.data ?? []} />}
          </main>
        </>
      )}
    </div>
  );
}
