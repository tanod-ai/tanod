import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';
type StatusFilter = ApprovalStatus | 'all';

interface ApprovalRequest {
  approval_id: string;
  request_id: string;
  status: ApprovalStatus;
  request: {
    actor: { user_id: string };
    agent: { agent_id: string; environment?: string };
    tool: { name: string; category?: string; operation?: string };
    target?: { system?: string; environment?: string };
    arguments: Record<string, unknown>;
    context?: Record<string, unknown>;
  };
  decision: {
    decision: string;
    risk_level: string;
    policy_ids: string[];
    message: string;
  };
  argument_hash: string;
  requested_by: string;
  approved_by?: string;
  rejected_by?: string;
  rejection_reason?: string;
  created_at: string;
  updated_at: string;
}

const defaultApiBase = import.meta.env.VITE_TANOD_API_BASE ?? '';

function App() {
  const [apiBase, setApiBase] = useLocalStorage('tanod.console.apiBase', defaultApiBase);
  const [apiKey, setApiKey] = useSessionStorage('tanod.console.apiKey', '');
  const [approver, setApprover] = useLocalStorage('tanod.console.approver', 'operator@example.com');
  const [approverRole, setApproverRole] = useLocalStorage('tanod.console.approverRole', 'platform_owner');
  const [status, setStatus] = useState<StatusFilter>('pending');
  const [records, setRecords] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const stats = useMemo(() => ({
    pending: records.filter((r) => r.status === 'pending').length,
    total: records.length,
  }), [records]);

  async function api(path: string, init?: RequestInit) {
    const headers = new Headers(init?.headers);
    headers.set('content-type', 'application/json');
    if (apiKey.trim()) headers.set('authorization', `Bearer ${apiKey.trim()}`);
    const response = await fetch(`${apiBase.replace(/\/$/, '')}${path}`, { ...init, headers });
    const text = await response.text();
    const data = text ? JSON.parse(text) : undefined;
    if (!response.ok) throw new Error(data?.error ?? response.statusText);
    return data;
  }

  async function loadApprovals(nextStatus = status) {
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const query = nextStatus === 'all' ? '' : `?status=${encodeURIComponent(nextStatus)}`;
      const data = await api(`/v1/approval-requests${query}`);
      setRecords(data.approval_requests ?? []);
      setMessage(`Loaded ${(data.approval_requests ?? []).length} ${nextStatus} approval request(s).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load approvals.');
    } finally {
      setLoading(false);
    }
  }

  async function approve(record: ApprovalRequest) {
    setError('');
    try {
      await api(`/v1/approval-requests/${encodeURIComponent(record.approval_id)}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approved_by: approver, approved_role: approverRole }),
      });
      await loadApprovals();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Approval failed.');
    }
  }

  async function reject(record: ApprovalRequest) {
    const reason = window.prompt('Reason for rejection?') ?? undefined;
    setError('');
    try {
      await api(`/v1/approval-requests/${encodeURIComponent(record.approval_id)}/reject`, {
        method: 'POST',
        body: JSON.stringify({ rejected_by: approver, reason }),
      });
      await loadApprovals();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rejection failed.');
    }
  }

  useEffect(() => { void loadApprovals(); }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="logo">T</span><div><strong>Tanod</strong><small>Execution Control</small></div></div>
        <nav>
          <a className="active">Approvals</a>
          <a>Audit</a>
          <a>Policies</a>
          <a>Agents</a>
        </nav>
        <div className="sidebar-note">Policy, approval, signed execution, and audit controls for AI-agent tool calls.</div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div><h1>Approval Queue</h1><p>Review exact tool calls before signed execution.</p></div>
          <button onClick={() => loadApprovals()} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh'}</button>
        </header>

        <section className="config-grid">
          <label>API base<input value={apiBase} onChange={(e) => setApiBase(e.target.value)} placeholder="same origin or http://host:8787" /></label>
          <label>API key<input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="required if TANOD_API_KEYS is set" /></label>
          <label>Approver<input value={approver} onChange={(e) => setApprover(e.target.value)} /></label>
          <label>Role<input value={approverRole} onChange={(e) => setApproverRole(e.target.value)} placeholder="platform_owner" /></label>
          <label>Status<select value={status} onChange={(e) => { const next = e.target.value as StatusFilter; setStatus(next); void loadApprovals(next); }}><option value="pending">Pending</option><option value="all">All</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="expired">Expired</option></select></label>
        </section>

        <section className="metrics"><div><strong>{stats.pending}</strong><span>Pending</span></div><div><strong>{stats.total}</strong><span>Shown</span></div><div><strong>{status}</strong><span>Filter</span></div></section>
        {error && <div className="banner error">{error}</div>}
        {message && !error && <div className="banner ok">{message}</div>}

        <section className="cards">
          {records.length === 0 ? <EmptyState status={status} /> : records.map((record) => <ApprovalCard key={record.approval_id} record={record} onApprove={approve} onReject={reject} />)}
        </section>
      </main>
    </div>
  );
}

function ApprovalCard({ record, onApprove, onReject }: { record: ApprovalRequest; onApprove: (r: ApprovalRequest) => void; onReject: (r: ApprovalRequest) => void }) {
  return <article className="approval-card">
    <div className="card-head"><div><h2>{record.request.tool.name}</h2><p>{record.decision.message}</p></div><div className="badges"><span className={`status ${record.status}`}>{record.status}</span><span className="risk">{record.decision.risk_level}</span></div></div>
    <div className="meta-grid"><Meta label="Approval" value={record.approval_id} /><Meta label="Request" value={record.request_id} /><Meta label="Agent" value={record.request.agent.agent_id} /><Meta label="Actor" value={record.request.actor.user_id} /><Meta label="Target" value={`${record.request.target?.system ?? 'unknown'} / ${record.request.target?.environment ?? 'unknown'}`} /><Meta label="Policies" value={record.decision.policy_ids.join(', ') || 'manual'} /></div>
    <div className="hash"><span>Argument hash</span><code>{record.argument_hash}</code></div>
    <div className="json-grid"><div><h3>Arguments</h3><pre>{JSON.stringify(record.request.arguments, null, 2)}</pre></div><div><h3>Context</h3><pre>{JSON.stringify(record.request.context ?? {}, null, 2)}</pre></div></div>
    {record.status === 'pending' ? <div className="actions"><button className="approve" onClick={() => onApprove(record)}>Approve exact action</button><button className="reject" onClick={() => onReject(record)}>Reject</button></div> : <p className="muted">No actions available for {record.status} requests.</p>}
  </article>;
}

function Meta({ label, value }: { label: string; value: string }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function EmptyState({ status }: { status: StatusFilter }) { return <div className="empty"><h2>No {status} approval requests</h2><p>Create one with <code>tanod request-approval examples/requests/shell-write-prod.json --by ross@example.com</code>.</p><p>A plain <code>tanod decide</code> only evaluates policy and does not create a persistent console item.</p></div>; }
function useLocalStorage(key: string, initial: string): [string, (value: string) => void] { const [value, setValue] = useState(() => localStorage.getItem(key) ?? initial); return [value, (next) => { localStorage.setItem(key, next); setValue(next); }]; }
function useSessionStorage(key: string, initial: string): [string, (value: string) => void] {
  const [value, setValue] = useState(() => {
    localStorage.removeItem(key);
    return sessionStorage.getItem(key) ?? initial;
  });
  return [value, (next) => { sessionStorage.setItem(key, next); setValue(next); }];
}

createRoot(document.getElementById('root')!).render(<App />);
