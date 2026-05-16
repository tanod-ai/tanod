import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import tanodLogo from './assets/tanod-logo.png';
import './styles.css';

type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';
type StatusFilter = ApprovalStatus | 'all';
type Role = 'Admin' | 'Approver' | 'Viewer';
type View = 'login' | 'approvals' | 'audit' | 'policies' | 'agents' | 'profile' | 'admin';

interface ToolCallRequest {
  actor: { user_id: string };
  agent: { agent_id: string; agent_type?: string; environment?: string };
  tool: { name: string; category?: string; operation?: string };
  target?: { system?: string; environment?: string; resource?: string };
  arguments: Record<string, unknown>;
  context?: Record<string, unknown>;
}

interface DecisionResponse {
  decision: string;
  risk_level: string;
  policy_ids: string[];
  message: string;
  approval?: { required_roles?: string[]; token_ttl_seconds?: number };
}

interface ApprovalRequest {
  approval_id: string;
  request_id: string;
  status: ApprovalStatus;
  request: ToolCallRequest;
  decision: DecisionResponse;
  argument_hash: string;
  requested_by: string;
  approved_by?: string;
  approved_role?: string;
  rejected_by?: string;
  rejection_reason?: string;
  created_at: string;
  updated_at: string;
}

interface AuditEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  request_id?: string;
  actor_id?: string;
  agent_id?: string;
  tool_name?: string;
  decision?: string;
  risk_level?: string;
  policy_ids?: string[];
  argument_hash?: string;
  approval_id?: string;
  result?: string;
  details?: Record<string, unknown>;
  event_hash?: string;
}

interface PolicyRule {
  id: string;
  description?: string;
  priority?: number;
  when: Record<string, unknown>;
  then: {
    decision: string;
    risk_level?: string;
    message?: string;
    approval?: { required_roles?: string[]; token_ttl_seconds?: number };
    audit?: { severity?: string };
  };
}

interface PolicyFile {
  version: string;
  default_decision?: string;
  default_risk_level?: string;
  policies: PolicyRule[];
}

interface AgentSummary {
  agent_id: string;
  agent_type?: string;
  environment?: string;
  tool_call_count: number;
  pending_approval_count: number;
  approved_approval_count: number;
  rejected_approval_count: number;
  decisions: Record<string, number>;
  tools: string[];
  actors: string[];
  last_seen_at?: string;
}

interface UserRecord {
  user_id: string;
  identity: string;
  display_name: string;
  roles: Role[];
  status: 'active' | 'disabled';
  created_at: string;
  updated_at: string;
}

interface InvitationRecord {
  invitation_id: string;
  token: string;
  email: string;
  roles: Role[];
  invited_by: string;
  invite_url?: string;
  accepted_by?: string;
  accepted_at?: string;
  expires_at: string;
  created_at: string;
}

interface MeResponse {
  identity?: string;
  role?: Role;
  roles: Role[];
  external_roles?: string[];
  user?: UserRecord;
  capabilities: { view: boolean; approve: boolean; administer: boolean; mutate_policies: boolean };
}

interface OidcProvider {
  id: string;
  label: string;
  issuer: string;
  clientId: string;
  scope?: string;
}

interface OAuth2Provider {
  id: string;
  label: string;
}

interface ConsoleConfig {
  api_base_url?: string;
  oidc_providers?: OidcProvider[];
  oauth2_providers?: OAuth2Provider[];
}

interface OidcSession {
  provider: string;
  identity: string;
  idToken: string;
}

const defaultApiBase = import.meta.env.VITE_TANOD_API_BASE ?? defaultLocalApiBase();
const defaultApiKey = import.meta.env.VITE_TANOD_API_KEY ?? '';
const fallbackOidcProviders = configuredOidcProviders();
const baseViews: Array<{ id: View; label: string }> = [
  { id: 'approvals', label: 'Approvals' },
  { id: 'audit', label: 'Audit' },
  { id: 'policies', label: 'Policies' },
  { id: 'agents', label: 'Agents' },
];

function App() {
  const [apiBase, setApiBase] = useLocalStorage('tanod.console.apiBase', defaultApiBase);
  const [apiKey, setApiKey] = useSessionStorage('tanod.console.apiKey', defaultApiKey);
  const [approver, setApprover] = useLocalStorage('tanod.console.approver', 'operator@example.com');
  const [oidcSession, setOidcSession] = useSessionState();
  const [consoleProviders, setConsoleProviders] = useState<OidcProvider[]>(fallbackOidcProviders);
  const [oauth2Providers, setOAuth2Providers] = useState<OAuth2Provider[]>([]);
  const [me, setMe] = useState<MeResponse | undefined>();
  const [authChecked, setAuthChecked] = useState(false);
  const [authBootstrapComplete, setAuthBootstrapComplete] = useState(false);
  const [activeView, setActiveView] = useState<View>('approvals');
  const [sessionMenuOpen, setSessionMenuOpen] = useState(false);
  const [status, setStatus] = useState<StatusFilter>('pending');
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [policyFile, setPolicyFile] = useState<PolicyFile | undefined>();
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [invitations, setInvitations] = useState<InvitationRecord[]>([]);
  const [inviteText, setInviteText] = useState('');
  const [inviteRole, setInviteRole] = useState<Role>('Viewer');
  const [newUserId, setNewUserId] = useState('');
  const [newUserDisplayName, setNewUserDisplayName] = useState('');
  const [newUserRoles, setNewUserRoles] = useState<Role[]>(['Viewer']);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const approvalIdentity = oidcSession?.identity ?? me?.identity ?? approver;
  const activeBearer = oidcSession?.idToken ?? apiKey;
  const canApprove = Boolean(me?.capabilities.approve);
  const canAdmin = Boolean(me?.capabilities.administer);
  const isLoggedIn = Boolean(me);
  const views = isLoggedIn ? (canAdmin ? [...baseViews, { id: 'admin' as const, label: 'Admin' }] : baseViews) : [{ id: 'login' as const, label: 'Login' }];
  const header = viewHeader(activeView);
  const stats = useMemo(() => ({
    pending: approvals.filter((r) => r.status === 'pending').length,
    approvals: approvals.length,
    audit: auditEvents.length,
    policies: policyFile?.policies.length ?? 0,
    agents: agents.length,
  }), [approvals, auditEvents, policyFile, agents]);

  async function api<T>(path: string, init?: RequestInit): Promise<T> {
    const headers = new Headers(init?.headers);
    headers.set('content-type', 'application/json');
    if (activeBearer.trim()) headers.set('authorization', `Bearer ${activeBearer.trim()}`);
    const response = await fetch(`${apiBase.replace(/\/$/, '')}${path}`, { ...init, headers, credentials: 'include' });
    const text = await response.text();
    const data = text ? JSON.parse(text) : undefined;
    if (!response.ok) throw new Error(data?.error ?? response.statusText);
    return data as T;
  }

  async function loadConsoleConfig() {
    try {
      const response = await fetch(`${apiBase.replace(/\/$/, '')}/v1/console-config`, { credentials: 'include' });
      if (!response.ok) return;
      const data = await response.json() as ConsoleConfig;
      if (data.api_base_url && apiBase === defaultApiBase && shouldUseConfiguredApiBase(data.api_base_url)) setApiBase(data.api_base_url);
      setConsoleProviders((data.oidc_providers ?? []).length > 0 ? data.oidc_providers ?? [] : fallbackOidcProviders);
      setOAuth2Providers(data.oauth2_providers ?? []);
    } catch {
      setConsoleProviders(fallbackOidcProviders);
      setOAuth2Providers([]);
    }
  }

  async function loadMe(): Promise<MeResponse | undefined> {
    try {
      const data = await api<MeResponse>('/v1/me');
      setMe(data);
      if (data.identity) setApprover(data.identity);
      if (activeView === 'admin' && !data.capabilities.administer) setActiveView('approvals');
      if (activeView === 'login') setActiveView('approvals');
      setError('');
      return data;
    } catch (err) {
      setMe(undefined);
      setActiveView('login');
      if (activeBearer.trim()) setError(err instanceof Error ? err.message : 'Could not load current user.');
      return undefined;
    } finally {
      setAuthChecked(true);
    }
  }

  async function acceptPendingInvite() {
    const token = new URLSearchParams(window.location.search).get('invite');
    if (!token || !activeBearer.trim()) return;
    const user = await api<UserRecord>(`/v1/invitations/${encodeURIComponent(token)}/accept`, { method: 'POST', body: '{}' });
    window.history.replaceState({}, document.title, redirectUriForConsole());
    setMessage(`Invitation accepted with roles: ${user.roles.join(', ')}.`);
  }

  async function loadView(nextView = activeView, nextStatus = status) {
    if (nextView === 'login' || nextView === 'profile') return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      if (nextView === 'approvals') {
        const query = nextStatus === 'all' ? '' : `?status=${encodeURIComponent(nextStatus)}`;
        const data = await api<{ approval_requests: ApprovalRequest[] }>(`/v1/approval-requests${query}`);
        setApprovals(data.approval_requests ?? []);
        setMessage(`Loaded ${(data.approval_requests ?? []).length} ${nextStatus} approval request(s).`);
      }
      if (nextView === 'audit') {
        const data = await api<{ audit_events: AuditEvent[] }>('/v1/audit-events?limit=100');
        setAuditEvents(data.audit_events ?? []);
        setMessage(`Loaded ${(data.audit_events ?? []).length} audit event(s).`);
      }
      if (nextView === 'policies') {
        const data = await api<PolicyFile>('/v1/policies');
        setPolicyFile(data);
        setMessage(`Loaded ${data.policies.length} policy rule(s).`);
      }
      if (nextView === 'agents') {
        const data = await api<{ agents: AgentSummary[] }>('/v1/agents');
        setAgents(data.agents ?? []);
        setMessage(`Loaded ${(data.agents ?? []).length} agent(s).`);
      }
      if (nextView === 'admin') {
        if (!canAdmin) throw new Error('Admin role required.');
        await loadAdmin();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Could not load ${nextView}.`);
    } finally {
      setLoading(false);
    }
  }

  async function loadAdmin() {
    const [usersData, invitationsData] = await Promise.all([
      api<{ users: UserRecord[] }>('/v1/users'),
      api<{ invitations: InvitationRecord[] }>('/v1/invitations'),
    ]);
    setUsers(usersData.users ?? []);
    setInvitations(invitationsData.invitations ?? []);
  }

  async function approve(record: ApprovalRequest) {
    if (!canApprove) return;
    setError('');
    try {
      await api(`/v1/approval-requests/${encodeURIComponent(record.approval_id)}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approved_by: approvalIdentity, approved_role: approvalRole(me?.roles) }),
      });
      await loadView('approvals');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Approval failed.');
    }
  }

  async function reject(record: ApprovalRequest) {
    if (!canApprove) return;
    const reason = window.prompt('Reason for rejection?') ?? undefined;
    setError('');
    try {
      await api(`/v1/approval-requests/${encodeURIComponent(record.approval_id)}/reject`, {
        method: 'POST',
        body: JSON.stringify({ rejected_by: approvalIdentity, reason }),
      });
      await loadView('approvals');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rejection failed.');
    }
  }

  async function sendInvites() {
    const emails = inviteText.split(/[\n,;]+/).map((item) => item.trim()).filter(Boolean);
    if (emails.length === 0) return;
    setError('');
    try {
      const data = await api<{ invitations: InvitationRecord[] }>('/v1/invitations', {
        method: 'POST',
        body: JSON.stringify({ invites: emails.map((email) => ({ email, roles: [inviteRole] })) }),
      });
      setInviteText('');
      await loadAdmin();
      setMessage(`Created ${data.invitations.length} invitation(s).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send invitations.');
    }
  }

  async function updateUser(user: UserRecord, patch: Partial<Pick<UserRecord, 'display_name' | 'roles' | 'status'>>) {
    setError('');
    try {
      await api(`/v1/users/${encodeURIComponent(user.user_id)}`, { method: 'PATCH', body: JSON.stringify(patch) });
      await loadAdmin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update user.');
    }
  }

  async function createUser() {
    const identity = newUserId.trim();
    if (!identity) return;
    setError('');
    try {
      await api('/v1/users', {
        method: 'POST',
        body: JSON.stringify({ user_id: identity, display_name: newUserDisplayName.trim() || identity, roles: newUserRoles }),
      });
      setNewUserId('');
      setNewUserDisplayName('');
      setNewUserRoles(['Viewer']);
      await loadAdmin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create user.');
    }
  }

  async function deleteUser(user: UserRecord) {
    if (!window.confirm(`Delete ${user.identity}?`)) return;
    setError('');
    try {
      await api(`/v1/users/${encodeURIComponent(user.user_id)}`, { method: 'DELETE' });
      await loadAdmin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete user.');
    }
  }

  async function savePolicy(policy: PolicyRule) {
    const raw = window.prompt('Edit policy JSON', JSON.stringify(policy, null, 2));
    if (!raw) return;
    try {
      const next = JSON.parse(raw) as PolicyRule;
      await api(`/v1/policies/${encodeURIComponent(policy.id)}`, { method: 'PUT', body: JSON.stringify(next) });
      await loadView('policies');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save policy.');
    }
  }

  async function addPolicy() {
    const raw = window.prompt('New policy JSON', JSON.stringify({ id: 'new-policy', priority: 10, when: {}, then: { decision: 'deny', risk_level: 'L2' } }, null, 2));
    if (!raw) return;
    try {
      const policy = JSON.parse(raw) as PolicyRule;
      await api(`/v1/policies/${encodeURIComponent(policy.id)}`, { method: 'PUT', body: JSON.stringify(policy) });
      await loadView('policies');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add policy.');
    }
  }

  async function deletePolicy(policy: PolicyRule) {
    if (!window.confirm(`Delete policy ${policy.id}?`)) return;
    try {
      await api(`/v1/policies/${encodeURIComponent(policy.id)}`, { method: 'DELETE' });
      await loadView('policies');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete policy.');
    }
  }

  async function login(provider: OidcProvider) {
    setError('');
    try {
      await startOidcLogin(provider);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'OIDC login failed.');
    }
  }

  function loginOAuth2(provider: OAuth2Provider) {
    setApiBase(apiBase);
    const params = new URLSearchParams({ redirect_uri: redirectUriForConsole() });
    window.location.assign(`${apiBase.replace(/\/$/, '')}/v1/oauth2/${encodeURIComponent(provider.id)}/start?${params.toString()}`);
  }

  async function logout() {
    try {
      await fetch(`${apiBase.replace(/\/$/, '')}/v1/oauth2/logout`, { method: 'POST', credentials: 'include' });
    } catch {
      // Local state is still cleared if the API is unavailable.
    }
    sessionStorage.removeItem('tanod.console.oidcSession');
    sessionStorage.removeItem('tanod.console.apiKey');
    setApiKey('');
    setOidcSession(undefined);
    setMe(undefined);
    setActiveView('login');
    setSessionMenuOpen(false);
  }

  function switchView(nextView: View) {
    if (!isLoggedIn && nextView !== 'login') {
      setActiveView('login');
      return;
    }
    setActiveView(nextView);
    void loadView(nextView);
  }

  useEffect(() => {
    completeOidcLogin().then(async (session) => {
      if (session) {
        setOidcSession(session);
        setApprover(session.identity);
        setMessage(`Signed in as ${session.identity}.`);
      }
    }).catch((err) => setError(err instanceof Error ? err.message : 'OIDC login failed.'))
      .finally(() => setAuthBootstrapComplete(true));
  }, []);

  useEffect(() => { void loadConsoleConfig(); }, [apiBase]);
  useEffect(() => {
    if (!authBootstrapComplete) return;
    void (async () => {
      await acceptPendingInvite();
      const currentUser = await loadMe();
      if (currentUser) await loadView(activeView);
    })();
  }, [authBootstrapComplete, oidcSession?.idToken, apiKey, apiBase]);

  if (!authChecked) return <div className="login-shell"><div className="login-panel"><img className="login-logo" src={tanodLogo} alt="tanod logo" /><h1>tanod</h1><p>Checking session...</p></div></div>;

  if (!isLoggedIn || activeView === 'login') {
    return <LoginPage providers={consoleProviders} oauth2Providers={oauth2Providers} error={error} onLogin={login} onOAuth2Login={loginOAuth2} onRetry={() => void loadMe()} />;
  }

  const currentMe = me as MeResponse;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><img className="logo" src={tanodLogo} alt="tanod logo" /><div><strong>tanod</strong><small>{currentMe.roles.join(', ')}</small></div></div>
        <nav>
          {views.map((view) => <button key={view.id} className={view.id === activeView ? 'nav-link active' : 'nav-link'} onClick={() => switchView(view.id)}>{view.label}</button>)}
        </nav>
        <div className="sidebar-note">Policy, approval, signed execution, and audit controls for AI-agent tool calls.</div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div><h1>{header.title}</h1><p>{header.subtitle}</p></div>
          <div className="topbar-actions">
            {activeView === 'approvals' && <label className="status-filter">Status<select value={status} onChange={(e) => { const next = e.target.value as StatusFilter; setStatus(next); void loadView('approvals', next); }}><option value="pending">Pending</option><option value="all">All</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="expired">Expired</option></select></label>}
            <button onClick={() => loadView()} disabled={loading}>{loading ? 'Refreshing...' : 'Refresh'}</button>
            <SessionMenu me={currentMe} open={sessionMenuOpen} onToggle={() => setSessionMenuOpen(!sessionMenuOpen)} onProfile={() => { setSessionMenuOpen(false); switchView('profile'); }} onAdmin={canAdmin ? () => { setSessionMenuOpen(false); switchView('admin'); } : undefined} onSignOut={() => void logout()} />
          </div>
        </header>

        <section className="metrics">
          <Metric value={stats.pending} label="Pending" />
          <Metric value={stats.approvals} label="Approvals" />
          <Metric value={stats.audit} label="Audit events" />
          <Metric value={stats.policies} label="Policies" />
          <Metric value={stats.agents} label="Agents" />
        </section>
        {error && <div className="banner error">{error}</div>}
        {message && !error && <div className="banner ok">{message}</div>}

        {activeView === 'approvals' && <ApprovalsView records={approvals} status={status} canApprove={canApprove} onApprove={approve} onReject={reject} />}
        {activeView === 'audit' && <AuditView events={auditEvents} />}
        {activeView === 'policies' && <PoliciesView policyFile={policyFile} canAdmin={canAdmin} onAdd={addPolicy} onEdit={savePolicy} onDelete={deletePolicy} />}
        {activeView === 'agents' && <AgentsView agents={agents} />}
        {activeView === 'profile' && <ProfileView me={currentMe} oidcSession={oidcSession} />}
        {activeView === 'admin' && canAdmin && <AdminView users={users} invitations={invitations} inviteText={inviteText} inviteRole={inviteRole} newUserId={newUserId} newUserDisplayName={newUserDisplayName} newUserRoles={newUserRoles} onInviteText={setInviteText} onInviteRole={setInviteRole} onNewUserId={setNewUserId} onNewUserDisplayName={setNewUserDisplayName} onNewUserRoles={setNewUserRoles} onCreateUser={createUser} onSendInvites={sendInvites} onUpdateUser={updateUser} onDeleteUser={deleteUser} />}
      </main>
    </div>
  );
}

function viewHeader(view: View): { title: string; subtitle: string } {
  if (view === 'audit') return { title: 'Audit Trail', subtitle: 'Inspect signed event history and request outcomes.' };
  if (view === 'policies') return { title: 'Policies', subtitle: 'Review and manage the active policy file.' };
  if (view === 'agents') return { title: 'Agents', subtitle: 'Summarize known agents from decisions and approval requests.' };
  if (view === 'profile') return { title: 'Profile', subtitle: 'View your Tanod identity and roles.' };
  if (view === 'admin') return { title: 'Admin', subtitle: 'Manage users, roles, and invitations.' };
  return { title: 'Approval Queue', subtitle: 'Review exact tool calls before signed execution.' };
}

function LoginPage(props: { providers: OidcProvider[]; oauth2Providers: OAuth2Provider[]; error: string; onLogin: (provider: OidcProvider) => void; onOAuth2Login: (provider: OAuth2Provider) => void; onRetry: () => void }) {
  const hasConfiguredLogin = props.providers.length > 0 || props.oauth2Providers.length > 0;
  return <div className="login-shell">
    <section className="login-panel">
      <img className="login-logo" src={tanodLogo} alt="tanod logo" />
      <h1>tanod</h1>
      <p>Sign in to continue.</p>
      <div className="login-actions">
        {props.oauth2Providers.map((provider) => <LoginProviderButton key={provider.id} id={provider.id} label={provider.label} onClick={() => props.onOAuth2Login(provider)} />)}
        {props.providers.map((provider) => <LoginProviderButton key={provider.id} id={provider.id} label={provider.label} onClick={() => props.onLogin(provider)} />)}
        {!hasConfiguredLogin && <button className="dev-login" onClick={props.onRetry}>Continue as development admin</button>}
      </div>
      {props.error && <div className="banner error">{props.error}</div>}
    </section>
  </div>;
}

function LoginProviderButton({ id, label, onClick }: { id: string; label: string; onClick: () => void }) {
  return <button className={`provider-login ${id}`} onClick={onClick}>
    {id === 'github' && <GitHubIcon />}
    <span>Login with {label}</span>
  </button>;
}

function GitHubIcon() {
  return <svg className="provider-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
    <path fill="currentColor" d="M8 0C3.58 0 0 3.67 0 8.2c0 3.62 2.29 6.69 5.47 7.78.4.08.55-.18.55-.4 0-.2-.01-.86-.01-1.56-2.01.38-2.53-.5-2.69-.96-.09-.24-.48-.96-.82-1.15-.28-.16-.68-.55-.01-.56.63-.01 1.08.59 1.23.83.72 1.24 1.87.89 2.33.68.07-.53.28-.89.51-1.1-1.78-.21-3.64-.91-3.64-4.04 0-.89.31-1.62.82-2.19-.08-.21-.36-1.04.08-2.16 0 0 .67-.22 2.2.84A7.4 7.4 0 0 1 8 3.91c.68 0 1.36.09 2 .28 1.53-1.06 2.2-.84 2.2-.84.44 1.12.16 1.95.08 2.16.51.57.82 1.3.82 2.19 0 3.14-1.87 3.83-3.65 4.04.29.25.54.75.54 1.52 0 1.1-.01 1.98-.01 2.25 0 .22.15.48.55.4A8.15 8.15 0 0 0 16 8.2C16 3.67 12.42 0 8 0Z" />
  </svg>;
}

function SessionMenu({ me, open, onToggle, onProfile, onAdmin, onSignOut }: { me: MeResponse; open: boolean; onToggle: () => void; onProfile: () => void; onAdmin?: () => void; onSignOut: () => void }) {
  const identity = me.identity ?? 'user';
  return <div className="session-menu">
    <button className="avatar-button" onClick={onToggle} aria-haspopup="menu" aria-expanded={open} title="Account menu">{initials(identity)}</button>
    {open && <div className="session-dropdown" role="menu">
      <div className="session-summary"><strong>{identity}</strong><span>{me.roles.join(', ') || 'No roles'}</span></div>
      <button className="menu-item" onClick={onProfile}>Profile</button>
      {onAdmin && <button className="menu-item" onClick={onAdmin}>Admin</button>}
      <button className="menu-item" onClick={onSignOut}>Sign out</button>
    </div>}
  </div>;
}

function ProfileView({ me, oidcSession }: { me: MeResponse; oidcSession?: OidcSession }) {
  return <section className="cards"><article className="approval-card">
    <h2>{me.identity ?? 'Unknown user'}</h2>
    <div className="meta-grid">
      <Meta label="Username" value={me.identity ?? 'unknown'} />
      <Meta label="Roles" value={me.roles.join(', ') || 'none'} />
      <Meta label="OIDC provider" value={oidcSession?.provider ?? 'none'} />
      <Meta label="External roles" value={me.external_roles?.join(', ') || 'none'} />
      <Meta label="Status" value={me.user?.status ?? 'active'} />
    </div>
  </article></section>;
}

function Metric({ value, label }: { value: number | string; label: string }) {
  return <div><strong>{value}</strong><span>{label}</span></div>;
}

function ApprovalsView({ records, status, canApprove, onApprove, onReject }: { records: ApprovalRequest[]; status: StatusFilter; canApprove: boolean; onApprove: (r: ApprovalRequest) => void; onReject: (r: ApprovalRequest) => void }) {
  return <section className="cards">{records.length === 0 ? <EmptyState status={status} /> : records.map((record) => <ApprovalCard key={record.approval_id} record={record} canApprove={canApprove} onApprove={onApprove} onReject={onReject} />)}</section>;
}

function ApprovalCard({ record, canApprove, onApprove, onReject }: { record: ApprovalRequest; canApprove: boolean; onApprove: (r: ApprovalRequest) => void; onReject: (r: ApprovalRequest) => void }) {
  return <article className="approval-card">
    <div className="card-head"><div><h2>{record.request.tool.name}</h2><p>{record.decision.message}</p></div><div className="badges"><span className={`status ${record.status}`}>{record.status}</span><span className="risk">{record.decision.risk_level}</span></div></div>
    <div className="meta-grid"><Meta label="Approval" value={record.approval_id} /><Meta label="Request" value={record.request_id} /><Meta label="Agent" value={record.request.agent.agent_id} /><Meta label="Actor" value={record.request.actor.user_id} /><Meta label="Requested by" value={record.requested_by} /><Meta label="Approver" value={record.approved_by ?? record.rejected_by ?? 'pending'} /><Meta label="Role" value={record.approved_role ?? 'none'} /><Meta label="Target" value={`${record.request.target?.system ?? 'unknown'} / ${record.request.target?.environment ?? 'unknown'}`} /><Meta label="Policies" value={record.decision.policy_ids.join(', ') || 'manual'} /></div>
    <div className="hash"><span>Argument hash</span><code>{record.argument_hash}</code></div>
    <div className="json-grid"><div><h3>Arguments</h3><pre>{JSON.stringify(record.request.arguments, null, 2)}</pre></div><div><h3>Context</h3><pre>{JSON.stringify(record.request.context ?? {}, null, 2)}</pre></div></div>
    {record.status === 'pending' ? <div className="actions"><button className="approve" disabled={!canApprove} onClick={() => onApprove(record)}>Approve exact action</button><button className="reject" disabled={!canApprove} onClick={() => onReject(record)}>Reject</button></div> : <p className="muted">No actions available for {record.status} requests.</p>}
  </article>;
}

function AuditView({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) return <div className="empty"><h2>No audit events</h2><p>Events appear here after decisions, approval actions, verifications, or executions.</p></div>;
  return <section className="cards">{events.map((event) => <article className="approval-card compact" key={event.event_id}>
    <div className="card-head"><div><h2>{event.event_type}</h2><p>{formatDate(event.timestamp)}</p></div><div className="badges">{event.result && <span className="risk">{event.result}</span>}{event.risk_level && <span className="risk">{event.risk_level}</span>}</div></div>
    <div className="meta-grid"><Meta label="Event" value={event.event_id} /><Meta label="Request" value={event.request_id ?? 'none'} /><Meta label="Actor" value={event.actor_id ?? 'none'} /><Meta label="Agent" value={event.agent_id ?? 'none'} /><Meta label="Tool" value={event.tool_name ?? 'none'} /><Meta label="Decision" value={event.decision ?? 'none'} /><Meta label="Approval" value={event.approval_id ?? 'none'} /><Meta label="Policies" value={event.policy_ids?.join(', ') || 'none'} /></div>
    <div className="hash"><span>Event hash</span><code>{event.event_hash ?? 'missing'}</code></div>
    {event.details && <div><h3>Details</h3><pre>{JSON.stringify(event.details, null, 2)}</pre></div>}
  </article>)}</section>;
}

function PoliciesView({ policyFile, canAdmin, onAdd, onEdit, onDelete }: { policyFile?: PolicyFile; canAdmin: boolean; onAdd: () => void; onEdit: (policy: PolicyRule) => void; onDelete: (policy: PolicyRule) => void }) {
  if (!policyFile) return <div className="empty"><h2>No policies loaded</h2><p>Refresh after the API base is configured.</p></div>;
  return <section className="cards">
    <div className="summary-strip"><Meta label="Version" value={policyFile.version} /><Meta label="Default decision" value={policyFile.default_decision ?? 'unset'} /><Meta label="Default risk" value={policyFile.default_risk_level ?? 'unset'} /></div>
    {canAdmin && <div className="actions"><button onClick={onAdd}>Add policy</button></div>}
    {policyFile.policies.map((policy) => <article className="approval-card compact" key={policy.id}>
      <div className="card-head"><div><h2>{policy.id}</h2><p>{policy.description ?? policy.then.message ?? 'No description.'}</p></div><div className="badges"><span className="risk">{policy.then.decision}</span>{policy.then.risk_level && <span className="risk">{policy.then.risk_level}</span>}</div></div>
      <div className="meta-grid"><Meta label="Priority" value={String(policy.priority ?? 0)} /><Meta label="Approval roles" value={policy.then.approval?.required_roles?.join(', ') || 'none'} /><Meta label="Token TTL" value={policy.then.approval?.token_ttl_seconds ? `${policy.then.approval.token_ttl_seconds}s` : 'none'} /><Meta label="Audit severity" value={policy.then.audit?.severity ?? 'none'} /></div>
      <div className="json-grid policy-json-grid"><div><h3>When</h3><pre>{JSON.stringify(policy.when, null, 2)}</pre></div><div><h3>Then</h3><pre>{JSON.stringify(policy.then, null, 2)}</pre></div></div>
      {canAdmin && <div className="actions"><button className="secondary" onClick={() => onEdit(policy)}>Edit JSON</button><button className="reject" onClick={() => onDelete(policy)}>Delete</button></div>}
    </article>)}
  </section>;
}

function AgentsView({ agents }: { agents: AgentSummary[] }) {
  if (agents.length === 0) return <div className="empty"><h2>No agents seen</h2><p>Agents appear here after decisions or approval requests are recorded.</p></div>;
  return <section className="cards">{agents.map((agent) => <article className="approval-card compact" key={agent.agent_id}>
    <div className="card-head"><div><h2>{agent.agent_id}</h2><p>{agent.agent_type ?? 'agent'} {agent.environment ? `in ${agent.environment}` : ''}</p></div><div className="badges"><span className="risk">{agent.tool_call_count} calls</span><span className="status pending">{agent.pending_approval_count} pending</span></div></div>
    <div className="meta-grid"><Meta label="Last seen" value={agent.last_seen_at ? formatDate(agent.last_seen_at) : 'unknown'} /><Meta label="Approved" value={String(agent.approved_approval_count)} /><Meta label="Rejected" value={String(agent.rejected_approval_count)} /><Meta label="Decisions" value={formatCounts(agent.decisions)} /><Meta label="Tools" value={agent.tools.join(', ') || 'none'} /><Meta label="Actors" value={agent.actors.join(', ') || 'none'} /></div>
  </article>)}</section>;
}

function AdminView(props: { users: UserRecord[]; invitations: InvitationRecord[]; inviteText: string; inviteRole: Role; newUserId: string; newUserDisplayName: string; newUserRoles: Role[]; onInviteText: (value: string) => void; onInviteRole: (value: Role) => void; onNewUserId: (value: string) => void; onNewUserDisplayName: (value: string) => void; onNewUserRoles: (roles: Role[]) => void; onCreateUser: () => void; onSendInvites: () => void; onUpdateUser: (user: UserRecord, patch: Partial<Pick<UserRecord, 'display_name' | 'roles' | 'status'>>) => void; onDeleteUser: (user: UserRecord) => void }) {
  return <section className="cards">
    <article className="approval-card">
      <h2>Create user</h2>
      <div className="admin-invite-row">
        <label>User ID<input value={props.newUserId} onChange={(e) => props.onNewUserId(e.target.value)} placeholder="github:ross or ross@example.com" /></label>
        <label>Display name<input value={props.newUserDisplayName} onChange={(e) => props.onNewUserDisplayName(e.target.value)} placeholder="Ross" /></label>
        <RoleChecks roles={props.newUserRoles} onChange={props.onNewUserRoles} />
      </div>
      <div className="actions"><button onClick={props.onCreateUser}>Create user</button></div>
    </article>
    <article className="approval-card">
      <h2>Invitations</h2>
      <div className="admin-invite-row">
        <label>Email addresses<textarea value={props.inviteText} onChange={(e) => props.onInviteText(e.target.value)} placeholder="one@example.com&#10;two@example.com" /></label>
        <label>Role<select value={props.inviteRole} onChange={(e) => props.onInviteRole(e.target.value as Role)}><option>Viewer</option><option>Approver</option><option>Admin</option></select></label>
      </div>
      <div className="actions"><button onClick={props.onSendInvites}>Send invitations</button></div>
      <div className="table-list">{props.invitations.map((invite) => <div className="table-row" key={invite.invitation_id}><strong>{invite.email}</strong><span>{invite.roles.join(', ')}</span><span>{invite.accepted_at ? 'accepted' : 'pending'}</span><code>{invite.invite_url ?? `/?invite=${invite.token}`}</code></div>)}</div>
    </article>
    <article className="approval-card">
      <h2>Users</h2>
      <div className="table-list">{props.users.map((user) => <div className="table-row" key={user.user_id}>
        <div><strong>{user.user_id}</strong><span>{user.display_name}</span></div>
        <RoleChecks roles={user.roles} onChange={(roles) => props.onUpdateUser(user, { roles })} />
        <select value={user.status} onChange={(e) => props.onUpdateUser(user, { status: e.target.value as UserRecord['status'] })}><option>active</option><option>disabled</option></select>
        <button onClick={() => {
          const displayName = window.prompt('Display name', user.display_name);
          if (displayName) props.onUpdateUser(user, { display_name: displayName });
        }}>Edit</button>
        <button className="reject" onClick={() => props.onDeleteUser(user)}>Delete</button>
      </div>)}</div>
    </article>
  </section>;
}

function RoleChecks({ roles, onChange }: { roles: Role[]; onChange: (roles: Role[]) => void }) {
  return <div className="role-checks">{(['Viewer', 'Approver', 'Admin'] as Role[]).map((role) => <label key={role} className="check-label"><input type="checkbox" checked={roles.includes(role)} onChange={(event) => {
    const next = event.target.checked ? [...roles, role] : roles.filter((item) => item !== role);
    onChange(next.length > 0 ? next : ['Viewer']);
  }} />{role}</label>)}</div>;
}

function Meta({ label, value }: { label: string; value: string }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function EmptyState({ status }: { status: StatusFilter }) { return <div className="empty"><h2>No {status} approval requests</h2><p>Create one with <code>tanod request-approval examples/requests/shell-write-prod.json --by ross@example.com</code>.</p><p>A plain <code>tanod decide</code> only evaluates policy and does not create a persistent console item.</p></div>; }
function formatDate(value: string): string { return new Date(value).toLocaleString(); }
function formatCounts(counts: Record<string, number>): string { return Object.entries(counts).map(([key, value]) => `${key}: ${value}`).join(', ') || 'none'; }
function approvalRole(roles: Role[] | undefined): Role { return roles?.includes('Admin') ? 'Admin' : 'Approver'; }
function initials(identity: string): string {
  const parts = identity.split(/[^a-zA-Z0-9]+/).filter(Boolean);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : identity.slice(0, 2)).toUpperCase();
}

function useLocalStorage(key: string, initial: string): [string, (value: string) => void] { const [value, setValue] = useState(() => localStorage.getItem(key) ?? initial); return [value, (next) => { localStorage.setItem(key, next); setValue(next); }]; }
function useSessionStorage(key: string, initial: string): [string, (value: string) => void] {
  const [value, setValue] = useState(() => {
    localStorage.removeItem(key);
    return sessionStorage.getItem(key) ?? initial;
  });
  return [value, (next) => { sessionStorage.setItem(key, next); setValue(next); }];
}

function useSessionState(): [OidcSession | undefined, (session: OidcSession | undefined) => void] {
  const [session, setSession] = useState<OidcSession | undefined>(() => {
    const raw = sessionStorage.getItem('tanod.console.oidcSession');
    return raw ? JSON.parse(raw) as OidcSession : undefined;
  });
  return [session, (next) => {
    if (next) sessionStorage.setItem('tanod.console.oidcSession', JSON.stringify(next));
    else sessionStorage.removeItem('tanod.console.oidcSession');
    setSession(next);
  }];
}

function configuredOidcProviders(): OidcProvider[] {
  const fromJson = import.meta.env.VITE_TANOD_OIDC_PROVIDERS;
  if (fromJson) return JSON.parse(fromJson) as OidcProvider[];
  return [
    provider('google', 'Google', 'https://accounts.google.com', import.meta.env.VITE_TANOD_GOOGLE_CLIENT_ID),
    provider('microsoft', 'Microsoft', `https://login.microsoftonline.com/${import.meta.env.VITE_TANOD_MICROSOFT_TENANT_ID ?? 'common'}/v2.0`, import.meta.env.VITE_TANOD_MICROSOFT_CLIENT_ID),
    provider('github', 'GitHub', import.meta.env.VITE_TANOD_GITHUB_ISSUER, import.meta.env.VITE_TANOD_GITHUB_CLIENT_ID),
  ].filter((item): item is OidcProvider => Boolean(item));
}

function provider(id: string, label: string, issuer: string | undefined, clientId: string | undefined): OidcProvider | undefined {
  return issuer && clientId ? { id, label, issuer: issuer.replace(/\/$/, ''), clientId, scope: 'openid email profile' } : undefined;
}

function defaultLocalApiBase(): string {
  if (window.location.protocol === 'https:') return window.location.origin;
  return `${window.location.protocol}//${window.location.hostname || '127.0.0.1'}:8787`;
}

function shouldUseConfiguredApiBase(value: string): boolean {
  try {
    const configured = new URL(value);
    const browserHost = window.location.hostname;
    if (isPrivateBrowserHost(browserHost) && configured.hostname !== browserHost) return false;
    return true;
  } catch {
    return false;
  }
}

function isPrivateBrowserHost(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return true;
  const parts = hostname.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

async function startOidcLogin(provider: OidcProvider): Promise<void> {
  const metadata = await oidcMetadata(provider.issuer);
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const redirectUri = redirectUriForConsole();
  sessionStorage.setItem('tanod.console.oidcPending', JSON.stringify({ provider, verifier, state, redirectUri }));
  const params = new URLSearchParams({
    client_id: provider.clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: provider.scope ?? 'openid email profile',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  window.location.assign(`${metadata.authorization_endpoint}?${params.toString()}`);
}

async function completeOidcLogin(): Promise<OidcSession | undefined> {
  const params = new URLSearchParams(window.location.search);
  const oauthError = params.get('oauth_error');
  if (oauthError) {
    const identity = params.get('oauth_identity') ?? 'unknown';
    window.history.replaceState({}, document.title, redirectUriForConsole());
    throw new Error(oauthError === 'user_not_authorized' ? `User ${identity} is not authorized for tanod.` : oauthError);
  }
  const code = params.get('code');
  const state = params.get('state');
  if (!code || !state) return undefined;
  const pendingRaw = sessionStorage.getItem('tanod.console.oidcPending');
  if (!pendingRaw) throw new Error('OIDC login state was not found.');
  const pending = JSON.parse(pendingRaw) as { provider: OidcProvider; verifier: string; state: string; redirectUri: string };
  if (state !== pending.state) throw new Error('OIDC login state mismatch.');
  const metadata = await oidcMetadata(pending.provider.issuer);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: pending.provider.clientId,
    code,
    redirect_uri: pending.redirectUri,
    code_verifier: pending.verifier,
  });
  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const token = await response.json() as { id_token?: string; error_description?: string; error?: string };
  if (!response.ok || !token.id_token) throw new Error(token.error_description ?? token.error ?? 'OIDC token exchange failed.');
  const claims = decodeJwt(token.id_token);
  const identity = oidcIdentity(claims);
  if (!identity) throw new Error('OIDC token did not include an identity claim.');
  sessionStorage.removeItem('tanod.console.oidcPending');
  window.history.replaceState({}, document.title, redirectUriForConsole());
  return { provider: pending.provider.id, identity, idToken: token.id_token };
}

function oidcIdentity(claims: Record<string, unknown>): string {
  const issuer = typeof claims.iss === 'string' ? claims.iss : '';
  const subject = typeof claims.sub === 'string' ? claims.sub : '';
  return issuer && subject ? `${issuer}#${subject}` : subject;
}

async function oidcMetadata(issuer: string): Promise<{ authorization_endpoint: string; token_endpoint: string }> {
  const response = await fetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`Could not load OIDC metadata for ${issuer}.`);
  return await response.json() as { authorization_endpoint: string; token_endpoint: string };
}

function redirectUriForConsole(): string {
  return `${window.location.origin}${window.location.pathname}`;
}

function decodeJwt(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlDecode(payload)));
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

createRoot(document.getElementById('root')!).render(<App />);
