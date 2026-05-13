export function approvalConsoleHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tanod Approval Console</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; padding: 2rem; background: #0f172a; color: #e2e8f0; }
    main { max-width: 1100px; margin: 0 auto; }
    h1 { margin: 0 0 .25rem; }
    .sub { color: #94a3b8; margin-bottom: 1.5rem; }
    .toolbar { display: flex; gap: .75rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
    input, button, textarea { border-radius: .5rem; border: 1px solid #334155; background: #020617; color: #e2e8f0; padding: .6rem .75rem; }
    button { cursor: pointer; background: #1e293b; }
    button.approve { background: #166534; border-color: #22c55e; }
    button.reject { background: #7f1d1d; border-color: #ef4444; }
    button:hover { filter: brightness(1.15); }
    .card { border: 1px solid #334155; border-radius: .75rem; padding: 1rem; margin: 1rem 0; background: #111827; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
    .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .5rem; color: #cbd5e1; }
    .badge { display: inline-block; border-radius: 999px; padding: .2rem .55rem; background: #334155; color: #e2e8f0; font-size: .8rem; }
    pre { overflow: auto; background: #020617; border: 1px solid #1e293b; border-radius: .5rem; padding: .75rem; color: #cbd5e1; }
    .actions { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .75rem; }
    .error { color: #fecaca; }
    .ok { color: #bbf7d0; }
  </style>
</head>
<body>
  <main>
    <h1>Tanod Approval Console</h1>
    <div class="sub">Review exact AI-agent tool calls before signed execution.</div>
    <div class="toolbar">
      <input id="apiKey" type="password" placeholder="API key, if TANOD_API_KEYS is set" size="36" />
      <input id="approver" placeholder="approved/rejected by" value="operator@example.com" size="28" />
      <button onclick="loadApprovals()">Refresh</button>
    </div>
    <div id="status"></div>
    <section id="approvals"></section>
  </main>
<script>
const statusEl = document.getElementById('status');
const approvalsEl = document.getElementById('approvals');
const apiKeyEl = document.getElementById('apiKey');
const approverEl = document.getElementById('approver');

function headers() {
  const h = { 'content-type': 'application/json' };
  if (apiKeyEl.value.trim()) h['authorization'] = 'Bearer ' + apiKeyEl.value.trim();
  return h;
}

async function loadApprovals() {
  statusEl.textContent = 'Loading pending approvals...';
  approvalsEl.innerHTML = '';
  try {
    const res = await fetch('/v1/approval-requests?status=pending', { headers: headers() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    const records = data.approval_requests || [];
    statusEl.innerHTML = '<span class="ok">' + records.length + ' pending approval(s)</span>';
    approvalsEl.innerHTML = records.map(renderApproval).join('') || '<p>No pending approvals.</p>';
  } catch (err) {
    statusEl.innerHTML = '<span class="error">' + escapeHtml(String(err.message || err)) + '</span>';
  }
}

function renderApproval(record) {
  return '<article class="card">'
    + '<h2>' + escapeHtml(record.request.tool.name) + ' <span class="badge">' + escapeHtml(record.decision.risk_level) + '</span></h2>'
    + '<div class="meta">'
    + '<div><b>Approval</b><br>' + escapeHtml(record.approval_id) + '</div>'
    + '<div><b>Request</b><br>' + escapeHtml(record.request_id) + '</div>'
    + '<div><b>Agent</b><br>' + escapeHtml(record.request.agent.agent_id) + '</div>'
    + '<div><b>Actor</b><br>' + escapeHtml(record.request.actor.user_id) + '</div>'
    + '<div><b>Policy</b><br>' + escapeHtml((record.decision.policy_ids || []).join(', ') || 'manual') + '</div>'
    + '<div><b>Argument hash</b><br>' + escapeHtml(record.argument_hash) + '</div>'
    + '</div>'
    + '<h3>Arguments</h3><pre>' + escapeHtml(JSON.stringify(record.request.arguments, null, 2)) + '</pre>'
    + '<h3>Reason</h3><pre>' + escapeHtml(JSON.stringify(record.request.context || {}, null, 2)) + '</pre>'
    + '<div class="actions">'
    + '<button class="approve" onclick="approve(\'' + record.approval_id + '\')">Approve exact action</button>'
    + '<button class="reject" onclick="rejectApproval(\'' + record.approval_id + '\')">Reject</button>'
    + '</div>'
    + '</article>';
}

async function approve(id) {
  const approved_by = approverEl.value.trim();
  if (!approved_by) return alert('Approver is required.');
  const res = await fetch('/v1/approval-requests/' + encodeURIComponent(id) + '/approve', {
    method: 'POST', headers: headers(), body: JSON.stringify({ approved_by })
  });
  const data = await res.json();
  if (!res.ok) return alert(data.error || 'Approval failed');
  await loadApprovals();
}

async function rejectApproval(id) {
  const rejected_by = approverEl.value.trim();
  if (!rejected_by) return alert('Rejector is required.');
  const reason = prompt('Reason for rejection?') || undefined;
  const res = await fetch('/v1/approval-requests/' + encodeURIComponent(id) + '/reject', {
    method: 'POST', headers: headers(), body: JSON.stringify({ rejected_by, reason })
  });
  const data = await res.json();
  if (!res.ok) return alert(data.error || 'Reject failed');
  await loadApprovals();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

loadApprovals();
</script>
</body>
</html>`;
}
