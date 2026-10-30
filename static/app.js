const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const state = { token: localStorage.getItem('sentinel_token'), user: null, incidents: [], events: [], sources: [], indicators: [], filter: 'all' };
const api = async (path, options = {}) => {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  if (typeof options.body === 'string') headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...options, headers });
  const data = response.status === 204 ? null : await response.json().catch(() => ({}));
  if (response.status === 401 && path !== '/api/auth/token') logout();
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
};
const esc = (s = '') => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (value, opts = {}) => value ? new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', ...opts }).format(new Date(value)) : '—';
const ago = value => { const mins = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60000)); return mins < 1 ? 'just now' : mins < 60 ? `${mins}m ago` : mins < 1440 ? `${Math.floor(mins / 60)}h ago` : `${Math.floor(mins / 1440)}d ago`; };
const titleCase = s => String(s || '').replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
const sevClass = s => String(s || 'low').toLowerCase();
const statusPill = s => `<span class="status-pill ${esc(s)}">${esc(titleCase(s))}</span>`;
const severityPill = s => `<span class="sev-pill ${esc(sevClass(s))}">${esc(titleCase(s))}</span>`;

function toast(message, isError = false) {
  const el = document.createElement('div'); el.className = `toast${isError ? ' error' : ''}`; el.textContent = message; $('#toastRegion').append(el); setTimeout(() => el.remove(), 4200);
}
function showModal(id) { $(`#${id}`).classList.remove('hidden'); }
function closeModal(id) { $(`#${id}`).classList.add('hidden'); }
function logout() { state.token = null; localStorage.removeItem('sentinel_token'); $('#appShell').classList.add('hidden'); $('#loginScreen').classList.remove('hidden'); }
function navigate(view) {
  if (['audit','users'].includes(view) && state.user?.role !== 'admin') return toast('Administrator access is required.', true);
  $$('.view').forEach(el => el.classList.add('hidden')); $(`#view-${view}`).classList.remove('hidden');
  $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  const label = { overview: 'Overview', incidents: 'Incidents', events: 'Event stream', indicators: 'Indicators', sources: 'Event sources', users: 'Users', audit: 'Audit log' }[view];
  $('#currentSection').textContent = label; history.replaceState(null, '', `#${view}`);
  if (view === 'incidents') loadIncidents(); if (view === 'events') loadEvents(); if (view === 'indicators') loadIndicators(); if (view === 'sources') loadSources(); if (view === 'audit') loadAudit();
  if (view === 'users') loadUsers();
}
function renderPriority() {
  const list = state.incidents.filter(i => ['open', 'investigating'].includes(i.status)).slice(0, 5);
  $('#priorityList').innerHTML = list.length ? list.map(i => `<div class="priority-row" data-incident="${i.incident_id}"><span class="severity-mark ${sevClass(i.severity)}"></span><span><div class="priority-title">${esc(i.title)}</div><div class="priority-sub">${esc(i.incident_id.slice(0, 8))} · ${esc(i.event_count)} correlated event${i.event_count === 1 ? '' : 's'}</div></span><span class="priority-right"><div class="priority-time">${esc(ago(i.updated_at))}</div><div class="priority-count">${statusPill(i.status)}</div></span></div>`).join('') : '<div class="empty-state">No active incidents yet. Ingest events sharing an indicator to create one.</div>';
  $$('.priority-row').forEach(row => row.addEventListener('click', () => openIncident(row.dataset.incident)));
}
function renderSeverity(items) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }; items.forEach(i => counts[i.severity] = (counts[i.severity] || 0) + 1);
  const total = Object.values(counts).reduce((a, b) => a + b, 0); $('#donutTotal').textContent = total;
  $('#sevCritical').textContent = counts.critical; $('#sevHigh').textContent = counts.high; $('#sevMedium').textContent = counts.medium; $('#sevLow').textContent = counts.low;
  const colors = { critical: '#fb7185', high: '#f0a15c', medium: '#e8c963', low: '#74a5f6' }; let start = 0;
  const slices = Object.entries(counts).map(([key, value]) => { const end = start + (total ? value / total * 360 : 0); const slice = `${colors[key]} ${start}deg ${end}deg`; start = end; return slice; });
  $('#severityDonut').style.background = `conic-gradient(${slices.join(',')})`;
}
function renderIndicators(items) {
  const glyph = v => v === 'ip' ? 'IP' : v === 'domain' ? 'D' : 'H'; const kind = v => v === 'domain' ? 'domain' : 'hash';
  $('#topIndicators').innerHTML = items.length ? items.map(i => `<div class="indicator-row"><span class="indicator-type ${kind(i.indicator_type)}">${glyph(i.indicator_type)}</span><span><div class="indicator-value">${esc(i.normalized_value)}</div><div class="indicator-meta">${esc(titleCase(i.indicator_type))}</div></span><span class="indicator-count">${i.event_count}×</span></div>`).join('') : '<div class="empty-state">Indicators will appear after events are ingested.</div>';
  $('#indicatorCards').innerHTML = items.length ? items.map(i => `<article class="panel indicator-card"><span class="indicator-type ${kind(i.indicator_type)}">${glyph(i.indicator_type)}</span><div class="indicator-value">${esc(i.normalized_value)}</div><div class="indicator-meta"><span>${esc(titleCase(i.indicator_type))}</span><span>${i.event_count} event${i.event_count === 1 ? '' : 's'}</span></div></article>`).join('') : '<div class="panel empty-state">No indicators extracted yet.</div>';
}
function renderFeed(events) {
  $('#recentFeed').innerHTML = events.length ? events.slice(0, 5).map(e => `<div class="activity-item"><span class="activity-icon">⌁</span><span class="activity-main"><div class="activity-title"><b>${esc(e.source_name)}</b> · ${esc(e.summary)}</div><div class="activity-meta">${severityPill(e.severity)}</div></span><span class="activity-time">${esc(ago(e.occurred_at))}</span></div>`).join('') : '<div class="empty-state">No events ingested yet.</div>';
}
async function loadOverview() {
  try {
    const [dashboard, incidents, events] = await Promise.all([api('/api/dashboard'), api('/api/incidents?limit=100'), api('/api/events?limit=50')]);
    state.incidents = incidents; state.events = events;
    $('#metricEvents').textContent = dashboard.events.toLocaleString(); $('#metricIncidents').textContent = dashboard.active_incidents.toLocaleString(); $('#metricIndicators').textContent = dashboard.indicators.toLocaleString(); $('#metricSources').textContent = dashboard.sources.toLocaleString();
    $('#incidentNavCount').textContent = dashboard.active_incidents; renderPriority(); renderSeverity(incidents.filter(i => ['open', 'investigating'].includes(i.status))); renderIndicators(dashboard.top_indicators || []); renderFeed(events);
  } catch (e) { toast(e.message, true); }
}
function renderIncidentTable() {
  const query = ($('#incidentSearch')?.value || '').toLowerCase();
  const all = state.incidents.filter(i => (state.filter === 'all' || i.status === state.filter) && `${i.title} ${i.incident_id} ${i.status}`.toLowerCase().includes(query));
  $('#filterAllCount').textContent = state.incidents.length; $('#incidentTotalLabel').textContent = `${all.length} incident${all.length === 1 ? '' : 's'}`;
  $('#incidentsTable').innerHTML = all.length ? all.map(i => `<tr data-incident="${i.incident_id}"><td><div class="incident-name">${esc(i.title)}</div><div class="row-sub">INC-${esc(i.incident_id.slice(0, 8).toUpperCase())}</div></td><td>${severityPill(i.severity)}</td><td>${statusPill(i.status)}</td><td><span class="table-number">${i.event_count}</span></td><td>${esc(i.owner || 'Unassigned')}</td><td>${esc(fmt(i.updated_at))}</td><td>···</td></tr>`).join('') : '<tr><td colspan="7" class="empty-state">No incidents match this view.</td></tr>';
  $$('[data-incident]', $('#incidentsTable')).forEach(row => row.addEventListener('click', () => openIncident(row.dataset.incident)));
}
async function loadIncidents() { try { state.incidents = await api('/api/incidents?limit=250'); renderIncidentTable(); } catch (e) { toast(e.message, true); } }
function eventRows(events) {
  $('#eventsTable').innerHTML = events.length ? events.map(e => `<tr><td><div class="incident-name">${esc(e.summary)}</div><div class="row-sub">EVT-${esc(e.event_id.slice(0, 8).toUpperCase())}</div></td><td>${esc(e.source_name)}</td><td>${severityPill(e.severity)}</td><td>${(e.indicators || []).length ? e.indicators.map(v => `<span class="indicator-chip">${esc(v.value)}</span>`).join(' ') : '<span class="row-sub">None extracted</span>'}</td><td>${esc(fmt(e.occurred_at))}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-state">No events found.</td></tr>';
}
async function loadEvents() { try { state.events = await api('/api/events?limit=200'); eventRows(state.events); } catch (e) { toast(e.message, true); } }
async function loadIndicators() { try { const d = await api('/api/dashboard'); renderIndicators(d.top_indicators || []); } catch (e) { toast(e.message, true); } }
async function loadSources() {
  try { state.sources = await api('/api/sources');
    $('#sourcesGrid').innerHTML = state.sources.length ? state.sources.map(s => `<article class="panel source-card"><span class="source-glyph">◈</span><span class="source-info"><b>${esc(s.name)}</b><small>${esc(s.description || 'Connected telemetry source')}</small></span><span class="source-type">${esc(s.source_type)}</span><span class="source-enabled" title="${s.enabled ? 'Enabled' : 'Disabled'}"></span></article>`).join('') : '<div class="panel empty-state">No event sources configured.</div>';
    $('#eventSource').innerHTML = state.sources.filter(s => s.enabled).map(s => `<option value="${s.source_id}">${esc(s.name)} · ${esc(s.source_type)}</option>`).join('');
  } catch (e) { toast(e.message, true); }
}
async function loadAudit() {
  try { const logs = await api('/api/audit'); $('#auditTable').innerHTML = logs.length ? logs.map(a => `<tr><td><span class="incident-name">${esc(a.action)}</span></td><td>${esc(a.actor || 'System')}</td><td>${esc(a.entity_type)} · ${esc(a.entity_id?.slice(0, 8) || '')}</td><td>${esc(JSON.stringify(a.details))}</td><td>${esc(fmt(a.created_at))}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-state">No actions recorded yet.</td></tr>'; } catch (e) { toast(e.message, true); }
}
async function loadUsers() {
  try { const users = await api('/api/users'); $('#usersTable').innerHTML = users.map(u => `<tr><td><span class="incident-name">${esc(u.email)}</span></td><td>${esc(titleCase(u.role))}</td><td>${esc(fmt(u.created_at))}</td></tr>`).join('') || '<tr><td colspan="3" class="empty-state">No user accounts.</td></tr>'; } catch (e) { toast(e.message, true); }
}
async function openIncident(id) {
  try {
    const i = await api(`/api/incidents/${id}`);
    const events = i.events || [];
    $('#incidentDetail').innerHTML = `<div class="modal-head"><div><p class="eyebrow">INCIDENT · ${esc(id.slice(0, 8).toUpperCase())}</p><h2 class="detail-title">${esc(i.title)}</h2><p class="detail-sub">Created ${esc(fmt(i.created_at))} · Assigned to ${esc(i.owner || 'Unassigned')}</p></div><button class="close-button" data-close="incidentModal">×</button></div><div class="detail-head-row"><div class="detail-fields">${severityPill(i.severity)} ${statusPill(i.status)} <span class="indicator-chip">${events.length} correlated events</span></div><select class="status-select" id="incidentStatusSelect">${['open','investigating','resolved','false_positive'].map(s => `<option value="${s}" ${i.status === s ? 'selected' : ''}>${esc(titleCase(s))}</option>`).join('')}</select></div><div class="detail-section"><h3>Correlation evidence & timeline</h3>${events.length ? events.map(e => `<article class="detail-event"><div class="detail-event-head"><span class="detail-event-summary">${esc(e.summary)}</span>${severityPill(e.severity)}</div><div class="detail-event-meta">${esc(e.source_name)} · ${esc(fmt(e.occurred_at))}</div><div class="detail-match">↳ ${esc(e.match_reason)}</div><div class="detail-indicators">${(e.indicators || []).map(v => `<span class="indicator-chip">${esc(v.type)} · ${esc(v.value)}</span>`).join('')}</div></article>`).join('') : '<div class="empty-state">No linked events.</div>'}</div>`;
    showModal('incidentModal'); $('[data-close="incidentModal"]').addEventListener('click', () => closeModal('incidentModal'));
    $('#incidentStatusSelect').addEventListener('change', async ev => { try { await api(`/api/incidents/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: ev.target.value }) }); toast('Incident status updated and audit logged.'); closeModal('incidentModal'); await loadOverview(); if (!$(`#view-incidents`).classList.contains('hidden')) await loadIncidents(); } catch (e) { toast(e.message, true); } });
  } catch (e) { toast(e.message, true); }
}

async function login(event) {
  event.preventDefault(); $('#loginError').textContent = '';
  const form = new FormData(event.currentTarget); const body = new URLSearchParams(form);
  try { const result = await api('/api/auth/token', { method: 'POST', body }); state.token = result.access_token; localStorage.setItem('sentinel_token', state.token); await startApp(); }
  catch (e) { $('#loginError').textContent = e.message; }
}
async function startApp() {
  try {
    state.user = await api('/api/auth/me'); $('#loginScreen').classList.add('hidden'); $('#appShell').classList.remove('hidden');
    $('#profileEmail').textContent = state.user.email; $('#profileRole').textContent = titleCase(state.user.role); $('#avatar').textContent = state.user.email.split('@')[0].slice(0, 2).toUpperCase();
    $$('.admin-only').forEach(el => el.classList.toggle('hidden', state.user.role !== 'admin'));
    const dateLabel = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).format(new Date()).toUpperCase();
    $('#todayLabel').textContent = dateLabel; $('#overviewDate').textContent = dateLabel;
    await Promise.all([loadSources(), loadOverview()]);
    const initial = location.hash.replace('#', ''); navigate(['overview','incidents','events','indicators','sources','users','audit'].includes(initial) ? initial : 'overview');
  } catch (e) { logout(); $('#loginError').textContent = e.message; }
}

$('#loginForm').addEventListener('submit', login);
$$('.nav-item').forEach(el => el.addEventListener('click', () => navigate(el.dataset.view)));
$$('[data-goto]').forEach(el => el.addEventListener('click', () => navigate(el.dataset.goto)));
$$('[data-action="new-event"]').forEach(el => el.addEventListener('click', () => { loadSources(); showModal('eventModal'); }));
$('#newEventButton').addEventListener('click', async () => { await loadSources(); showModal('eventModal'); });
$('#addSourceButton').addEventListener('click', () => showModal('sourceModal'));
$('#addUserButton').addEventListener('click', () => showModal('userModal'));
$$('[data-close]').forEach(el => el.addEventListener('click', () => closeModal(el.dataset.close)));
$$('.modal-backdrop').forEach(el => el.addEventListener('click', e => { if (e.target === el) closeModal(el.id); }));
$('#refreshButton').addEventListener('click', async () => { await loadOverview(); const active = $('.nav-item.active')?.dataset.view; if (active === 'incidents') await loadIncidents(); if (active === 'events') await loadEvents(); toast('Workspace refreshed.'); });
$('#incidentSearch').addEventListener('input', renderIncidentTable);
$('#eventSearch').addEventListener('input', e => { const q = e.target.value.toLowerCase(); eventRows(state.events.filter(x => `${x.summary} ${x.source_name} ${JSON.stringify(x.indicators)}`.toLowerCase().includes(q))); });
$$('.filter-tab').forEach(el => el.addEventListener('click', () => { state.filter = el.dataset.filter; $$('.filter-tab').forEach(t => t.classList.toggle('active', t === el)); renderIncidentTable(); }));
$('#eventForm').addEventListener('submit', async e => {
  e.preventDefault(); const f = new FormData(e.currentTarget);
  try {
    const payload = JSON.parse(f.get('payload') || '{}'); const occurred = new Date(f.get('occurred_at')).toISOString();
    const result = await api('/api/events', { method: 'POST', body: JSON.stringify({ source_id: f.get('source_id'), occurred_at: occurred, severity: f.get('severity'), summary: f.get('summary'), payload }) });
    closeModal('eventModal'); e.currentTarget.reset(); toast(result.incident_id ? `Event correlated into incident ${result.incident_id.slice(0, 8)}.` : `Event ingested with ${result.indicators.length} indicator(s).`); await loadOverview();
  } catch (err) { toast(err instanceof SyntaxError ? 'Raw payload must be valid JSON.' : err.message, true); }
});
$('#sourceForm').addEventListener('submit', async e => {
  e.preventDefault(); const f = new FormData(e.currentTarget);
  try { await api('/api/sources', { method: 'POST', body: JSON.stringify({ name: f.get('name'), source_type: f.get('source_type'), description: f.get('description') || null }) }); closeModal('sourceModal'); e.currentTarget.reset(); toast('Event source added.'); await loadSources(); await loadOverview(); if (!$('#view-sources').classList.contains('hidden')) await loadSources(); }
  catch (err) { toast(err.message, true); }
});
$('#userForm').addEventListener('submit', async e => {
  e.preventDefault(); const f = new FormData(e.currentTarget);
  try { await api('/api/users', { method: 'POST', body: JSON.stringify({ email: f.get('email'), role: f.get('role'), password: f.get('password') }) }); closeModal('userModal'); e.currentTarget.reset(); toast('Workspace user created.'); await loadUsers(); }
  catch (err) { toast(err.message, true); }
});
$('#profileButton').addEventListener('click', logout);
$('#eventForm').elements.occurred_at.value = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
if (state.token) startApp();
