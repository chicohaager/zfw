// zfw module frontend — single-page UI for the ZFW host firewall plus the
// security dashboard. The daemon binds 127.0.0.1 and registers a gateway
// route, so the API is reachable same-origin under /v2/zfw — no CORS.

const API_BASE = (location.pathname.startsWith('/modules/') ||
                  location.pathname.startsWith('/v2/zfw'))
  ? '/v2/zfw/api'
  : './api';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function setStatus(msg, kind = '') {
  const el = $('#status');
  el.textContent = msg;
  el.className = kind;
  if (msg) setTimeout(() => {
    if (el.textContent === msg) { el.textContent = ''; el.className = ''; }
  }, 4500);
}

async function api(path, opts = {}) {
  // The ZimaOS gateway does not attach the session token to module calls,
  // so the daemon's auth middleware needs it sent explicitly.
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const tok = localStorage.getItem('access_token');
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  const r = await fetch(API_BASE + path, { ...opts, headers });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

/* ---------- tabs ---------- */
$$('.tab-btn').forEach(btn => btn.addEventListener('click', () => {
  $$('.tab-btn').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
  $$('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
  $('#tab-' + btn.dataset.tab).classList.add('active');
}));

/* ---------- firewall ---------- */
function fwItem(label, val, kind) {
  let right;
  if (typeof val === 'boolean') {
    let cls = 'dot-off', sym = '✗';
    if (val) { cls = kind === 'warn' ? 'dot-warn' : 'dot-ok'; sym = kind === 'warn' ? '!' : '✓'; }
    right = `<span class="dot ${cls}">${sym}</span>`;
  } else {
    right = `<span class="num">${esc(val)}</span>`;
  }
  return `<div class="sg-item"><span class="sg-label">${esc(label)}</span>${right}</div>`;
}

async function loadFirewall() {
  const d = await api('/status');
  $('#app-version').textContent = 'v' + (d.version || '?');
  const fw = d.firewall || {};
  const on = !!(fw.active && fw.hooked);
  const sfw = $('#stat-fw');
  sfw.textContent = on ? 'active' : 'off';
  sfw.className = 'stat-num ' + (on ? 'ok' : 'crit');
  $('#fw-status').innerHTML =
    fwItem('Firewall active', on) +
    fwItem('IPv6 protection', !!fw.ipv6_active) +
    fwItem('Boot-persistent', !!fw.service_enabled) +
    fwItem('INPUT rules', fw.input_rules || 0) +
    fwItem('DOCKER-USER DROPs', fw.docker_drops || 0) +
    fwItem('Dead-man armed', !!fw.deadman, 'warn');
}

async function doFw(path, body, msg) {
  setStatus(msg);
  $$('#tab-firewall .action-row button').forEach(b => b.disabled = true);
  try {
    const d = await api(path, { method: 'POST', body: JSON.stringify(body || {}) });
    const out = $('#fw-output');
    out.hidden = false;
    out.textContent = String(d.output || d.status || '').trim() || '(no output)';
    setStatus(d.status || 'OK', 'ok');
    await loadFirewall();
    await loadExposure();
    await loadAudit();
  } catch (e) {
    setStatus('Error: ' + e.message, 'err');
  } finally {
    $$('#tab-firewall .action-row button').forEach(b => b.disabled = false);
  }
}

$('#btn-apply-safe').addEventListener('click', () => doFw('/apply', { safe: true }, 'Safe-Apply running…'));
$('#btn-apply').addEventListener('click', () => doFw('/apply', { safe: false }, 'Apply running…'));
$('#btn-commit').addEventListener('click', () => doFw('/commit', {}, 'Confirming…'));
$('#btn-revert').addEventListener('click', () => {
  if (!confirm('Really remove the firewall completely? The host will be unfiltered afterwards.')) return;
  doFw('/revert', {}, 'Removing firewall…');
});

/* ---------- rules ---------- */
let ruleSet = null;
let rulesDirty = false;

async function loadRules() {
  ruleSet = await api('/rules');
  if (!Array.isArray(ruleSet.rules)) ruleSet.rules = [];
  rulesDirty = false;
  renderRules();
}

function markDirty() { rulesDirty = true; renderRules(); }

function ruleIndex(id) { return ruleSet.rules.findIndex(r => r.id === id); }

function renderRules() {
  if (!ruleSet) return;
  const dp = ruleSet.default_policy || 'deny';
  const n = ruleSet.rules.length;
  const rows = ruleSet.rules.map((r, i) => {
    const actCls = r.action === 'allow' ? 'act-allow' : 'act-deny';
    const actLbl = r.action === 'allow' ? 'Allow' : 'Deny';
    const src = r.source && r.source.type !== 'any' ? esc(r.source.value) : 'Any';
    let ports = 'All';
    if (r.ports && r.ports.type === 'list') ports = esc((r.ports.list || []).join(', '));
    else if (r.ports && r.ports.type === 'range') ports = esc(r.ports.from + '–' + r.ports.to);
    const zone = { auto: 'Auto', host: 'Host', docker: 'Docker' }[r.zone] || esc(r.zone);
    const noteBadge = r.notes
      ? ` <span class="note-pill" title="${esc(r.notes)}">note</span>`
      : '';
    return `<tr class="${r.enabled ? '' : 'rule-off'}" data-id="${esc(r.id)}">
      <td class="mono">${i + 1}</td>
      <td>${esc(r.name)}${noteBadge}</td>
      <td><span class="actbadge ${actCls}">${actLbl}</span></td>
      <td class="mono">${src}</td>
      <td class="mono">${ports} <span class="proto">${esc(r.protocol)}</span></td>
      <td>${zone}</td>
      <td><label class="switch"><input type="checkbox" ${r.enabled ? 'checked' : ''} data-act="toggle"><span></span></label></td>
      <td class="rule-ops">
        <button data-act="up" ${i === 0 ? 'disabled' : ''} title="up">▲</button>
        <button data-act="down" ${i === n - 1 ? 'disabled' : ''} title="down">▼</button>
      </td>
      <td><button data-act="edit" class="btn-secondary">Edit</button></td>
      <td><button data-act="del" class="btn-danger" title="delete">×</button></td>
    </tr>`;
  }).join('');
  $('#rules-panel').innerHTML = `
    <div class="card defpol">
      <span class="defpol-lbl">Default action for unmatched LAN traffic:</span>
      <label><input type="radio" name="defpol" value="deny" ${dp === 'deny' ? 'checked' : ''}> Deny <small>(allowlist)</small></label>
      <label><input type="radio" name="defpol" value="allow" ${dp === 'allow' ? 'checked' : ''}> Allow <small>(blocklist)</small></label>
    </div>
    <div class="action-row">
      <button id="btn-new-rule" class="btn-primary">+ New rule</button>
      <button id="btn-templates" class="btn-secondary" title="Pick from a catalog of pre-built rules (block VNC, block NFS, allow common services)">Templates</button>
      <button id="btn-recommended-defaults" class="btn-secondary" title="Replace all rules with the recommended starter set (auto-detected LAN, deny default, 5 baseline allow rules)">Recommended defaults</button>
      <button id="btn-save-rules" class="btn-secondary${rulesDirty ? ' dirty' : ''}">Save rules</button>
      <span class="save-hint"${rulesDirty ? '' : ' hidden'}>unsaved changes — save, then Safe-Apply on the Firewall tab</span>
    </div>
    <table class="tbl rules-tbl"><thead><tr>
      <th>#</th><th>Name</th><th>Action</th><th>Source</th><th>Ports</th><th>Zone</th>
      <th>Enabled</th><th>Order</th><th></th><th></th>
    </tr></thead><tbody>${rows || '<tr><td colspan="10" class="loading">No rules yet — use “+ New rule”.</td></tr>'}</tbody></table>`;
  wireRules();
}

function wireRules() {
  $$('input[name="defpol"]').forEach(rb => rb.addEventListener('change', () => {
    ruleSet.default_policy = rb.value;
    markDirty();
  }));
  $('#btn-new-rule').addEventListener('click', () => openRuleEditor(null));
  $('#btn-templates').addEventListener('click', openTemplatesPicker);
  $('#btn-recommended-defaults').addEventListener('click', applyRecommendedDefaults);
  $('#btn-save-rules').addEventListener('click', saveRules);
  $$('#rules-panel tbody tr[data-id]').forEach(tr => {
    const id = tr.dataset.id;
    tr.querySelectorAll('[data-act]').forEach(el => {
      const evt = el.dataset.act === 'toggle' ? 'change' : 'click';
      el.addEventListener(evt, () => ruleAction(id, el.dataset.act));
    });
  });
}

function ruleAction(id, act) {
  const i = ruleIndex(id);
  if (i < 0) return;
  const rs = ruleSet.rules;
  if (act === 'toggle') {
    rs[i].enabled = !rs[i].enabled;
    markDirty();
  } else if (act === 'del') {
    if (!confirm(`Delete rule “${rs[i].name}”?`)) return;
    rs.splice(i, 1);
    markDirty();
  } else if (act === 'up' && i > 0) {
    [rs[i - 1], rs[i]] = [rs[i], rs[i - 1]];
    markDirty();
  } else if (act === 'down' && i < rs.length - 1) {
    [rs[i + 1], rs[i]] = [rs[i], rs[i + 1]];
    markDirty();
  } else if (act === 'edit') {
    openRuleEditor(rs[i]);
  }
}

// openTemplatesPicker fetches the curated template catalog and renders
// it in a modal. Each card shows the template's name, category,
// description and rule count plus an "Add" button. Clicking "Add"
// appends the template's rules to the local rule set (with fresh
// order numbers); the user still has to click Save rules + Safe-Apply.
async function openTemplatesPicker() {
  const m = $('#templates-modal');
  const list = $('#tmpl-list');
  list.innerHTML = '<div class="loading">Loading templates&hellip;</div>';
  m.hidden = false;
  let templates;
  try {
    templates = await api('/rules/templates');
  } catch (e) {
    list.innerHTML = `<p class="rm-error">Failed to load templates: ${e.message}</p>`;
    return;
  }
  list.innerHTML = templates.map((t, i) => `
    <div class="tmpl-card" data-idx="${i}">
      <div class="tmpl-head">${t.name}<span class="tmpl-cat ${t.category}">${t.category}</span></div>
      <button class="btn-primary tmpl-add" data-idx="${i}">Add</button>
      <div class="tmpl-desc">${t.description}</div>
      <div class="tmpl-meta">${t.rules.length} rule${t.rules.length === 1 ? '' : 's'}</div>
    </div>`).join('');
  $$('#tmpl-list .tmpl-add').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = templates[parseInt(btn.dataset.idx, 10)];
      addTemplate(t);
      m.hidden = true;
    });
  });
  $('#tmpl-close').onclick = () => { m.hidden = true; };
  // Backdrop click closes the modal — same pattern as the rule editor.
  m.onclick = (ev) => { if (ev.target === m) m.hidden = true; };
}

// addTemplate appends a template's rules to the local rule set with
// fresh order numbers spaced 10 apart above the current max. IDs come
// pre-set from the server so two clicks on the same template produce
// independent rules in the table.
function addTemplate(t) {
  if (!ruleSet || !Array.isArray(ruleSet.rules)) ruleSet.rules = [];
  let maxOrder = 0;
  for (const r of ruleSet.rules) if ((r.order || 0) > maxOrder) maxOrder = r.order;
  t.rules.forEach((r, i) => {
    ruleSet.rules.push({ ...r, order: maxOrder + 10 * (i + 1) });
  });
  setStatus(`Added template "${t.name}" (${t.rules.length} rule${t.rules.length === 1 ? '' : 's'}). Review, then click Save rules.`, 'ok');
  markDirty();
}

// applyRecommendedDefaults replaces the current rules with the server's
// recommended starter set (auto-detected LAN, deny-default, 5 allow-rules
// for the services a ZimaOS host typically must keep reachable). Confirms
// before overwriting existing rules; the user still has to click Safe-Apply
// on the Firewall tab for the rules to take effect.
async function applyRecommendedDefaults() {
  if (ruleSet && Array.isArray(ruleSet.rules) && ruleSet.rules.length > 0) {
    if (!confirm('Replace all current rules with the recommended starter set?\n\n' +
                 '5 baseline rules will be installed (ZimaOS Web UI, SSH, Samba TCP, Samba UDP, mDNS).\n' +
                 'Default policy will become deny.')) return;
  }
  setStatus('Applying recommended defaults…');
  try {
    await api('/rules/defaults', { method: 'POST' });
    setStatus('Defaults installed — review here, then Safe-Apply on the Firewall tab.', 'ok');
    await loadRules();
  } catch (e) {
    setStatus('Error: ' + e.message, 'err');
  }
}

async function saveRules() {
  ruleSet.rules.forEach((r, i) => { r.order = (i + 1) * 10; });
  setStatus('Saving rules…');
  try {
    await api('/rules', { method: 'POST', body: JSON.stringify(ruleSet) });
    setStatus('Rules saved — now Safe-Apply on the Firewall tab', 'ok');
    await loadRules();
  } catch (e) {
    setStatus('Error: ' + e.message, 'err');
  }
}

/* ---------- rule editor modal ---------- */
let editingRuleId = null;

function openRuleEditor(rule) {
  const isEdit = !!(rule && rule.id);
  editingRuleId = isEdit ? rule.id : null;
  $('#rm-title').textContent = isEdit ? 'Edit rule' : 'New rule';
  const r = rule || {
    name: '', action: 'allow',
    source: { type: 'range', value: (ruleSet && ruleSet.lan) || '' },
    ports: { type: 'list', list: [] },
    protocol: 'tcp', zone: 'auto', enabled: true,
  };
  $('#rm-name').value = r.name || '';
  $('#rm-action').value = r.action || 'allow';
  $('#rm-srctype').value = (r.source && r.source.type) || 'any';
  $('#rm-srcval').value = (r.source && r.source.value) || '';
  $('#rm-porttype').value = (r.ports && r.ports.type) || 'list';
  $('#rm-portval').value = ((r.ports && r.ports.list) || []).join(', ');
  $('#rm-portfrom').value = (r.ports && r.ports.from) || '';
  $('#rm-portto').value = (r.ports && r.ports.to) || '';
  $('#rm-proto').value = r.protocol || 'tcp';
  $('#rm-zone').value = r.zone || 'auto';
  $('#rm-enabled').checked = r.enabled !== false;
  $('#rm-notes').value = r.notes || '';
  $('#rm-error').hidden = true;
  updateModalFields();
  $('#rule-modal').hidden = false;
  $('#rm-name').focus();
}

// openRuleEditorForPort prefills the editor from an exposed port (Exposure tab).
function openRuleEditorForPort(port) {
  openRuleEditor({
    id: '', name: 'Port ' + port, action: 'allow',
    source: { type: 'any', value: '' },
    ports: { type: 'list', list: [port] },
    protocol: 'tcp', zone: 'auto', enabled: true,
  });
}

function updateModalFields() {
  const st = $('#rm-srctype').value;
  const isGeo = st === 'country';
  const pt = $('#rm-porttype').value;
  $('#rm-srcval-fld').hidden = st === 'any';
  $('#rm-portval-fld').hidden = pt !== 'list';
  $('#rm-portrange-fld').hidden = pt !== 'range';
  $('#rm-geo-hint').hidden = !isGeo;
  $('#rm-srcval-label').textContent = isGeo ? 'Country codes (ISO, comma-separated)' : 'Source address';
  $('#rm-srcval').placeholder = isGeo ? 'DE, RU, CN' : '192.168.1.0/24';
}

function closeRuleEditor() { $('#rule-modal').hidden = true; }

function modalError(msg) {
  const e = $('#rm-error');
  e.textContent = msg;
  e.hidden = false;
}

function isIP(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => +o <= 255);
}
function isCIDR(s) {
  const m = /^(.+)\/(\d{1,2})$/.exec(s);
  return !!m && isIP(m[1]) && +m[2] <= 32;
}

function saveRuleFromEditor() {
  const name = $('#rm-name').value.trim();
  if (!name) return modalError('Name is required.');
  const srctype = $('#rm-srctype').value;
  let srcval = $('#rm-srcval').value.trim();
  if (srctype === 'ip' && !isIP(srcval)) return modalError('Source IP is invalid.');
  if (srctype === 'range' && !isCIDR(srcval)) return modalError('Source range must be a CIDR (e.g. 192.168.1.0/24).');
  if (srctype === 'country') {
    const codes = srcval.split(/[\s,]+/).filter(Boolean);
    if (!codes.length) return modalError('Enter at least one country code.');
    if (codes.some(c => !/^[A-Za-z]{2}$/.test(c))) {
      return modalError('Country code = 2 letters (ISO-3166, e.g. DE).');
    }
    srcval = codes.map(c => c.toUpperCase()).join(',');
  }
  const porttype = $('#rm-porttype').value;
  let list = [];
  let portFrom = 0, portTo = 0;
  if (porttype === 'list') {
    list = $('#rm-portval').value.split(/[\s,]+/).filter(Boolean).map(Number);
    if (!list.length) return modalError('Enter at least one port.');
    if (list.some(p => !Number.isInteger(p) || p < 1 || p > 65535)) {
      return modalError('Invalid port — allowed range is 1–65535.');
    }
  } else if (porttype === 'range') {
    portFrom = Number($('#rm-portfrom').value);
    portTo   = Number($('#rm-portto').value);
    if (!Number.isInteger(portFrom) || portFrom < 1 || portFrom > 65535) {
      return modalError('Port range: "from" must be 1–65535.');
    }
    if (!Number.isInteger(portTo) || portTo < 1 || portTo > 65535) {
      return modalError('Port range: "to" must be 1–65535.');
    }
    if (portFrom > portTo) {
      return modalError('Port range: "from" must be ≤ "to".');
    }
  }
  const portsObj = { type: porttype, list: list };
  if (porttype === 'range') { portsObj.from = portFrom; portsObj.to = portTo; }
  const notes = $('#rm-notes').value.trim();
  if (notes.length > 256) return modalError('Notes are capped at 256 characters.');
  const rule = {
    id: editingRuleId || '',
    enabled: $('#rm-enabled').checked,
    name,
    action: $('#rm-action').value,
    source: { type: srctype, value: srctype === 'any' ? '' : srcval },
    ports: portsObj,
    protocol: $('#rm-proto').value,
    zone: $('#rm-zone').value,
    notes,
  };
  if (editingRuleId) {
    const i = ruleIndex(editingRuleId);
    if (i >= 0) {
      rule.order = ruleSet.rules[i].order;
      ruleSet.rules[i] = rule;
    }
  } else {
    rule.order = (ruleSet.rules.length + 1) * 10;
    ruleSet.rules.push(rule);
  }
  closeRuleEditor();
  markDirty();
  setStatus('Rule applied — don’t forget “Save rules”.', 'ok');
}

$('#rm-cancel').addEventListener('click', closeRuleEditor);
$('#rm-save').addEventListener('click', saveRuleFromEditor);
$('#rm-srctype').addEventListener('change', updateModalFields);
$('#rm-porttype').addEventListener('change', updateModalFields);
$('#rule-modal').addEventListener('click', e => {
  if (e.target.id === 'rule-modal') closeRuleEditor();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('#rule-modal').hidden) closeRuleEditor();
});

/* ---------- exposure ---------- */
async function loadExposure() {
  const d = await api('/exposure');
  let exposed = 0, blocked = 0;
  const map = {
    lan: ['badge-lan', 'LAN'],
    blocked: ['badge-blocked', 'blocked'],
    local: ['badge-local', 'localhost'],
  };
  const rows = d.map(s => {
    if (s.reach === 'lan') exposed++;
    if (s.reach === 'blocked') blocked++;
    const [cls, lbl] = map[s.reach] || map.local;
    return `<tr>
      <td class="mono">${esc(s.port)}</td>
      <td>${esc(s.proc || '—')}</td>
      <td class="mono">${esc(s.bind)}</td>
      <td><span class="badge ${cls}">${lbl}</span></td>
      <td><button class="btn-secondary exp-rule" data-port="${esc(s.port)}">+ Rule</button></td>
    </tr>`;
  }).join('');
  const se = $('#stat-exposed');
  se.textContent = exposed;
  se.className = 'stat-num ' + (exposed > 10 ? 'warn' : '');
  const sb = $('#stat-blocked');
  sb.textContent = blocked;
  sb.className = 'stat-num ok';
  $('#exposure-list').innerHTML = d.length
    ? `<table class="tbl"><thead><tr><th>Port</th><th>Process</th><th>Bind</th><th>Reachable</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="loading">No listening ports found.</div>';
  $$('#exposure-list .exp-rule').forEach(b => b.addEventListener('click',
    () => openRuleEditorForPort(parseInt(b.dataset.port, 10))));
}

/* ---------- audit ---------- */
async function loadAudit() {
  const d = await api('/audit');
  const order = { open: 0, mitigated: 1, fixed: 2 };
  d.sort((a, b) => (order[a.status] - order[b.status]) || a.id.localeCompare(b.id));
  let open = 0;
  const rows = d.map(f => {
    if (f.status === 'open') open++;
    const sev = { HIGH: 'sev-high', MED: 'sev-med', LOW: 'sev-low' }[f.sev] || 'sev-low';
    const st = { open: 'st-open', mitigated: 'st-mit', fixed: 'st-fixed' }[f.status] || 'st-open';
    const stl = { open: 'open', mitigated: 'LAN-blocked', fixed: 'fixed' }[f.status] || f.status;
    return `<div class="finding ${st}">
      <div class="finding-head">
        <span class="sev ${sev}">${esc(f.sev)}</span>
        <span class="fid">${esc(f.id)}</span>
        <span class="ftitle">${esc(f.title)}</span>
        <span class="fstatus ${st}">${esc(stl)}</span>
      </div>
      <p class="fdetail">${esc(f.detail)}</p>
    </div>`;
  }).join('');
  const sf = $('#stat-findings');
  sf.textContent = open;
  sf.className = 'stat-num ' + (open > 0 ? 'warn' : 'ok');
  $('#audit-list').innerHTML = rows || '<div class="loading">No findings.</div>';
}

/* ---------- events ---------- */
async function loadEvents() {
  // Query the last hour, newest-first. The server parses journald with the
  // ZFW-IN-DROP / ZFW-DOCK-DROP log prefixes; nothing is persisted by us.
  const sinceTs = Math.floor(Date.now() / 1000) - 3600;
  const d = await api('/events?since=' + sinceTs + '&limit=300');
  $('#stat-events').textContent = d.length;
  $('#stat-events').className = 'stat-num ' + (d.length > 0 ? 'warn' : 'ok');
  if (!d.length) {
    $('#events-list').innerHTML = '<div class="loading">No drops in the last hour. Either nothing is probing your host or the firewall has not been applied yet — Safe-Apply on the Firewall tab installs the log targets.</div>';
    return;
  }
  const zoneMap = {
    host:   ['badge-blocked', 'host'],
    host6:  ['badge-blocked', 'host (v6)'],
    docker: ['badge-lan',     'docker'],
  };
  const rows = d.map(e => {
    const t = new Date(e.time);
    const ts = t.toLocaleTimeString() + ' ' + t.toLocaleDateString();
    const [cls, lbl] = zoneMap[e.zone] || ['badge-local', e.zone];
    return `<tr>
      <td class="mono">${esc(ts)}</td>
      <td class="mono">${esc(e.source || '?')}</td>
      <td class="mono">${e.port || '—'}</td>
      <td>${esc((e.protocol || '').toUpperCase())}</td>
      <td><span class="badge ${cls}">${lbl}</span></td>
    </tr>`;
  }).join('');
  $('#events-list').innerHTML = `<table class="tbl">
    <thead><tr><th>Time</th><th>Source IP</th><th>Dest port</th><th>Proto</th><th>Zone</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

/* ---------- versions ---------- */
async function loadVersions() {
  const d = await api('/versions');
  $('#versions-list').innerHTML = d.map(c => {
    const lvl = { ok: 'lvl-ok', warn: 'lvl-warn', crit: 'lvl-crit' }[c.level] || 'lvl-ok';
    return `<div class="vrow ${lvl}">
      <div class="vmain"><span class="vname">${esc(c.name)}</span><span class="vver mono">${esc(c.version)}</span></div>
      <p class="vnote">${esc(c.note)}</p>
    </div>`;
  }).join('') || '<div class="loading">No data.</div>';
}

/* ---------- init ---------- */
async function refreshAll() {
  setStatus('Loading…');
  try {
    await loadFirewall();
    await loadRules();
    await loadExposure();
    await loadEvents();
    await loadAudit();
    await loadVersions();
    setStatus('');
  } catch (e) {
    setStatus('Error: ' + e.message, 'err');
  }
}

$('#refresh-btn').addEventListener('click', refreshAll);
refreshAll();
