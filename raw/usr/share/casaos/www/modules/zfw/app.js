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
  const r = await fetch(API_BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
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
  sfw.textContent = on ? 'aktiv' : 'aus';
  sfw.className = 'stat-num ' + (on ? 'ok' : 'crit');
  $('#fw-status').innerHTML =
    fwItem('Firewall aktiv', on) +
    fwItem('IPv6-Schutz', !!fw.ipv6_active) +
    fwItem('Boot-persistent', !!fw.service_enabled) +
    fwItem('INPUT-Regeln', fw.input_rules || 0) +
    fwItem('DOCKER-USER DROPs', fw.docker_drops || 0) +
    fwItem('Totmann scharf', !!fw.deadman, 'warn');
}

async function doFw(path, body, msg) {
  setStatus(msg);
  $$('#tab-firewall .action-row button').forEach(b => b.disabled = true);
  try {
    const d = await api(path, { method: 'POST', body: JSON.stringify(body || {}) });
    const out = $('#fw-output');
    out.hidden = false;
    out.textContent = String(d.output || d.status || '').trim() || '(kein Output)';
    setStatus(d.status || 'OK', 'ok');
    await loadFirewall();
    await loadExposure();
    await loadAudit();
  } catch (e) {
    setStatus('Fehler: ' + e.message, 'err');
  } finally {
    $$('#tab-firewall .action-row button').forEach(b => b.disabled = false);
  }
}

$('#btn-apply-safe').addEventListener('click', () => doFw('/apply', { safe: true }, 'Safe-Apply läuft…'));
$('#btn-apply').addEventListener('click', () => doFw('/apply', { safe: false }, 'Apply läuft…'));
$('#btn-commit').addEventListener('click', () => doFw('/commit', {}, 'Bestätige…'));
$('#btn-revert').addEventListener('click', () => {
  if (!confirm('Firewall wirklich komplett entfernen? Der Host ist danach ungefiltert.')) return;
  doFw('/revert', {}, 'Entferne Firewall…');
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
    const actLbl = r.action === 'allow' ? 'Erlauben' : 'Sperren';
    const src = r.source && r.source.type !== 'any' ? esc(r.source.value) : 'Alle';
    const ports = r.ports && r.ports.type === 'list' ? esc((r.ports.list || []).join(', ')) : 'Alle';
    const zone = { auto: 'Auto', host: 'Host', docker: 'Docker' }[r.zone] || esc(r.zone);
    return `<tr class="${r.enabled ? '' : 'rule-off'}" data-id="${esc(r.id)}">
      <td class="mono">${i + 1}</td>
      <td>${esc(r.name)}</td>
      <td><span class="actbadge ${actCls}">${actLbl}</span></td>
      <td class="mono">${src}</td>
      <td class="mono">${ports} <span class="proto">${esc(r.protocol)}</span></td>
      <td>${zone}</td>
      <td><label class="switch"><input type="checkbox" ${r.enabled ? 'checked' : ''} data-act="toggle"><span></span></label></td>
      <td class="rule-ops">
        <button data-act="up" ${i === 0 ? 'disabled' : ''} title="hoch">▲</button>
        <button data-act="down" ${i === n - 1 ? 'disabled' : ''} title="runter">▼</button>
      </td>
      <td><button data-act="edit" class="btn-secondary">Bearbeiten</button></td>
      <td><button data-act="del" class="btn-danger" title="löschen">×</button></td>
    </tr>`;
  }).join('');
  $('#rules-panel').innerHTML = `
    <div class="card defpol">
      <span class="defpol-lbl">Standard-Aktion für nicht passenden LAN-Verkehr:</span>
      <label><input type="radio" name="defpol" value="deny" ${dp === 'deny' ? 'checked' : ''}> Sperren <small>(Allowlist)</small></label>
      <label><input type="radio" name="defpol" value="allow" ${dp === 'allow' ? 'checked' : ''}> Durchlassen <small>(Blocklist)</small></label>
    </div>
    <div class="action-row">
      <button id="btn-new-rule" class="btn-primary">+ Neue Regel</button>
      <button id="btn-save-rules" class="btn-secondary${rulesDirty ? ' dirty' : ''}">Regeln speichern</button>
      <span class="save-hint"${rulesDirty ? '' : ' hidden'}>ungespeicherte Änderungen — speichern, dann im Firewall-Tab Safe-Apply</span>
    </div>
    <table class="tbl rules-tbl"><thead><tr>
      <th>#</th><th>Name</th><th>Aktion</th><th>Quelle</th><th>Ports</th><th>Zone</th>
      <th>Aktiv</th><th>Reihenfolge</th><th></th><th></th>
    </tr></thead><tbody>${rows || '<tr><td colspan="10" class="loading">Noch keine Regeln — „+ Neue Regel".</td></tr>'}</tbody></table>`;
  wireRules();
}

function wireRules() {
  $$('input[name="defpol"]').forEach(rb => rb.addEventListener('change', () => {
    ruleSet.default_policy = rb.value;
    markDirty();
  }));
  $('#btn-new-rule').addEventListener('click', () => openRuleEditor(null));
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
    if (!confirm(`Regel „${rs[i].name}" löschen?`)) return;
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

async function saveRules() {
  ruleSet.rules.forEach((r, i) => { r.order = (i + 1) * 10; });
  setStatus('Speichere Regeln…');
  try {
    await api('/rules', { method: 'POST', body: JSON.stringify(ruleSet) });
    setStatus('Regeln gespeichert — jetzt im Firewall-Tab Safe-Apply', 'ok');
    await loadRules();
  } catch (e) {
    setStatus('Fehler: ' + e.message, 'err');
  }
}

/* ---------- rule editor modal ---------- */
let editingRuleId = null;

function openRuleEditor(rule) {
  const isEdit = !!(rule && rule.id);
  editingRuleId = isEdit ? rule.id : null;
  $('#rm-title').textContent = isEdit ? 'Regel bearbeiten' : 'Neue Regel';
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
  $('#rm-proto').value = r.protocol || 'tcp';
  $('#rm-zone').value = r.zone || 'auto';
  $('#rm-enabled').checked = r.enabled !== false;
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
  $('#rm-srcval-fld').hidden = st === 'any';
  $('#rm-portval-fld').hidden = $('#rm-porttype').value !== 'list';
  $('#rm-geo-hint').hidden = !isGeo;
  $('#rm-srcval-label').textContent = isGeo ? 'Ländercodes (ISO, Komma-getrennt)' : 'Quell-Adresse';
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
  if (!name) return modalError('Name fehlt.');
  const srctype = $('#rm-srctype').value;
  let srcval = $('#rm-srcval').value.trim();
  if (srctype === 'ip' && !isIP(srcval)) return modalError('Quell-IP ungültig.');
  if (srctype === 'range' && !isCIDR(srcval)) return modalError('Quell-Bereich muss ein CIDR sein (z. B. 192.168.1.0/24).');
  if (srctype === 'country') {
    const codes = srcval.split(/[\s,]+/).filter(Boolean);
    if (!codes.length) return modalError('Mindestens einen Ländercode angeben.');
    if (codes.some(c => !/^[A-Za-z]{2}$/.test(c))) {
      return modalError('Ländercode = 2 Buchstaben (ISO-3166, z. B. DE).');
    }
    srcval = codes.map(c => c.toUpperCase()).join(',');
  }
  const porttype = $('#rm-porttype').value;
  let list = [];
  if (porttype === 'list') {
    list = $('#rm-portval').value.split(/[\s,]+/).filter(Boolean).map(Number);
    if (!list.length) return modalError('Mindestens einen Port angeben.');
    if (list.some(p => !Number.isInteger(p) || p < 1 || p > 65535)) {
      return modalError('Ungültiger Port — erlaubt ist 1–65535.');
    }
  }
  const rule = {
    id: editingRuleId || '',
    enabled: $('#rm-enabled').checked,
    name,
    action: $('#rm-action').value,
    source: { type: srctype, value: srctype === 'any' ? '' : srcval },
    ports: { type: porttype, list: list },
    protocol: $('#rm-proto').value,
    zone: $('#rm-zone').value,
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
  setStatus('Regel übernommen — „Regeln speichern" nicht vergessen.', 'ok');
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
    blocked: ['badge-blocked', 'gesperrt'],
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
      <td><button class="btn-secondary exp-rule" data-port="${esc(s.port)}">+ Regel</button></td>
    </tr>`;
  }).join('');
  const se = $('#stat-exposed');
  se.textContent = exposed;
  se.className = 'stat-num ' + (exposed > 10 ? 'warn' : '');
  const sb = $('#stat-blocked');
  sb.textContent = blocked;
  sb.className = 'stat-num ok';
  $('#exposure-list').innerHTML = d.length
    ? `<table class="tbl"><thead><tr><th>Port</th><th>Prozess</th><th>Bind</th><th>Erreichbar</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="loading">Keine lauschenden Ports gefunden.</div>';
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
    const stl = { open: 'offen', mitigated: 'LAN-gesperrt', fixed: 'behoben' }[f.status] || f.status;
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
  $('#audit-list').innerHTML = rows || '<div class="loading">Keine Befunde.</div>';
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
  }).join('') || '<div class="loading">Keine Daten.</div>';
}

/* ---------- init ---------- */
async function refreshAll() {
  setStatus('Lade…');
  try {
    await loadFirewall();
    await loadRules();
    await loadExposure();
    await loadAudit();
    await loadVersions();
    setStatus('');
  } catch (e) {
    setStatus('Fehler: ' + e.message, 'err');
  }
}

$('#refresh-btn').addEventListener('click', refreshAll);
refreshAll();
