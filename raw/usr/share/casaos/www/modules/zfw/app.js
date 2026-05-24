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
    const schedBadge = r.schedule
      ? ` <span class="sched-pill" title="Active ${esc(r.schedule.from)}–${esc(r.schedule.to)}${r.schedule.days && r.schedule.days.length ? ' on ' + r.schedule.days.join(',') : ' every day'}">${esc(r.schedule.from)}–${esc(r.schedule.to)}</span>`
      : '';
    return `<tr class="${r.enabled ? '' : 'rule-off'}" data-id="${esc(r.id)}">
      <td class="mono">${i + 1}</td>
      <td>${esc(r.name)}${noteBadge}${schedBadge}</td>
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
      <button id="btn-backup-rules" class="btn-secondary" title="Download the currently saved rules.json as a timestamped JSON file">Backup</button>
      <button id="btn-restore-rules" class="btn-secondary" title="Restore rules from a previously downloaded JSON file (replaces current rules)">Restore&hellip;</button>
      <input type="file" id="restore-file" accept="application/json,.json" hidden>
      <button id="btn-diff-rules" class="btn-secondary" ${rulesDirty ? '' : 'disabled'} title="Show what Save rules will change vs the currently saved rules.json">Diff</button>
      <button id="btn-save-rules" class="btn-secondary${rulesDirty ? ' dirty' : ''}">Save rules</button>
      <button id="btn-push-peers" class="btn-secondary" hidden title="Push the currently saved rules.json to every configured follower host (multi-host sync, opt-in)">Push to peers</button>
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
  $('#btn-backup-rules').addEventListener('click', backupRules);
  $('#btn-restore-rules').addEventListener('click', () => $('#restore-file').click());
  $('#restore-file').addEventListener('change', restoreRulesFromFile);
  $('#btn-diff-rules').addEventListener('click', openDiffView);
  $('#btn-save-rules').addEventListener('click', saveRules);
  $('#btn-push-peers').addEventListener('click', pushToPeers);
  // Multi-host sync is opt-in: surface the button only when peers.json has
  // entries. A daemon with no peers configured returns []; the button
  // stays hidden so a fresh install never sees it.
  api('/peers').then(ps => {
    if (Array.isArray(ps) && ps.length > 0) {
      const btn = $('#btn-push-peers');
      if (btn) {
        btn.hidden = false;
        btn.title = `Push the currently saved rules.json to ${ps.length} configured follower host${ps.length === 1 ? '' : 's'} (${ps.map(p => p.name).join(', ')})`;
      }
    }
  }).catch(() => { /* silent — peers is best-effort */ });
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

// backupRules downloads the current SAVED rules (the server-side rules.json,
// not the local dirty state) as a timestamped JSON file. The filename
// carries the date so a folder of backups stays self-describing without
// embedded metadata; the file content is the raw RuleSet exactly as the
// daemon serves it, so restoring is a single POST /api/rules.
async function backupRules() {
  let snapshot;
  try {
    snapshot = await api('/rules');
  } catch (e) {
    setStatus('Backup failed: ' + e.message, 'err');
    return;
  }
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace(/T/, '_').slice(0, 19);
  const filename = `zfw-rules-${ts}.json`;
  const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  const count = (snapshot.rules || []).length;
  setStatus(`Backup downloaded: ${filename} (${count} rule${count === 1 ? '' : 's'}).`, 'ok');
}

// restoreRulesFromFile reads a previously downloaded backup, validates
// the shape client-side, asks the user to confirm the overwrite, then
// POSTs to /api/rules. Server-side Validate runs again on the way in,
// so a tampered file still gets rejected with a clear error.
async function restoreRulesFromFile(ev) {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = ''; // clear the picker so the same file can be re-selected
  if (!f) return;
  let parsed;
  try {
    parsed = JSON.parse(await f.text());
  } catch (e) {
    setStatus('Restore failed: file is not valid JSON.', 'err');
    return;
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.rules) ||
      (parsed.default_policy !== 'deny' && parsed.default_policy !== 'allow')) {
    setStatus('Restore failed: file does not look like a zfw rules backup ' +
              '(expecting { default_policy, rules: [...] }).', 'err');
    return;
  }
  const incoming = parsed.rules.length;
  const current = (ruleSet && ruleSet.rules) ? ruleSet.rules.length : 0;
  if (!confirm(`Restore ${incoming} rule${incoming === 1 ? '' : 's'} from "${f.name}"?\n\n` +
               `This replaces the current ${current} rule${current === 1 ? '' : 's'} ` +
               `on the server. The firewall is NOT re-applied automatically — you still ` +
               `have to Safe-Apply on the Firewall tab after the restore.`)) return;
  setStatus('Restoring rules…');
  try {
    await api('/rules', { method: 'POST', body: JSON.stringify(parsed) });
    setStatus(`Restored ${incoming} rule${incoming === 1 ? '' : 's'} — now Safe-Apply on the Firewall tab.`, 'ok');
    await loadRules();
  } catch (e) {
    setStatus('Restore failed: ' + e.message, 'err');
  }
}

// ruleSignature collapses the semantic content of a rule to a single
// string for equality testing. Excludes id (may be empty for not-yet-
// saved rules) and order (renumbered on save), so two rules with the
// same effect but different positions count as identical.
function ruleSignature(r) {
  if (!r) return '';
  return JSON.stringify({
    enabled: r.enabled !== false,
    name: r.name || '',
    action: r.action || '',
    source: r.source || {},
    ports: r.ports || {},
    protocol: r.protocol || '',
    zone: r.zone || '',
    notes: r.notes || '',
    schedule: r.schedule || null,
    log: !!r.log,
    rate_limit: r.rate_limit || null,
  });
}

// ruleSummary returns a one-line human description of a rule —
// "Allow tcp 22 from 192.168.1.0/24 (Host)" — used in diff rows.
function ruleSummary(r) {
  const verb = r.action === 'deny' ? 'Deny' : 'Allow';
  const src = (r.source && r.source.type && r.source.type !== 'any')
    ? `from ${r.source.value || r.source.type}`
    : 'from any';
  let ports;
  if (!r.ports || r.ports.type === 'all') ports = 'all ports';
  else if (r.ports.type === 'range') ports = `${r.ports.from}–${r.ports.to}`;
  else ports = (r.ports.list || []).join(',');
  const zone = { auto: 'Auto', host: 'Host', docker: 'Docker' }[r.zone] || r.zone;
  let sched = '';
  if (r.schedule) {
    const days = (r.schedule.days && r.schedule.days.length) ? r.schedule.days.join(',') : 'every day';
    sched = ` @ ${r.schedule.from}-${r.schedule.to} ${days}`;
  }
  return `${verb} ${r.protocol || '?'} ${ports} ${src} [${zone}]${sched}`;
}

// computeDiff compares the saved snapshot (server-side rules.json)
// against the local rule set in memory and returns a list of changes.
// Each entry has a `type` field: "policy" (default_policy changed),
// "added" (rule in local but not saved), "removed" (rule saved but
// not local), "changed" (same id, different content).
function computeDiff(saved, local) {
  const changes = [];
  const savedPol = (saved && saved.default_policy) || 'deny';
  const localPol = (local && local.default_policy) || 'deny';
  if (savedPol !== localPol) changes.push({ type: 'policy', from: savedPol, to: localPol });

  const savedById = {};
  for (const r of (saved.rules || [])) if (r.id) savedById[r.id] = r;
  const localById = {};
  for (const r of (local.rules || [])) if (r.id) localById[r.id] = r;

  for (const r of (local.rules || [])) {
    if (!r.id) { changes.push({ type: 'added', rule: r }); continue; }
    if (!savedById[r.id]) { changes.push({ type: 'added', rule: r }); continue; }
    if (ruleSignature(savedById[r.id]) !== ruleSignature(r)) {
      changes.push({ type: 'changed', before: savedById[r.id], after: r });
    }
  }
  for (const id of Object.keys(savedById)) {
    if (!localById[id]) changes.push({ type: 'removed', rule: savedById[id] });
  }
  return changes;
}

// openDiffView fetches the currently saved rule set and renders the
// changes against the local in-memory ruleSet. Read-only: the modal
// has no action other than Close — the user reviews and then clicks
// Save rules in the action row when ready.
async function openDiffView() {
  const m = $('#diff-modal');
  const list = $('#diff-list');
  list.innerHTML = '<div class="loading">Computing diff&hellip;</div>';
  m.hidden = false;
  let saved;
  try {
    saved = await api('/rules');
  } catch (e) {
    list.innerHTML = `<p class="rm-error">Failed to load the saved rules: ${esc(e.message)}</p>`;
    return;
  }
  const changes = computeDiff(saved, ruleSet || { rules: [], default_policy: 'deny' });
  if (changes.length === 0) {
    list.innerHTML = '<p class="rm-hint">No changes — the local rule set matches what is saved on disk.</p>';
  } else {
    const parts = changes.map(c => {
      if (c.type === 'policy') {
        return `<div class="diff-row diff-changed">
          <span class="diff-mark">~</span>
          <div><div class="diff-title">Default policy</div>
            <div class="diff-detail"><span class="diff-from">${esc(c.from)}</span> → <span class="diff-to">${esc(c.to)}</span></div>
          </div></div>`;
      }
      if (c.type === 'added') {
        return `<div class="diff-row diff-added">
          <span class="diff-mark">+</span>
          <div><div class="diff-title">${esc(c.rule.name || '(unnamed)')}</div>
            <div class="diff-detail">${esc(ruleSummary(c.rule))}</div>
          </div></div>`;
      }
      if (c.type === 'removed') {
        return `<div class="diff-row diff-removed">
          <span class="diff-mark">−</span>
          <div><div class="diff-title">${esc(c.rule.name || '(unnamed)')}</div>
            <div class="diff-detail">${esc(ruleSummary(c.rule))}</div>
          </div></div>`;
      }
      // changed
      return `<div class="diff-row diff-changed">
        <span class="diff-mark">~</span>
        <div><div class="diff-title">${esc(c.after.name || '(unnamed)')}</div>
          <div class="diff-detail"><span class="diff-from">${esc(ruleSummary(c.before))}</span></div>
          <div class="diff-detail"><span class="diff-to">${esc(ruleSummary(c.after))}</span></div>
        </div></div>`;
    });
    const counts = changes.reduce((a, c) => (a[c.type] = (a[c.type] || 0) + 1, a), {});
    const summary = Object.entries(counts)
      .map(([k, v]) => `${v} ${k}`).join(', ');
    list.innerHTML = `<div class="diff-summary">${esc(summary)}</div>${parts.join('')}`;
  }
  $('#diff-close').onclick = () => { m.hidden = true; };
  m.onclick = (ev) => { if (ev.target === m) m.hidden = true; };
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

// pushToPeers fans out the currently saved rules.json to every configured
// follower via /api/peers/push. The endpoint reads rules.json off disk
// itself — so a user with unsaved local changes pushes the LAST SAVED
// set, not their in-flight edits. The result is one row per peer (ok or
// error string), surfaced via a status message rather than a modal so
// it stays consistent with the other action-row buttons.
async function pushToPeers() {
  const ps = await api('/peers').catch(() => []);
  if (!ps || ps.length === 0) {
    setStatus('No peers configured — set ZFW_PEERS to a peers.json file', 'err');
    return;
  }
  if (!confirm(`Push the currently saved rules.json to ${ps.length} peer${ps.length === 1 ? '' : 's'}?\n\n` +
               ps.map(p => `• ${p.name} (${p.url})`).join('\n') + '\n\n' +
               'Each peer must still Safe-Apply afterwards.')) return;
  setStatus(`Pushing rules to ${ps.length} peer${ps.length === 1 ? '' : 's'}…`);
  try {
    const results = await api('/peers/push', { method: 'POST' });
    const ok = results.filter(r => r.ok).map(r => r.name);
    const fail = results.filter(r => !r.ok);
    let msg = '';
    if (ok.length > 0) msg += `Pushed to: ${ok.join(', ')}. `;
    if (fail.length > 0) {
      msg += `Failed: ${fail.map(r => `${r.name} (${r.error || `HTTP ${r.code}`})`).join('; ')}.`;
    }
    setStatus(msg || 'Done.', fail.length === 0 ? 'ok' : 'err');
  } catch (e) {
    setStatus('Push failed: ' + e.message, 'err');
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
  // v0.4.4 advanced fields. Per-rule log: simple checkbox. Per-rule
  // rate-limit: collapsible fieldset with conn/seconds inputs that
  // round-trip the RateLimit pointer.
  $('#rm-log').checked = !!r.log;
  const rl = r.rate_limit || null;
  $('#rm-ratelimit-on').checked = !!rl;
  $('#rm-ratelimit-fld').hidden = !rl;
  $('#rm-ratelimit-conn').value = (rl && rl.conn) || 3;
  $('#rm-ratelimit-secs').value = (rl && rl.seconds) || 1;
  // Schedule: load the optional time-window into the fieldset; an
  // absent schedule means always-on (the checkbox stays unchecked
  // and the fieldset stays collapsed).
  const sch = r.schedule || null;
  $('#rm-schedule-on').checked = !!sch;
  $('#rm-schedule-fld').hidden = !sch;
  $('#rm-schedule-from').value = (sch && sch.from) || '08:00';
  $('#rm-schedule-to').value = (sch && sch.to) || '18:00';
  const days = (sch && Array.isArray(sch.days)) ? sch.days : [];
  $$('#rm-schedule-days input').forEach(cb => { cb.checked = days.indexOf(cb.value) !== -1; });
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

// openDenyEditorForPort is the Exposure-tab "→ Deny" one-click quick
// action: open the rule editor pre-filled for a flat deny on the given
// port. The user still has to Save rules + Safe-Apply — the prefill
// just removes the field-by-field setup so blocking an exposed port
// from the LAN takes two clicks instead of seven.
function openDenyEditorForPort(port) {
  openRuleEditor({
    id: '', name: 'Block port ' + port, action: 'deny',
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
  // v0.4.4 advanced fields. Same nil-pointer contract as Schedule:
  // only attach when the user opted in, so existing rules stay
  // byte-equal on the wire after a save-roundtrip with no edits to
  // these fields.
  const logOn = $('#rm-log').checked;
  let rateLimit = null;
  if ($('#rm-ratelimit-on').checked) {
    const conn = Number($('#rm-ratelimit-conn').value);
    const secs = Number($('#rm-ratelimit-secs').value);
    if (!Number.isInteger(conn) || conn < 1 || conn > 1000) {
      return modalError('Rate-limit: max conns must be 1–1000.');
    }
    if (!Number.isInteger(secs) || secs < 1 || secs > 3600) {
      return modalError('Rate-limit: seconds must be 1–3600.');
    }
    rateLimit = { conn, seconds: secs };
  }
  // Schedule: only attached when the checkbox is on, so existing
  // rules without a window stay schedule-less on the wire (matches
  // the backend's omitempty + nil-pointer contract).
  let schedule = null;
  if ($('#rm-schedule-on').checked) {
    const from = $('#rm-schedule-from').value;
    const to = $('#rm-schedule-to').value;
    if (!/^\d{2}:\d{2}$/.test(from) || !/^\d{2}:\d{2}$/.test(to)) {
      return modalError('Schedule: From and To must be HH:MM.');
    }
    const days = $$('#rm-schedule-days input').filter(cb => cb.checked).map(cb => cb.value);
    schedule = { from, to, days };
  }
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
  if (logOn) rule.log = true;
  if (rateLimit) rule.rate_limit = rateLimit;
  if (schedule) rule.schedule = schedule;
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
$('#rm-schedule-on').addEventListener('change', e => {
  $('#rm-schedule-fld').hidden = !e.target.checked;
});
$('#rm-ratelimit-on').addEventListener('change', e => {
  $('#rm-ratelimit-fld').hidden = !e.target.checked;
});
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
      <td class="exp-actions">
        <button class="btn-secondary exp-rule" data-port="${esc(s.port)}" title="Open rule editor pre-filled for this port">+ Rule</button>
        <button class="btn-secondary exp-deny" data-port="${esc(s.port)}" title="Open rule editor pre-filled to block this port from the LAN">&rarr; Deny</button>
      </td>
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
  $$('#exposure-list .exp-deny').forEach(b => b.addEventListener('click',
    () => openDenyEditorForPort(parseInt(b.dataset.port, 10))));
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
      ${renderHistory(f.history)}
    </div>`;
  }).join('');
  const sf = $('#stat-findings');
  sf.textContent = open;
  sf.className = 'stat-num ' + (open > 0 ? 'warn' : 'ok');
  $('#audit-list').innerHTML = rows || '<div class="loading">No findings.</div>';
}

// renderHistory turns a finding's status timeline into a compact
// inline summary. Hidden entirely on first sight (≤1 entry — the
// posture has never flipped, no story to tell); otherwise shows the
// chain of transitions as "open → fixed → open (since 2026-05-22)".
// The "since" is the timestamp of the LATEST entry — the moment the
// current status began. Date-only formatting keeps it scannable.
function renderHistory(history) {
  if (!Array.isArray(history) || history.length < 2) return '';
  const arrow = ' → ';
  const chain = history.map(e => esc(e.status)).join(arrow);
  const since = (history[history.length - 1].ts || '').slice(0, 10);
  return `<p class="fhistory" title="Status timeline (max 20 entries kept on disk).">
    History: ${chain}${since ? ` <span class="fhistory-since">(since ${esc(since)})</span>` : ''}
  </p>`;
}

/* ---------- events ---------- */

// topN counts occurrences of pick(ev) across events and returns the
// n entries with the highest counts as [{key, count}], descending.
// Ties are broken lexicographically on key so renders stay stable
// between refreshes — a flickering top-10 looks like a bug.
function topN(events, pick, n) {
  const m = new Map();
  for (const e of events) {
    const k = pick(e);
    if (k === null || k === undefined || k === '') continue;
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (b.count - a.count) || (String(a.key) > String(b.key) ? 1 : -1))
    .slice(0, n);
}

// bucketByTime returns an Array of count-per-bucket spanning [start, end),
// each bucket bucketMs wide. Events outside the range are dropped. Used
// by the 24h × 10-minute sparkline above the status bar.
function bucketByTime(events, startMs, endMs, bucketMs) {
  const buckets = new Array(Math.max(0, Math.ceil((endMs - startMs) / bucketMs))).fill(0);
  for (const e of events) {
    const t = new Date(e.time).getTime();
    if (!Number.isFinite(t) || t < startMs || t >= endMs) continue;
    const i = Math.floor((t - startMs) / bucketMs);
    if (i >= 0 && i < buckets.length) buckets[i]++;
  }
  return buckets;
}

// renderSparkline builds an inline SVG of len(buckets) vertical bars
// scaled to the tallest bar. Empty timeline renders as an empty box
// (no SVG noise). Width is fixed-ish via CSS — bar widths derive from
// 100% so the host element controls layout.
function renderSparkline(buckets) {
  if (!buckets.length) return '';
  const max = Math.max(1, ...buckets);
  const w = 100 / buckets.length;
  const bars = buckets.map((c, i) => {
    const h = (c / max) * 100;
    return `<rect x="${(i * w).toFixed(3)}%" y="${(100 - h).toFixed(3)}%" width="${w.toFixed(3)}%" height="${h.toFixed(3)}%"/>`;
  }).join('');
  return `<svg viewBox="0 0 100 100" preserveAspectRatio="none" class="sparkline" aria-hidden="true">${bars}</svg>`;
}

function renderTopList(elId, items, label) {
  const el = $(elId);
  if (!items.length) {
    el.innerHTML = '<div class="ev-top-empty">No data.</div>';
    return;
  }
  const max = items[0].count;
  el.innerHTML = items.map(it => {
    const pct = max > 0 ? (it.count / max) * 100 : 0;
    return `<div class="ev-top-row">
      <span class="ev-top-key mono">${esc(it.key)}</span>
      <span class="ev-top-bar"><span class="ev-top-fill" style="width:${pct.toFixed(1)}%"></span></span>
      <span class="ev-top-count mono">${it.count}</span>
    </div>`;
  }).join('');
}

// flagFor renders an ISO-3166 alpha-2 country code as the matching
// regional-indicator flag emoji. Empty/unknown codes render as a
// neutral placeholder so the column stays aligned without the
// flag-of-undefined-country glyph.
function flagFor(cc) {
  if (!cc || cc.length !== 2) return '';
  const base = 0x1F1E6;
  const A = 'A'.charCodeAt(0);
  return String.fromCodePoint(
    base + (cc.toUpperCase().charCodeAt(0) - A),
    base + (cc.toUpperCase().charCodeAt(1) - A),
  );
}

async function loadEvents() {
  // Fetch the full 24h window once — the sparkline needs the long view
  // and the 1h table is just a slice of the same data. limit=5000 caps
  // the worst-case payload from a noisy host; older events get truncated
  // (the sparkline then under-reports the oldest buckets, which is
  // honest enough for an at-a-glance signal).
  const nowMs = Date.now();
  const since24 = Math.floor(nowMs / 1000) - 86400;
  const all = await api('/events?since=' + since24 + '&limit=5000');

  // Sparkline: 144 buckets × 10 minutes covering the last 24h.
  const bucketMs = 10 * 60 * 1000;
  const startMs = nowMs - 24 * 3600 * 1000;
  const buckets = bucketByTime(all, startMs, nowMs, bucketMs);
  $('#stat-sparkline').innerHTML = renderSparkline(buckets);

  // 1h slice — drives stat counter, top-N cards, and the events table.
  const oneHourAgo = nowMs - 3600 * 1000;
  const recent = all.filter(e => new Date(e.time).getTime() >= oneHourAgo);

  $('#stat-events').textContent = recent.length;
  $('#stat-events').className = 'stat-num ' + (recent.length > 0 ? 'warn' : 'ok');

  // GeoIP source-flag enrichment (v0.4.5). Batch-resolve every unique
  // source IP in the visible window through /api/geo/lookup, which
  // returns a {ip: country-code} map from the cached geo .zone files.
  // Missing data = "" = no flag. Network errors degrade silently so a
  // broken /api/geo never breaks the events table.
  let countryByIP = {};
  if (recent.length > 0) {
    const uniq = [...new Set(recent.map(e => e.source).filter(Boolean))];
    if (uniq.length > 0) {
      try {
        countryByIP = await api('/geo/lookup?ips=' + uniq.map(encodeURIComponent).join(','));
      } catch (_) { /* silent — flags are best-effort */ }
    }
  }

  // Top-N analytics: hidden when there's nothing to summarise, so an
  // empty Events tab stays as clean as before v0.4.1.
  if (recent.length > 0) {
    $('#events-analytics').hidden = false;
    renderTopList('#ev-top-sources', topN(recent, e => e.source, 10));
    renderTopList('#ev-top-ports', topN(recent, e => e.port || null, 10));
  } else {
    $('#events-analytics').hidden = true;
  }

  if (!recent.length) {
    $('#events-list').innerHTML = '<div class="loading">No drops in the last hour. Either nothing is probing your host or the firewall has not been applied yet — Safe-Apply on the Firewall tab installs the log targets.</div>';
    return;
  }
  const zoneMap = {
    host:   ['badge-blocked', 'host'],
    host6:  ['badge-blocked', 'host (v6)'],
    docker: ['badge-lan',     'docker'],
  };
  // Threat banner: counts events that the server-side classifier
  // flagged with port_scan / brute_force tags in the visible window.
  // Hidden when neither pattern fired so the tab stays quiet on a
  // healthy host.
  const threatCounts = { port_scan: new Set(), brute_force: new Set() };
  for (const e of recent) {
    if (!e.threats) continue;
    for (const t of e.threats) {
      if (threatCounts[t]) threatCounts[t].add(e.source || '?');
    }
  }
  const threatBanner = (() => {
    const parts = [];
    if (threatCounts.port_scan.size > 0) {
      parts.push(`<b>${threatCounts.port_scan.size}</b> source${threatCounts.port_scan.size === 1 ? '' : 's'} flagged for port-scan`);
    }
    if (threatCounts.brute_force.size > 0) {
      parts.push(`<b>${threatCounts.brute_force.size}</b> source${threatCounts.brute_force.size === 1 ? '' : 's'} flagged for brute-force`);
    }
    return parts.length
      ? `<div class="threat-banner"><span class="threat-icon" aria-hidden="true">&#9888;</span> ${parts.join(' · ')} <small>(last hour)</small></div>`
      : '';
  })();
  const threatLabel = { port_scan: 'scan', brute_force: 'brute' };
  const rows = recent.map(e => {
    const t = new Date(e.time);
    const ts = t.toLocaleTimeString() + ' ' + t.toLocaleDateString();
    const [cls, lbl] = zoneMap[e.zone] || ['badge-local', e.zone];
    const pills = (e.threats || []).map(tag =>
      `<span class="threat-pill threat-${esc(tag)}" title="Classifier flagged this event with ${esc(tag)}">${esc(threatLabel[tag] || tag)}</span>`
    ).join('');
    const cc = countryByIP[e.source];
    const flag = cc
      ? `<span class="geo-flag" title="Source country: ${esc(cc.toUpperCase())} (from cached geo .zone files)">${flagFor(cc)} ${esc(cc.toUpperCase())}</span>`
      : '';
    return `<tr${e.threats && e.threats.length ? ' class="ev-threat-row"' : ''}>
      <td class="mono">${esc(ts)}</td>
      <td class="mono">${esc(e.source || '?')}${flag}${pills}</td>
      <td class="mono">${e.port || '—'}</td>
      <td>${esc((e.protocol || '').toUpperCase())}</td>
      <td><span class="badge ${cls}">${lbl}</span></td>
    </tr>`;
  }).join('');
  $('#events-list').innerHTML = threatBanner + `<table class="tbl">
    <thead><tr><th>Time</th><th>Source IP</th><th>Dest port</th><th>Proto</th><th>Zone</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

/* ---------- conntrack ---------- */
async function loadConntrack() {
  const d = await api('/conntrack');
  if (!d.length) {
    $('#conntrack-list').innerHTML = '<div class="loading">No active connections, or the kernel conntrack module is not available on this host.</div>';
    return;
  }
  const stateBadge = st => {
    if (!st) return '<span class="ct-state ct-state-none">&mdash;</span>';
    const cls = {
      ESTABLISHED: 'ct-state-est',
      TIME_WAIT:   'ct-state-tw',
      CLOSE_WAIT:  'ct-state-cw',
      SYN_SENT:    'ct-state-syn',
      SYN_RECV:    'ct-state-syn',
    }[st] || 'ct-state-other';
    return `<span class="ct-state ${cls}">${esc(st)}</span>`;
  };
  const rows = d.map(c => {
    const sport = c.src_port ? ':' + c.src_port : '';
    const dport = c.dst_port ? ':' + c.dst_port : '';
    return `<tr>
      <td>${esc((c.protocol || '').toUpperCase())}</td>
      <td>${stateBadge(c.state)}</td>
      <td class="mono">${esc(c.src_ip)}${esc(sport)}</td>
      <td class="mono">${esc(c.dst_ip)}${esc(dport)}</td>
      <td class="mono">${c.age_sec || 0}s</td>
    </tr>`;
  }).join('');
  $('#conntrack-list').innerHTML = `<table class="tbl">
    <thead><tr><th>Proto</th><th>State</th><th>Source</th><th>Destination</th><th>Expires in</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

/* ---------- versions ---------- */
async function loadVersions() {
  const d = await api('/versions');
  // Self-update check: pull the cached status (the daemon polls weekly,
  // this just reads its in-memory snapshot). Render a non-blocking
  // "vX available" banner at the top of the tab when an upgrade exists.
  // A disabled checker or any network error returns a Status with no
  // Latest set — the banner is then silently hidden.
  let updateBanner = '';
  try {
    const u = await api('/update');
    if (u && u.available && u.latest) {
      const notes = u.notes ? ` &mdash; ${esc(u.notes)}` : '';
      updateBanner = `<div class="upd-banner">
        <span class="upd-pill">Update available: v${esc(u.latest)}</span>
        <span class="upd-cur">current: v${esc(u.current)}${notes}</span>
      </div>`;
    }
  } catch (_) { /* silent — badge is best-effort */ }
  $('#versions-list').innerHTML = updateBanner + d.map(c => {
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
    await loadConntrack();
    await loadAudit();
    await loadVersions();
    setStatus('');
  } catch (e) {
    setStatus('Error: ' + e.message, 'err');
  }
}

$('#refresh-btn').addEventListener('click', refreshAll);
refreshAll();
