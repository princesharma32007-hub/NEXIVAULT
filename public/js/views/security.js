// Security Check: health dashboard, breach monitoring (k-anonymity), privacy risk scanner.
import { S, log, commit } from '../state.js';
import { html, icon, $, toast, timeAgo, fmtDateTime } from '../util.js';
import { registerView, registerActions, ui, rerender } from '../router.js';
import { analyze, privacyFindings, SOURCE_LABEL } from '../analysis.js';
import { sha1Hex } from '../crypto.js';
import { scoreRing } from './dashboard.js';

const TABS = [['health', 'Health'], ['breach', 'Breach monitoring'], ['privacy', 'Privacy risks']];
let running = false;

function bar(label, n, total, cls) {
  const pct = total ? Math.round(n / total * 100) : 0;
  return html`<div class="bar-row"><span>${label}</span><div class="meter"><i class="${cls}" style="width:${pct}%"></i></div><b>${n}</b></div>`;
}

function healthTab(an) {
  const d = S.data;
  const recent = d.activity.slice(0, 5);
  return html`<div class="grid g-score">
    <div class="card"><h3>Overall security score</h3><div class="ring-wrap">${scoreRing(an.score, an.grade)}
      <div class="checks">${an.checks.map(c => html`<div class="check-row"><span class="l">${c.label}</span><span class="v">${c.value}<div class="tiny faint" style="font-weight:500">${SOURCE_LABEL[c.source]}</div></span></div>`)}</div></div>
      <div class="meta-line"><span>Last check: <b>${d.lastSecurityCheck ? timeAgo(d.lastSecurityCheck) : 'never'}</b></span></div></div>
    <div class="card"><h3>Password breakdown</h3><div class="bars">
      ${bar('Strong', an.strong, an.total, 'good')}${bar('Medium', an.medium, an.total, 'warn')}${bar('Weak', an.weak, an.total, 'bad')}${bar('Reused', an.reused, an.total, 'bad')}${bar('Old', an.old, an.total, 'warn')}${bar('Exposed', an.exposed, an.total, 'bad')}</div></div></div>
    <div class="grid g4 mt">${[
      ['Total passwords', an.total, 'passwords', 'all', ''], ['Old passwords', an.old, 'passwords', 'old', `>${d.settings.oldDays} days`], ['Exposed', an.breachLive ? an.exposed : 'n/a', 'security', null, an.breachLive ? 'live breach check' : 'not checked'], ['Website warnings', an.siteWarnings, 'timeline', 'autofill', 'last 30 days + http:// sites']]
      .map(([l, v, view, f, s]) => html`<button class="card" style="text-align:left;cursor:pointer" data-action="go" data-view="${view}" data-params="${JSON.stringify(f ? { filter: f } : { tab: 'breach' })}"><div class="small muted">${l}</div><div style="font-size:30px;font-weight:800">${v}</div><div class="tiny faint">${s}</div></button>`)}</div>
    <div class="card mt"><div class="row between"><h3>Recent security activity</h3><button class="btn sm ghost" data-action="go" data-view="timeline">View all</button></div>
      ${recent.length ? recent.map(a => html`<div class="row small" style="padding:6px 0"><span class="grow">${a.text}</span><span class="faint tiny">${timeAgo(a.ts)}</span></div>`) : html`<p class="muted small">No activity yet.</p>`}</div>`;
}

function breachTab(an) {
  const d = S.data, api = S.api, b = d.breach;
  const enabled = d.settings.privacy.useBreachRange && api?.breachRange?.enabled;
  return html`<div class="note-banner mb">${icon('info', 16)}<div><b>How this works.</b> Each password is hashed (SHA-1) in your browser; only the first 5 characters of the hash go to your NexiVault server, which relays the request to the Have I Been Pwned range API. The server and HIBP never see your password or the full hash. Results come back as a list your browser matches locally (k-anonymity). Account-level “dark web” monitoring (by email address) needs a paid service and is <b>not</b> included.</div></div>
    <div class="card mt"><div class="row between wrap"><div><h3 style="margin:0">Breach status</h3><p class="small muted mt-sm">Last checked: <b>${b.lastChecked ? fmtDateTime(b.lastChecked) : 'never'}</b> · Mode: <b>${b.mode === 'live' ? 'Live HIBP range lookup' : b.mode === 'unavailable' ? 'Service unavailable' : 'Not run'}</b></p></div>
      <button class="btn primary" data-action="breach-run" ${running || !an.total || !enabled ? 'disabled' : ''}>${running ? html`<span class="spinner"></span> Checking…` : html`${icon('refresh', 16)} ${b.lastChecked ? 'Recheck' : 'Run breach check'}`}</button></div>
      ${!enabled ? html`<p class="small text-warn mt-sm">Breach lookups are ${d.settings.privacy.useBreachRange ? 'disabled on the server' : 'turned off in Settings → Privacy'}.</p>` : ''}
      ${b.mode === 'unavailable' ? html`<p class="small text-warn mt-sm">${b.error || 'The breach service could not be reached.'} Nothing was marked safe or exposed. Try again when online.</p>` : ''}</div>
    <div class="card mt"><h3>Per-account results</h3>
      ${an.total ? d.entries.map(e => { const r = b.results[e.id]; return html`<div class="row" style="padding:10px 0;border-bottom:1px solid var(--border)"><div class="grow"><b>${e.name}</b><div class="tiny muted">${e.username || e.email}</div></div>
        ${r ? (r.count > 0 ? html`<span class="badge bad">Exposed · ${r.count.toLocaleString()}×</span><button class="btn sm" data-action="go" data-view="passwords" data-params='{"filter":"exposed"}'>Fix</button>` : html`<span class="badge good">Not found</span>`) : html`<span class="badge neutral">Not checked</span>`}</div>`; }) : html`<p class="muted small">Add passwords to check them.</p>`}
      <h4 class="mt">Recommended remediation</h4><ul class="small muted" style="margin:6px 0 0 18px"><li>Change any exposed password on the real site and use a generated one.</li><li>Never reuse an exposed password anywhere else.</li><li>Turn on two-factor authentication for affected accounts.</li></ul></div>`;
}

function privacyTab(an) {
  const items = privacyFindings(S.data, an, S.api);
  const cls = { high: 'bad', medium: 'warn', low: 'neutral', info: 'info', good: 'good' };
  return html`<div class="card"><h3>Privacy risk scanner</h3><p class="small muted">Based only on what NexiVault can verify from this vault and its configuration. It cannot see accounts outside the vault.</p>
    ${items.map(i => html`<div class="sugg"><div class="si ${i.severity === 'good' ? 'good' : i.severity}">${icon(i.severity === 'good' ? 'shieldcheck' : i.severity === 'info' ? 'info' : 'alert', 20)}</div><div class="grow"><b>${i.title} <span class="badge ${cls[i.severity]}">${i.severity}</span></b><span class="d">${i.text}</span></div>${i.action ? html`<button class="btn sm" data-action="go" data-view="${i.action.view}" data-params="${JSON.stringify(i.action.params || {})}">${i.action.label}</button>` : ''}</div>`)}</div>`;
}

registerView('security', {
  title: 'Security Check',
  render(el, params) {
    if (params.tab) ui.securityTab = params.tab;
    const an = analyze(S.data);
    el.innerHTML = html`<div class="page-head"><div><h2>Security Check</h2><p>Statistics calculated from your actual vault. Unrun checks are labelled, never assumed safe.</p></div><button class="btn primary" data-action="run-check">${icon('refresh', 16)} Run security check</button></div>
      <div class="tabs" role="tablist">${TABS.map(([id, l]) => html`<button class="tab ${ui.securityTab === id ? 'active' : ''}" role="tab" data-action="sec-tab" data-tab="${id}">${l}</button>`)}</div>
      ${ui.securityTab === 'breach' ? breachTab(an) : ui.securityTab === 'privacy' ? privacyTab(an) : healthTab(an)}`.s;
  }
});

registerActions({
  'sec-tab': (el) => { ui.securityTab = el.dataset.tab; rerender(); },
  'breach-run': async () => {
    if (running) return; running = true; rerender();
    const d = S.data, cache = new Map(); let failed = false;
    try {
      for (const e of d.entries) {
        const hash = await sha1Hex(e.password), prefix = hash.slice(0, 5), suffix = hash.slice(5);
        if (!cache.has(prefix)) {
          const r = await fetch('/api/breach/range/' + prefix);
          if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'HTTP ' + r.status);
          cache.set(prefix, await r.text());
        }
        let count = 0;
        for (const line of cache.get(prefix).split('\n')) { const [h, c] = line.trim().split(':'); if (h === suffix) { count = parseInt(c, 10) || 0; break; } }
        d.breach.results[e.id] = { count, checkedAt: new Date().toISOString() };
      }
      d.breach.mode = 'live'; d.breach.lastChecked = new Date().toISOString(); d.breach.error = null;
      const n = Object.values(d.breach.results).filter(r => r.count > 0).length;
      log('scan-completed', `Breach check completed: ${n} exposed of ${d.entries.length}`, n ? 'warn' : 'success');
      toast(n ? `${n} password(s) found in breaches.` : 'No exposed passwords found.', n ? 'warn' : 'success');
    } catch (e) {
      failed = true; d.breach.mode = 'unavailable'; d.breach.error = e.message === 'Failed to fetch' ? 'NexiVault server unreachable.' : e.message;
      log('scan-completed', 'Breach check failed: service unavailable', 'warn'); toast('Breach service unavailable. No results were recorded as safe.', 'error');
    } finally { running = false; await commit(); rerender(); }
  }
});
