import { S, log, commit } from '../state.js';
import { html, icon, raw, $, timeAgo, toast } from '../util.js';
import { registerView, registerActions, go, rerender } from '../router.js';
import { analyze, buildFindings, SOURCE_LABEL } from '../analysis.js';

export const RISK_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
export const sortFindings = (f) => [...f].sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);

export function greeting() { const h = new Date().getHours(); return h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening'; }

export function scoreRing(score, grade, size = 160) {
  const r = 64, c = 2 * Math.PI * r, pct = score == null ? 0 : score / 100;
  const color = score == null ? '#6f88b0' : score >= 75 ? '#10b981' : score >= 50 ? '#f59e0b' : '#f43f5e';
  return html`<div class="ring" style="width:${size}px;height:${size}px"><svg viewBox="0 0 160 160" width="${size}" height="${size}" role="img" aria-label="Security score ${score ?? 'not available'} out of 100">
    <circle cx="80" cy="80" r="${r}" fill="none" stroke="rgba(157,180,214,.2)" stroke-width="12"/>
    <circle cx="80" cy="80" r="${r}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${(c * pct).toFixed(1)} ${c.toFixed(1)}" style="transition:stroke-dasharray .6s"/></svg>
    <div class="center"><div class="num">${score ?? '—'}</div><div class="grade" style="color:${color}">${grade}</div></div></div>`;
}

const SRC_CLASS = { verified: 'text-good', live: 'text-good', 'not-run': 'text-info', unavailable: 'text-warn', demo: 'text-info' };

export function findingRow(f) {
  const ic = f.risk === 'high' ? 'alert' : f.risk === 'medium' ? 'alert' : 'info';
  return html`<div class="sugg"><div class="si ${f.risk}">${icon(ic, 20)}</div><div class="grow"><b>${f.title}</b><span class="d">${f.text}</span></div>
    ${f.action ? html`<button class="btn sm" data-action="go" data-view="${f.action.view}" data-params="${JSON.stringify(f.action.params || {})}">${f.action.label}</button>` : ''}</div>`;
}

registerView('dashboard', {
  title: 'Dashboard',
  render(el) {
    const d = S.data, an = analyze(d);
    const findings = sortFindings(buildFindings(d, an));
    const dateStr = new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
    el.innerHTML = html`
      <section class="welcome">
        <div class="date">${dateStr}</div>
        <h1><span class="grad-text">${greeting()},</span><span> ${d.profile.name}!</span><span class="sun">${icon('sun', 38)}</span></h1>
        <p style="font-size:18px;opacity:.9">Welcome back to NexiVault. Your digital security starts here.</p>
        <div class="status-line"><span class="status-dot"></span>Your vault is unlocked and encrypted on this device</div>
        <div class="glance">${icon('lock', 26)}<div><b>Your vault at a glance</b><div class="small muted">${an.total} saved password${an.total === 1 ? '' : 's'} <span class="faint">·</span> Security score <b>${an.score == null ? 'n/a' : an.score + '/100'}</b></div></div>
          <button class="btn primary" data-action="go" data-view="passwords">Open vault →</button></div>
      </section>
      <section class="stat-grid" aria-label="Vault statistics">
        <button class="stat purple" data-action="go" data-view="passwords" data-params='{"filter":"all"}'><div><div class="lbl">Total Passwords</div><div class="num">${an.total}</div></div><div class="ic">${icon('lock', 30)}</div></button>
        <button class="stat cyan" data-action="go" data-view="passwords" data-params='{"filter":"strong"}'><div><div class="lbl">Strong</div><div class="num">${an.strong}</div></div><div class="ic">${icon('check', 30)}</div></button>
        <button class="stat orange" data-action="go" data-view="passwords" data-params='{"filter":"weak"}'><div><div class="lbl">Weak</div><div class="num">${an.weak}</div></div><div class="ic">${icon('alert', 30)}</div></button>
        <button class="stat pink" data-action="go" data-view="passwords" data-params='{"filter":"reused"}'><div><div class="lbl">Reused</div><div class="num">${an.reused}</div></div><div class="ic">${icon('refresh', 30)}</div></button>
      </section>
      <section class="grid g-score">
        <div class="card"><div class="row between wrap"><h3>Security Score</h3><button class="btn sm" data-action="run-check">${icon('refresh', 14)} Run security check</button></div>
          <div class="ring-wrap">${scoreRing(an.score, an.grade)}
            <div class="checks">${an.checks.map(c => html`<div class="check-row"><span class="l"><span class="${c.status === 'ok' ? 'text-good' : c.status === 'bad' ? 'text-bad' : c.status === 'warn' ? 'text-warn' : 'text-info'}">${icon(c.status === 'ok' ? 'check' : c.status === 'unverified' ? 'info' : 'alert', 15)}</span>${c.label}</span>
              <span class="v ${c.status === 'ok' ? 'text-good' : c.status === 'bad' ? 'text-bad' : c.status === 'warn' ? 'text-warn' : 'text-info'}">${c.value}<div class="tiny ${SRC_CLASS[c.source]}" style="font-weight:500">${SOURCE_LABEL[c.source]}</div></span></div>`)}</div></div>
          <div class="meta-line"><span>Two-factor: <b class="${an.totp ? 'text-good' : 'text-warn'}">${an.totp ? 'Enabled' : 'Not enabled'}</b></span><span>Last security check: <b>${d.lastSecurityCheck ? timeAgo(d.lastSecurityCheck) : 'never run'}</b></span><span>Unique: <b>${an.unique}/${an.total}</b></span></div>
          <p class="tiny faint mt-sm">Score is computed from your actual vault. Checks that have not been run (like breach lookups) are excluded, not assumed safe.</p></div>
        <div class="card"><div class="row between"><h3>Security Suggestions</h3><span class="badge ${findings.length ? 'warn' : 'good'}">${findings.length ? findings.length + ' open' : 'All clear'}</span></div>
          ${findings.length ? findings.slice(0, 4).map(findingRow) : html`<div class="sugg"><div class="si good">${icon('shieldcheck', 20)}</div><div class="grow"><b>Nothing needs attention</b><span class="d">Keep passwords unique and re-check regularly.</span></div></div>`}
          ${findings.length > 4 ? html`<button class="btn sm block mt-sm" data-action="go" data-view="guardian">See all ${findings.length} in Guardian</button>` : ''}</div>
      </section>
      <section class="grid g2 mt">
        <div class="card"><h3>Check a website before you sign in</h3><p class="muted small">Paste a link to see whether it matches your saved logins or looks like an imitation. Nothing is opened.</p>
          <form id="quick-scan" class="input-group mt-sm" novalidate><label class="sr-only" for="qs-url">Website address</label><input id="qs-url" placeholder="https://paypa1.com/login" autocomplete="off"><button class="btn primary" type="submit">${icon('globe', 16)} Scan</button></form></div>
        <div class="card"><div class="row between"><h3>Recent activity</h3><button class="btn sm ghost" data-action="go" data-view="timeline">View all</button></div>
          ${d.activity.slice(0, 4).map(a => html`<div class="row small" style="padding:6px 0"><span class="badge ${a.severity === 'error' ? 'bad' : a.severity === 'warn' ? 'warn' : a.severity === 'success' ? 'good' : 'info'}">${a.type.split('-')[0]}</span><span class="grow truncate">${a.text}</span><span class="faint tiny">${timeAgo(a.ts)}</span></div>`)}
          ${d.activity.length ? '' : html`<p class="muted small">No activity yet.</p>`}</div>
      </section>`.s;
    el.querySelector('#quick-scan').addEventListener('submit', (e) => { e.preventDefault(); go('scanner', { url: el.querySelector('#qs-url').value, auto: true }); });
  }
});

registerActions({
  'run-check': async () => {
    S.data.lastSecurityCheck = new Date().toISOString();
    const an = analyze(S.data);
    log('scan-completed', `Security check completed: score ${an.score ?? 'n/a'}, ${an.weak} weak, ${an.reused} reused`, 'success');
    toast('Security check complete.', 'success'); rerender();
  }
});
