// Safe-autofill flow + shared website-assessment rendering (used by Passwords and the Website Safety Scanner).
import { S, log, commit, touchUsed } from '../state.js';
import { html, icon, raw, $, openModal, toast, copyText, uid, timeAgo } from '../util.js';
import { assessDestination, mergeThreatIntel, parseUrl, LEVEL_LABEL } from '../domain.js';

/** Ask the server for reputation. Sends ONLY the origin (scheme+host[:port]); never a password, path or query. */
export async function checkThreatIntel(origin) {
  if (!S.data.settings.privacy.useThreatIntel) return { configured: false, available: false, status: 'disabled', note: 'Disabled in Settings → Privacy.' };
  try {
    const r = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: origin }) });
    const j = await r.json().catch(() => ({}));
    if (r.status === 429) return { configured: true, available: false, status: 'unavailable', error: 'Rate limited. Try again in a minute.' };
    if (!r.ok) return { configured: false, available: false, status: 'unavailable', error: j.error || 'Scanner returned an error.' };
    if (!j.configured) return { configured: false, available: false, status: 'not-configured', note: j.note };
    if (!j.available) return { ...j, status: 'unavailable' };
    return { ...j, status: j.malicious ? 'flagged' : 'clean' };
  } catch { return { configured: false, available: false, status: 'unavailable', error: 'NexiVault server unreachable.' }; }
}

export const tiText = (ti) => ({
  disabled: 'Disabled in privacy settings.', 'not-configured': 'Not configured: no threat-intelligence API key on the server. Local heuristics only.', 'not-run': 'Not run.',
  unavailable: `Unavailable${ti?.error ? ': ' + ti.error : ''}. Result is based on local heuristics only.`,
  clean: `No match in ${ti?.source || 'threat-intelligence database'} (this does not prove the site is safe).`,
  flagged: `Flagged by ${ti?.source || 'threat intelligence'}${ti?.threats?.length ? ': ' + ti.threats.join(', ') : ''}.`
}[ti?.status || 'not-run']);

const LEVEL_ICON = { safe: 'shieldcheck', suspicious: 'alert', malicious: 'alert', unverified: 'info', invalid: 'info' };
const LEVEL_MSG = {
  safe: 'The destination matches your saved domain and no check raised a warning. Still glance at the address bar before signing in.',
  suspicious: 'This address differs from your saved domain or looks like an imitation. Do not enter your password here unless you can verify the site independently.',
  malicious: 'A reliable detection source identified this destination as dangerous. Autofill is blocked and no password was copied.',
  unverified: 'NexiVault cannot confirm this site belongs to the saved account, so it is not being treated as safe.',
  invalid: 'This address could not be checked.'
};

export function verdictBanner(a) {
  return html`<div class="verdict ${a.level}"><div class="vi">${icon(LEVEL_ICON[a.level], 26)}</div><div><h3>${LEVEL_LABEL[a.level]}</h3><p class="small">${a.error || LEVEL_MSG[a.level]}</p></div></div>`;
}

const sevBadge = { high: 'bad', medium: 'warn', low: 'neutral', info: 'info' };
export function assessmentDetails(a, { name } = {}) {
  const ti = a.threatIntel;
  const rows = [
    ['Website', name || (a.matchedEntryName ? a.matchedEntryName : 'Not a saved login')],
    ['Current hostname', a.hostname + (a.hostnameUnicode && a.hostnameUnicode !== a.hostname ? `  (displays as ${a.hostnameUnicode})` : '')],
    ['Expected saved domain', a.expectedHostname || 'None saved'],
    ['HTTPS', a.https ? 'Yes. The connection is encrypted (this alone does not prove authenticity).' : 'No. The connection is not encrypted.'],
    ['Domain match', a.checks.find(c => c.id === 'match')?.detail],
    ['Impersonation indicators', a.indicators.filter(i => i.severity === 'high').length ? `${a.indicators.filter(i => i.severity === 'high').length} high-risk` : 'None found'],
    ['Threat intelligence', tiText(ti)],
    ['Final assessment', LEVEL_LABEL[a.level]]
  ];
  return html`<dl class="kv">${rows.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>
    ${a.indicators.length ? html`<div class="mt"><div class="small muted" style="font-weight:700;margin-bottom:4px">Indicators <span class="badge neutral">Local heuristics</span></div>${a.indicators.map(i => html`<div class="ind"><span class="badge ${sevBadge[i.severity]}">${i.severity}</span><span class="small">${i.text}</span></div>`)}</div>` : ''}`;
}

export function recommendations(a) {
  if (a.level === 'safe') return ['Check that the address bar matches before entering anything.', 'Keep two-factor authentication on for this account.'];
  if (a.level === 'malicious') return ['Close the page and do not enter any credentials.', 'If you already entered a password there, change it immediately on the real site.', 'Report the page to the service it imitates.'];
  if (a.level === 'unverified') return ['Add the official website address to the saved login so NexiVault can verify it.', 'Open the real site from a bookmark or by typing the address yourself.'];
  return ['Do not sign in on this page. Type the real address yourself or use a bookmark.', 'Compare the registrable domain letter by letter with the one you saved.', 'If you already entered a password, change it on the real site now.'];
}

export function recordScan(host, level, source, name) {
  if (!S.data.settings.privacy.recordScanHistory) return;
  S.data.scans.unshift({ id: uid(), ts: new Date().toISOString(), host, level, source, name: name || '' });
  S.data.scans.length = Math.min(S.data.scans.length, 50);
}

/** Full assessment (local + threat intel) and activity logging. Returns the merged assessment. */
export async function assessWithIntel(destination, expected, { name, source = 'autofill' } = {}) {
  const local = assessDestination(destination, expected);
  if (local.level === 'invalid') return local;
  const ti = await checkThreatIntel(parseUrl(destination).displayOrigin);
  const a = mergeThreatIntel(local, ti);
  recordScan(a.hostname, a.level, source, name);
  if (a.level === 'safe') log('scan-completed', `Website check: ${a.hostname} matches saved domain${name ? ' for "' + name + '"' : ''}`, 'success');
  else {
    log('suspicious-domain', `${LEVEL_LABEL[a.level]}: ${a.hostname}${name ? ' (saved login "' + name + '")' : ''}`, a.level === 'malicious' ? 'error' : 'warn');
    if (source === 'autofill') log('autofill-blocked', `Autofill blocked on ${a.hostname} for "${name}"`, 'warn');
  }
  return a;
}

// ---------- the autofill dialog flow ----------
export function startAutofill(entryId, presetUrl) {
  const e = S.data.entries.find(x => x.id === entryId); if (!e) return;
  const m = openModal(String(html`
    <div class="modal-head"><h3>Safe autofill check</h3></div>
    <form id="af-form" novalidate><div class="modal-body">
      <p class="muted small">NexiVault verifies where you are signing in <b>before</b> any credential is copied or filled for <b>${e.name}</b>. A normal web page cannot see your other browser tabs, so enter the address of the page you are about to use. (A browser extension would read it automatically; see the Website Safety Scanner page.)</p>
      <label class="field mt"><span>Page you are signing in on</span><input id="af-url" placeholder="https://…" autocomplete="off" value="${presetUrl ?? e.url ?? ''}" autofocus><span class="hint">Only the site address is checked. Your password is never sent anywhere.</span></label>
      <div class="err" id="af-err" role="alert"></div>
    </div><div class="modal-foot"><button class="btn ghost" type="button" id="af-cancel">Cancel</button><button class="btn primary" type="submit" id="af-go">${icon('shieldcheck', 16)} Check website</button></div></form>`), { label: 'Safe autofill check' });
  $('#af-cancel', m.el).onclick = () => m.close();
  $('#af-form', m.el).addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const url = $('#af-url', m.el).value, btn = $('#af-go', m.el), err = $('#af-err', m.el);
    const p = parseUrl(url); if (!p.ok) return err.textContent = p.error;
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Checking…';
    const a = await assessWithIntel(url, e.url, { name: e.name });
    m.close(); showResult(e, a);
  });
}

function showResult(e, a) {
  const blocked = a.level !== 'safe';
  const m = openModal(String(html`
    <div class="modal-head"><h3>Website safety result</h3></div>
    <div class="modal-body">
      ${verdictBanner(a)}
      <div class="mt">${assessmentDetails(a, { name: e.name })}</div>
      ${blocked ? html`<div class="note-banner warn mt">${icon('alert', 16)}<div><b>Autofill is blocked.</b> No username or password has been filled or copied.<ul class="small" style="margin:6px 0 0 16px;padding:0">${recommendations(a).map(r => html`<li>${r}</li>`)}</ul></div></div>` : ''}
      ${a.level === 'suspicious' || a.level === 'unverified' ? html`<div class="card flat mt" id="override-box"><label class="check"><input type="checkbox" id="ov-ok"><span class="small">I have verified independently that <b>${a.hostname}</b> is the genuine site for ${e.name}.</span></label></div>` : ''}
      <div id="fill-actions" class="${blocked ? 'hidden' : ''} mt"><div class="row wrap"><button class="btn" id="fa-user">${icon('user', 15)} Copy username</button><button class="btn" id="fa-fill">${icon('edit', 15)} Fill demo login form</button><button class="btn primary" id="fa-pw">${icon('key', 15)} Copy password</button></div></div>
    </div>
    <div class="modal-foot"><button class="btn ${blocked ? 'primary' : 'ghost'}" id="fa-close">${a.level === 'safe' ? 'Done' : 'Cancel and return to vault'}</button>
      ${a.level === 'suspicious' || a.level === 'unverified' ? html`<button class="btn warn" id="ov-go" disabled>Proceed anyway</button>` : ''}</div>`), { wide: true, label: 'Website safety result' });
  const el = m.el, ok = $('#ov-ok', el), go = $('#ov-go', el);
  $('#fa-close', el).onclick = () => m.close();
  if (ok) { ok.onchange = () => { go.disabled = !ok.checked; }; go.onclick = () => { log('autofill-override', `Override: user proceeded on ${a.hostname} for "${e.name}" after warning`, 'warn'); $('#fill-actions', el).classList.remove('hidden'); $('#override-box', el).classList.add('hidden'); go.classList.add('hidden'); toast('Warning acknowledged. Proceed with care.', 'warn'); }; }
  const clear = S.data.settings.clipboardClearSeconds;
  $('#fa-user', el).onclick = async () => { if (await copyText(e.username || e.email, { label: 'Username copied' })) { touchUsed(e.id); log('username-copied', `Copied username for "${e.name}" on ${a.hostname}`); } };
  $('#fa-pw', el).onclick = async () => { if (await copyText(e.password, { sensitive: true, clearAfter: clear, label: 'Password copied' })) { touchUsed(e.id); log('password-copied', `Copied password for "${e.name}" on ${a.hostname}`); } };
  $('#fa-fill', el).onclick = () => { m.close(); showDemoForm(e, a); };
}

function showDemoForm(e, a) {
  const m = openModal(String(html`
    <div class="modal-head"><h3>Autofill simulation</h3></div>
    <div class="modal-body">
      <div class="fake-page"><div class="fake-bar">${icon('lock', 14)}<span class="url">${a.https ? 'https' : 'http'}://${a.hostname}/login</span></div>
        <div class="fake-body"><label for="fp-u">Username or email</label><input id="fp-u" readonly><label for="fp-p">Password</label><input id="fp-p" type="password" readonly><button class="btn primary" type="button" tabindex="-1">Sign in (demo)</button></div></div>
      <p class="tiny muted mt-sm">Simulation only. A real browser extension would fill the actual page's login fields after the same verification, and only on a user click.</p>
    </div><div class="modal-foot"><button class="btn primary" id="fp-done">Close</button></div>`), { label: 'Autofill simulation' });
  $('#fp-u', m.el).value = e.username || e.email; $('#fp-p', m.el).value = e.password;
  $('#fp-done', m.el).onclick = () => { $('#fp-p', m.el).value = ''; m.close(); };
  touchUsed(e.id); log('autofill-completed', `Demo autofill for "${e.name}" on ${a.hostname}`, 'success');
}
