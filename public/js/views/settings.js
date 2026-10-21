import { S, log, commit, whenSaved, DEFAULT_SETTINGS, deviceInfo, enableSync, syncNow, loadApiStatus, normalizeData, LS_ENV } from '../state.js';
import { html, icon, $, toast, confirmDialog, copyText, downloadFile, openModal, fmtDateTime, timeAgo } from '../util.js';
import { registerView, registerActions, ui, rerender } from '../router.js';
import * as C from '../crypto.js';
import { analyzePassword } from '../strength.js';
import { applyTheme } from '../app.js';
import { biometricSupported, registerBiometric } from '../biometric.js';
import { showRecoveryKey } from '../auth.js';

const SECTIONS = [['appearance', 'Appearance'], ['security', 'Security'], ['generator', 'Generator'], ['privacy', 'Privacy'], ['notifications', 'Notifications'], ['sync', 'Cloud sync'], ['sessions', 'Sessions'], ['data', 'Export & recovery']];
let bioOk = null;

const sw = (path, on) => html`<label class="switch"><input type="checkbox" data-change="set-bool" data-path="${path}" ${on ? 'checked' : ''}><i></i></label>`;
const row = (t, d, ctl) => html`<div class="setting"><div><div class="t">${t}</div><div class="d">${d}</div></div>${ctl}</div>`;
const setPath = (obj, path, v) => { const k = path.split('.'); let o = obj; while (k.length > 1) o = o[k.shift()]; o[k[0]] = v; };

function section(id) {
  const s = S.data.settings, sy = s.sync;
  if (id === 'appearance') return html`<div class="card"><h3>Appearance</h3>${row('Theme', 'Saved with your vault.', html`<select data-change="set-theme" aria-label="Theme">${['dark', 'light', 'system'].map(t => html`<option value="${t}" ${s.theme === t ? 'selected' : ''}>${t[0].toUpperCase() + t.slice(1)}</option>`)}</select>`)}</div>`;
  if (id === 'security') return html`<div class="card"><h3>Vault protection</h3>
    ${row('Auto-lock', 'Lock after inactivity.', html`<select data-change="set-num" data-path="autoLockMinutes" aria-label="Auto-lock">${[[1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [0, 'Never']].map(([v, l]) => html`<option value="${v}" ${s.autoLockMinutes === v ? 'selected' : ''}>${l}</option>`)}</select>`)}
    ${row('Clipboard clearing', 'Clear copied passwords after a delay. Browsers may block this when the tab is not focused.', html`<select data-change="set-num" data-path="clipboardClearSeconds" aria-label="Clipboard clearing">${[[0, 'Off'], [15, '15 seconds'], [30, '30 seconds'], [60, '1 minute']].map(([v, l]) => html`<option value="${v}" ${s.clipboardClearSeconds === v ? 'selected' : ''}>${l}</option>`)}</select>`)}
    ${row('Old password threshold', 'Flag passwords unchanged for this long.', html`<select data-change="set-num" data-path="oldDays" aria-label="Old password threshold">${[90, 180, 365].map(v => html`<option value="${v}" ${s.oldDays === v ? 'selected' : ''}>${v} days</option>`)}</select>`)}
    ${row('Two-factor authentication (TOTP)', s.totp.enabled ? 'On: a 6-digit code is required after the master password. Local second step; see README limits.' : 'Add an authenticator-app code to unlocking. Local second step, not server-verified.', html`<button class="btn sm ${s.totp.enabled ? '' : 'primary'}" data-action="${s.totp.enabled ? 'totp-off' : 'totp-on'}">${s.totp.enabled ? 'Disable' : 'Set up'}</button>`)}
    ${row('Biometric / device unlock', bioOk === false ? 'Not supported in this browser or context (needs HTTPS or localhost and a platform authenticator).' : (s.biometric.enabled ? 'On: your device’s unlock (Windows Hello, Touch ID…) is asked after the master password. This is a convenience gate and does not replace the master password or protect the encryption key.' : 'Ask for device verification after the master password.'), html`<button class="btn sm" data-action="bio-toggle" ${bioOk === false ? 'disabled' : ''}>${s.biometric.enabled ? 'Disable' : 'Enable'}</button>`)}
    ${row('Change master password', 'Re-wraps your encryption key; entries are not re-uploaded.', html`<button class="btn sm" data-action="change-master">Change</button>`)}
    ${row('Recovery key', 'Generate a new offline recovery key. The old one stops working.', html`<button class="btn sm" data-action="new-recovery">Generate new</button>`)}</div>`;
  if (id === 'generator') return html`<div class="card"><h3>Generator defaults</h3>
    ${row('Length', 'Default password length.', html`<select data-change="set-num" data-path="gen.length" aria-label="Default length">${[12, 16, 20, 24, 32, 48].map(v => html`<option ${s.gen.length === v ? 'selected' : ''}>${v}</option>`)}</select>`)}
    ${[['gen.upper', 'Uppercase'], ['gen.lower', 'Lowercase'], ['gen.digits', 'Numbers'], ['gen.symbols', 'Symbols'], ['gen.noAmbiguous', 'Exclude ambiguous characters']].map(([p, l]) => row(l, '', sw(p, p.split('.').reduce((o, k) => o[k], s))))}</div>`;
  if (id === 'privacy') return html`<div class="card"><h3>Privacy</h3>
    ${row('Threat-intelligence checks', 'Send only a site’s origin (no path, no passwords) to your server’s reputation provider, if configured.', sw('privacy.useThreatIntel', s.privacy.useThreatIntel))}
    ${row('Breach range lookups', 'k-anonymity: only a 5-character hash prefix leaves your device.', sw('privacy.useBreachRange', s.privacy.useBreachRange))}
    ${row('Record scan history', 'Keep hostnames of scanned sites (never paths or queries).', sw('privacy.recordScanHistory', s.privacy.recordScanHistory))}</div>`;
  if (id === 'notifications') return html`<div class="card"><h3>Security notifications</h3><p class="small muted">In-app notices only (no push or email in this prototype).</p>
    ${row('Suspicious website alerts', 'Show a toast when a lookalike is detected.', sw('notifications.suspicious', s.notifications.suspicious))}
    ${row('Breach alerts', 'Show a toast when a breach check finds exposed passwords.', sw('notifications.breach', s.notifications.breach))}
    ${row('Old password reminders', 'Flag old passwords in Guardian.', sw('notifications.old', s.notifications.old))}</div>`;
  if (id === 'sync') {
    const dev = deviceInfo();
    return html`<div class="card"><h3>Encrypted cloud sync</h3>
      <div class="note-banner mb">${icon('info', 16)}<div>Your vault is encrypted in this browser (AES-256-GCM) before upload. The included server stores only that ciphertext and cannot read it. It is a local/self-hosted prototype: there is no account system, so access is gated by a random sync token. Metadata like vault size and timing is visible to the server.</div></div>
      ${row('Sync status', sy.enabled ? ({ ok: 'Up to date', syncing: 'Syncing…', idle: 'Pending', error: 'Error: ' + sy.error, conflict: 'Conflict: another device uploaded newer changes' })[sy.status] || sy.status : 'Off. This vault stays only in this browser.', html`${sy.enabled ? html`<span class="badge ${sy.status === 'ok' ? 'good' : sy.status === 'error' || sy.status === 'conflict' ? 'bad' : 'info'}">${sy.status}</span>` : html`<button class="btn sm primary" data-action="sync-enable">Enable</button>`}`)}
      ${sy.enabled ? html`${row('Last synchronisation', sy.lastSync ? fmtDateTime(sy.lastSync) + ' · server version ' + sy.version : 'Never', html`<button class="btn sm" data-action="sync-now" ${sy.status === 'syncing' ? 'disabled' : ''}>${icon('refresh', 14)} Sync now</button>`)}
        ${sy.status === 'conflict' ? html`<div class="note-banner warn mt-sm">${icon('alert', 16)}<div>The server has a newer version (v${sy.conflict?.serverVersion}). Choose which copy wins. <div class="row mt-sm wrap"><button class="btn sm" data-action="sync-take-server">Use server copy (lock &amp; reconnect)</button><button class="btn sm warn" data-action="sync-force">Overwrite server with this device</button></div></div></div>` : ''}
        <div class="setting"><div><div class="t">Connect another device</div><div class="d">On the other device choose “Connect synced vault” on the lock screen and enter these.</div></div></div>
        <div class="code">Vault ID: ${S.env.vaultId}<br>Token: <span id="tok">••••••••••••••••</span> <button class="btn sm" data-action="tok-show">Show</button> <button class="btn sm" data-action="tok-copy">Copy</button></div>
        <h4 class="mt">Devices</h4>${(sy.devices.length ? sy.devices : [{ id: dev.id, name: dev.name, lastSeen: sy.lastSync }]).map(d => html`<div class="row small" style="padding:7px 0">${icon('panel', 16)}<span class="grow">${d.name} ${d.id === dev.id ? html`<span class="badge purple">this device</span>` : ''}</span><span class="faint tiny">${d.lastSeen ? timeAgo(d.lastSeen) : '—'}</span></div>`)}
        <div class="mt"><button class="btn sm danger" data-action="sync-off">Turn off sync</button></div>` : ''}</div>`;
  }
  if (id === 'sessions') return html`<div class="card"><h3>Session</h3>${row('This session', `Unlocked ${timeAgo(S.sessionStart)} on ${deviceInfo().name}`, html`<button class="btn sm" data-action="lock-now">Lock now</button>`)}
    ${row('Server integrations', 'Detected from your NexiVault server.', html`<span class="small muted">${S.api ? `Threat intel: ${S.api.threatIntel.configured ? 'on' : 'off'} · Breach range: ${S.api.breachRange.enabled ? 'on' : 'off'}` : 'Server unreachable'}</span>`)}
    <p class="tiny faint mt">Sessions exist only in this browser tab; closing it or locking discards the decrypted vault from memory.</p></div>`;
  return html`<div class="card"><h3>Export & recovery</h3>
    ${row('Encrypted backup', 'Download the encrypted vault file. Needs your master password or recovery key to open.', html`<button class="btn sm" data-action="export-enc">${icon('download', 14)} Download</button>`)}
    ${row('Plain-text export (CSV)', 'Contains all passwords unencrypted. Handle and delete with care.', html`<button class="btn sm" data-action="export-csv">${icon('download', 14)} Export CSV</button>`)}
    ${row('Import encrypted backup', 'Replaces this device’s vault with a backup file.', html`<button class="btn sm" data-action="import-enc">${icon('upload', 14)} Import</button>`)}
    <input type="file" id="imp-file" accept=".json,application/json" class="hidden">
    ${row('Erase vault on this device', 'Permanently deletes the local encrypted vault.', html`<button class="btn sm danger" data-action="erase">Erase</button>`)}</div>`;
}

registerView('settings', {
  title: 'Settings',
  render(el, params) {
    if (params.section) ui.settingsSection = params.section;
    if (bioOk === null) biometricSupported().then(v => { bioOk = v; if (S.view === 'settings' && !v) rerender(); });
    el.innerHTML = html`<div class="page-head"><div><h2>Settings</h2><p>Changes apply immediately and are saved with your encrypted vault.</p></div></div>
      <div class="tabs" role="tablist">${SECTIONS.map(([id, l]) => html`<button class="tab ${ui.settingsSection === id ? 'active' : ''}" role="tab" data-action="set-section" data-s="${id}">${l}</button>`)}</div>${section(ui.settingsSection)}`.s;
  }
});

const changed = (what) => { log('settings-changed', what); };
async function newMasterDialog(title, withCurrent = true) {
  return new Promise((resolve) => {
    const m = openModal(String(html`<div class="modal-head"><h3>${title}</h3></div><form id="mp" novalidate><div class="modal-body">
      <label class="field"><span>Current master password</span><input id="mp-old" type="password" autocomplete="current-password" autofocus></label>
      <label class="field"><span>New master password</span><input id="mp-new" type="password" autocomplete="new-password"></label>
      <label class="field"><span>Confirm new password</span><input id="mp-new2" type="password" autocomplete="new-password"></label><div class="err" id="mp-err" role="alert"></div></div>
      <div class="modal-foot"><button class="btn ghost" type="button" id="mp-x">Cancel</button><button class="btn primary" type="submit">Change password</button></div></form>`), { label: title, onClose: () => resolve(null) });
    $('#mp-x', m.el).onclick = () => m.close();
    $('#mp', m.el).addEventListener('submit', async (e) => {
      e.preventDefault(); const err = $('#mp-err', m.el), np = $('#mp-new', m.el).value;
      if (!(await C.verifyMaster(S.env, $('#mp-old', m.el).value))) return err.textContent = 'Current master password is incorrect.';
      if (np.length < 10 || analyzePassword(np).rating === 'Weak') return err.textContent = 'Choose a stronger password (10+ characters).';
      if (np !== $('#mp-new2', m.el).value) return err.textContent = 'Passwords do not match.';
      m.closed = true; m.overlay.remove(); resolve(np);
    });
  });
}

registerActions({
  'set-section': (el) => { ui.settingsSection = el.dataset.s; rerender(); },
  'set-theme': (el) => { S.data.settings.theme = el.value; applyTheme(el.value); changed('Theme set to ' + el.value); },
  'set-num': (el) => { setPath(S.data.settings, el.dataset.path, Number(el.value)); changed('Changed setting: ' + el.dataset.path); },
  'set-bool': (el) => { setPath(S.data.settings, el.dataset.path, el.checked); changed('Changed setting: ' + el.dataset.path); },
  'totp-on': () => {
    const secret = C.newTotpSecret(), uri = `otpauth://totp/NexiVault:${encodeURIComponent(S.data.profile.name)}?secret=${secret}&issuer=NexiVault&digits=6&period=30`;
    const m = openModal(String(html`<div class="modal-head"><h3>Set up two-factor</h3></div><form id="tf" novalidate><div class="modal-body"><p class="small muted">Add this key to an authenticator app (Google Authenticator, Authy, 1Password…) as a time-based account, then enter the 6-digit code to confirm.</p>
      <div class="code mt-sm">${secret.match(/.{1,4}/g).join(' ')}</div><div class="row mt-sm"><button class="btn sm" type="button" id="tf-copy">Copy key</button><button class="btn sm" type="button" id="tf-uri">Copy otpauth link</button></div>
      <label class="field mt"><span>6-digit code</span><input id="tf-code" inputmode="numeric" maxlength="7" autocomplete="off" autofocus></label><div class="err" id="tf-err" role="alert"></div></div>
      <div class="modal-foot"><button class="btn ghost" type="button" id="tf-x">Cancel</button><button class="btn primary" type="submit">Verify &amp; enable</button></div></form>`), { label: 'Set up two-factor' });
    $('#tf-x', m.el).onclick = () => m.close(); $('#tf-copy', m.el).onclick = () => copyText(secret, { label: 'Key copied' }); $('#tf-uri', m.el).onclick = () => copyText(uri, { label: 'Link copied' });
    $('#tf', m.el).addEventListener('submit', async (e) => { e.preventDefault(); if (!(await C.verifyTotp(secret, $('#tf-code', m.el).value))) return $('#tf-err', m.el).textContent = 'Code did not match. Check your device clock.'; S.data.settings.totp = { enabled: true, secret }; changed('Two-factor authentication enabled'); toast('Two-factor enabled.', 'success'); m.close(); rerender(); });
  },
  'totp-off': async () => { if (await confirmDialog({ title: 'Disable two-factor?', message: 'Only your master password will be needed to unlock.', confirmText: 'Disable', danger: true })) { S.data.settings.totp = { enabled: false, secret: null }; changed('Two-factor authentication disabled'); rerender(); } },
  'bio-toggle': async () => {
    const b = S.data.settings.biometric;
    if (b.enabled) { S.data.settings.biometric = { enabled: false, credId: null }; changed('Device unlock disabled'); return rerender(); }
    try { const id = await registerBiometric(S.data.profile.name); S.data.settings.biometric = { enabled: true, credId: id }; changed('Device unlock enabled'); toast('Device unlock enabled.', 'success'); }
    catch { toast('Device verification was cancelled or is not available.', 'error'); }
    rerender();
  },
  'change-master': async () => {
    const np = await newMasterDialog('Change master password'); if (!np) return;
    const { envelope } = await C.rewrapMaster(S.env, S.session, np); S.env = envelope; localStorage.setItem(LS_ENV, JSON.stringify(envelope));
    changed('Master password changed'); await commit(); toast('Master password changed.', 'success');
  },
  'new-recovery': async () => {
    if (!(await confirmDialog({ title: 'Generate a new recovery key?', message: 'The previous recovery key will stop working.', confirmText: 'Generate' }))) return;
    let pw; try { pw = await askCurrent(); } catch { return; }
    const { envelope, recoveryKey } = await C.rewrapMaster(S.env, S.session, pw, { newRecovery: true });
    S.env = envelope; localStorage.setItem(LS_ENV, JSON.stringify(envelope));
    showRecoveryKey(recoveryKey, () => { S.data.settings.recoveryAcknowledged = true; changed('Recovery key regenerated'); commit(); rerender(); }, 'Your new recovery key');
  },
  'sync-enable': async () => { const r = await enableSync(); toast(r.ok ? 'Encrypted sync enabled.' : 'Sync could not start: ' + (r.error || 'unknown error'), r.ok ? 'success' : 'error'); rerender(); },
  'sync-now': async () => { const r = await syncNow(); toast(r.ok ? 'Synced.' : r.conflict ? 'Conflict detected.' : 'Sync failed: ' + r.error, r.ok ? 'success' : 'error'); rerender(); },
  'sync-force': async () => { if (await confirmDialog({ title: 'Overwrite server copy?', message: 'Changes made on the other device that are not in this vault will be lost.', confirmText: 'Overwrite', danger: true })) { S.data.settings.sync.status = 'idle'; const r = await syncNow({ force: true }); toast(r.ok ? 'Server updated.' : 'Failed: ' + r.error, r.ok ? 'success' : 'error'); rerender(); } },
  'sync-take-server': async () => { toast('Locking. Use “Connect synced vault” to load the server copy.', 'info'); const { lock } = await import('../state.js'); S.data.settings.sync = { ...S.data.settings.sync }; await lock('Locked to adopt server copy'); },
  'sync-off': async () => { if (await confirmDialog({ title: 'Turn off sync?', message: 'This device stops uploading. The server copy is not deleted.', confirmText: 'Turn off', danger: true })) { Object.assign(S.data.settings.sync, { enabled: false, status: 'off', token: null }); changed('Sync turned off'); rerender(); } },
  'tok-show': (el) => { const t = $('#tok'); const on = t.dataset.on === '1'; t.textContent = on ? '••••••••••••••••' : S.data.settings.sync.token; t.dataset.on = on ? '0' : '1'; el.textContent = on ? 'Show' : 'Hide'; },
  'tok-copy': () => copyText(S.data.settings.sync.token, { sensitive: true, clearAfter: 30, label: 'Token copied' }),
  'export-enc': async () => { await whenSaved(); downloadFile('nexivault-encrypted-backup.json', JSON.stringify(S.env), 'application/json'); changed('Encrypted backup exported'); },
  'export-csv': async () => {
    if (!(await confirmDialog({ title: 'Export passwords as plain text?', message: 'The CSV file will contain every password unencrypted. Anyone who gets the file can read them.', confirmText: 'Export', danger: true }))) return;
    const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`.replace(/^"([=+\-@])/, '"\'$1');
    downloadFile('nexivault-export.csv', ['name,url,username,email,password,category,notes', ...S.data.entries.map(e => [e.name, e.url, e.username, e.email, e.password, e.category, e.notes].map(q).join(','))].join('\n'), 'text/csv');
    changed('Plain-text CSV export created');
  },
  'import-enc': () => { const f = $('#imp-file'); f.onchange = async () => {
    const file = f.files[0]; if (!file) return;
    try {
      const env = JSON.parse(await file.text()); if (!env.vaultId || !env.data?.ct || !env.wrapM) throw new Error();
      if (!(await confirmDialog({ title: 'Replace this vault?', message: 'The current local vault will be replaced by the backup and the app will lock.', confirmText: 'Replace', danger: true }))) return;
      localStorage.setItem(LS_ENV, JSON.stringify(env)); const { lock } = await import('../state.js'); S.data.settings.sync.enabled = false; await lock('Vault replaced from backup');
    } catch { toast('That file is not a valid NexiVault backup.', 'error'); }
  }; f.click(); },
  erase: async () => { if (await confirmDialog({ title: 'Erase vault on this device?', message: 'Without a backup or synced copy, everything is lost.', confirmText: 'Erase', danger: true, requireText: 'ERASE' })) { localStorage.removeItem(LS_ENV); location.reload(); } }
});

function askCurrent() {
  return new Promise((resolve, reject) => {
    const m = openModal(String(html`<div class="modal-head"><h3>Confirm master password</h3></div><form id="cm" novalidate><div class="modal-body"><label class="field"><span>Master password</span><input id="cm-pw" type="password" autofocus></label><div class="err" id="cm-err" role="alert"></div></div><div class="modal-foot"><button class="btn ghost" type="button" id="cm-x">Cancel</button><button class="btn primary" type="submit">Confirm</button></div></form>`), { label: 'Confirm master password', onClose: () => reject(new Error('cancel')) });
    $('#cm-x', m.el).onclick = () => m.close();
    $('#cm', m.el).addEventListener('submit', async (e) => { e.preventDefault(); const pw = $('#cm-pw', m.el).value; if (!(await C.verifyMaster(S.env, pw))) return $('#cm-err', m.el).textContent = 'Incorrect master password.'; m.closed = true; m.overlay.remove(); resolve(pw); });
  });
}
