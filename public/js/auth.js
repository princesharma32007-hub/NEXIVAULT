// Lock screen: first-run setup, unlock (+2FA/biometric gate), recovery-key reset, connect to a synced vault, erase.
import * as C from './crypto.js';
import { S, LS_ENV, LS_THEME, newData, normalizeData, setSession, loadEnvelope, log, fetchServerEnvelope, whenSaved, commit } from './state.js';
import { html, icon, $, toast, openModal, confirmDialog, copyText, downloadFile, uid } from './util.js';
import { analyzePassword, strengthClass } from './strength.js';
import { assertBiometric } from './biometric.js';

const DAY = 86400000;
const shell = (inner) => html`<div class="lock-screen"><div class="lock-card">
  <div class="brand"><span class="brand-mark">${icon('lock', 22)}</span><span>NexiVault</span></div>${inner}</div></div>`;

export function renderAuth() {
  const root = $('#root');
  const env = loadEnvelope();
  S.env = env;
  if (!env) return renderSetup(root);
  renderUnlock(root);
}

// ---------- sample data (clearly fake; offered only at setup) ----------
function sampleData(name) {
  const d = newData(name);
  const mk = (n, url, user, pw, cat, o = {}) => ({ id: uid(), name: n, username: user, email: o.email || '', password: pw, url, category: cat, tags: ['sample'], notes: 'Sample entry (fake data).', favorite: !!o.fav, createdAt: new Date(Date.now() - (o.age || 30) * DAY).toISOString(), updatedAt: new Date(Date.now() - (o.age || 30) * DAY).toISOString(), passwordChangedAt: new Date(Date.now() - (o.age || 30) * DAY).toISOString(), lastUsedAt: o.used || null, history: o.history || [] });
  d.entries.push(
    mk('GitHub', 'https://github.com', 'sartaj-dev', 'vK7#qLm2$Zt9!xRb4Wp', 'Developer', { fav: true, age: 240, used: new Date().toISOString() }),
    mk('PayPal', 'https://paypal.com', 'sample.user', 'Hq3!tRw8@Nc5yLd2Ge', 'Finance', { email: 'sample.user@example.com', age: 60, history: [{ password: 'OldPass#2023', changedAt: new Date(Date.now() - 120 * DAY).toISOString() }] }),
    mk('Google', 'https://accounts.google.com', 'sample.user', 'Bz9$mKp4#Vt7!wQa3Xs', 'Email', { email: 'sample.user@example.com', age: 45, fav: true }),
    mk('Amazon', 'https://amazon.in', 'sample.user', 'Tropical-Fjord-Lantern-92', 'Shopping', { age: 90 }),
    mk('Spotify', 'https://spotify.com', 'sample.user', 'Tropical-Fjord-Lantern-92', 'Entertainment', { age: 90 }),
    mk('Netflix', 'https://netflix.com', 'sample.user', 'netflix123', 'Entertainment', { age: 400 })
  );
  d.notes.push({ id: uid(), title: 'Welcome to NexiVault', body: 'This is a sample secure note. It is encrypted together with the rest of your vault. Delete the sample entries any time.', category: 'General', tags: ['sample'], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  return d;
}

function meterHtml(r) { return `<div class="meter mt-sm"><i class="${strengthClass(r.rating)}" style="width:${Math.max(4, r.score)}%"></i></div><div class="tiny muted mt-sm">${r.rating}${r.length < 10 ? ' · use at least 10 characters' : ''}${r.flags.length ? ' · ' + r.flags[0] : ''}</div>`; }

// ---------- setup ----------
function renderSetup(root) {
  root.innerHTML = shell(html`
    <h2>Create your vault</h2><p class="sub">Your master password never leaves this device and is never stored. Pick something long and unique.</p>
    <form id="setup" novalidate>
      <label class="field"><span>Your name</span><input id="s-name" autocomplete="given-name" maxlength="40" placeholder="e.g. Sartaj" autofocus></label>
      <label class="field"><span>Master password</span><input id="s-pw" type="password" autocomplete="new-password"><div id="s-meter"></div></label>
      <label class="field"><span>Confirm master password</span><input id="s-pw2" type="password" autocomplete="new-password"></label>
      <label class="check mt-sm"><input type="checkbox" id="s-sample" checked><span>Add sample (fake) entries so I can explore</span></label>
      <div class="err" id="s-err" role="alert"></div>
      <button class="btn primary block" type="submit" id="s-go">${icon('shieldcheck', 18)} Create vault</button>
    </form>
    <p class="tiny faint mt" style="text-align:center">Prototype notice: data is encrypted in this browser (PBKDF2 + AES-256-GCM). <button class="link-btn tiny" id="to-connect" type="button">Connect an existing synced vault</button></p>`).s;
  const pw = $('#s-pw');
  pw.addEventListener('input', () => { $('#s-meter').innerHTML = pw.value ? meterHtml(analyzePassword(pw.value)) : ''; });
  $('#to-connect').onclick = () => renderConnect(root);
  $('#setup').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = $('#s-name').value.trim(), p = pw.value, err = $('#s-err');
    err.textContent = '';
    if (!name) return err.textContent = 'Please enter your name.';
    if (p.length < 10) return err.textContent = 'Master password must be at least 10 characters.';
    if (analyzePassword(p).rating === 'Weak') return err.textContent = 'That password is too easy to guess. Try a longer passphrase of several unrelated words.';
    if (p !== $('#s-pw2').value) return err.textContent = 'Passwords do not match.';
    const btn = $('#s-go'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Creating…';
    const data = $('#s-sample').checked ? sampleData(name) : newData(name);
    const { envelope, session, recoveryKey } = await C.createVault(p, data);
    localStorage.setItem(LS_ENV, JSON.stringify(envelope));
    showRecoveryKey(recoveryKey, () => { data.settings.recoveryAcknowledged = true; setSession(envelope, session, data); log('vault-created', 'Vault created', 'success'); commit(); });
  });
}

export function showRecoveryKey(key, onDone, title = 'Save your recovery key') {
  const m = openModal(String(html`
    <div class="modal-head"><h3>${title}</h3></div>
    <div class="modal-body">
      <p class="muted small">If you forget your master password, this key is the <b>only</b> way back into your vault. NexiVault cannot recover it for you. Store it offline (print it or keep it in a safe place), not in this browser.</p>
      <div class="recovery-key mt">${key}</div>
      <div class="row mt"><button class="btn sm" id="rk-copy">${icon('copy', 15)} Copy</button><button class="btn sm" id="rk-dl">${icon('download', 15)} Download .txt</button></div>
      <label class="check mt"><input type="checkbox" id="rk-ok"><span>I have saved my recovery key somewhere safe</span></label>
    </div>
    <div class="modal-foot"><button class="btn primary" id="rk-done" disabled>Continue</button></div>`), { label: title, dismissible: false });
  $('#rk-ok', m.el).onchange = (e) => { $('#rk-done', m.el).disabled = !e.target.checked; };
  $('#rk-copy', m.el).onclick = () => copyText(key, { label: 'Recovery key copied' });
  $('#rk-dl', m.el).onclick = () => downloadFile('nexivault-recovery-key.txt', `NexiVault recovery key\n\n${key}\n\nKeep this file offline. Anyone with this key and your encrypted vault can open it.\n`, 'text/plain');
  $('#rk-done', m.el).onclick = () => { m.close(); onDone(); };
}

// ---------- unlock ----------
let fails = 0, lockedUntil = 0;
function renderUnlock(root) {
  root.innerHTML = shell(html`
    <h2>Welcome back</h2><p class="sub">Unlock your vault with your master password.</p>
    <form id="unlock" novalidate>
      <label class="field"><span>Master password</span><input id="u-pw" type="password" autocomplete="current-password" autofocus></label>
      <div class="err" id="u-err" role="alert"></div>
      <button class="btn primary block" type="submit" id="u-go">${icon('unlock', 18)} Unlock vault</button>
    </form>
    <div class="row between mt wrap"><button class="link-btn small" id="to-rec" type="button">Use recovery key</button><button class="link-btn small" id="to-connect" type="button">Connect synced vault</button><button class="link-btn small text-bad" id="to-erase" type="button">Erase vault</button></div>`).s;
  $('#to-rec').onclick = () => renderRecovery(root);
  $('#to-connect').onclick = () => renderConnect(root);
  $('#to-erase').onclick = async () => {
    if (await confirmDialog({ title: 'Erase this device’s vault?', message: 'This permanently deletes the encrypted vault stored in this browser. Without a synced copy or backup it cannot be recovered.', confirmText: 'Erase vault', danger: true, requireText: 'ERASE' })) { localStorage.removeItem(LS_ENV); localStorage.removeItem(LS_THEME); toast('Local vault erased.', 'warn'); renderAuth(); }
  };
  const form = $('#unlock'), err = $('#u-err'), btn = $('#u-go');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    const wait = Math.ceil((lockedUntil - Date.now()) / 1000);
    if (wait > 0) return err.textContent = `Too many attempts. Try again in ${wait}s.`;
    const pw = $('#u-pw').value; if (!pw) return err.textContent = 'Enter your master password.';
    btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Unlocking…';
    const res = await C.unlockWithMaster(S.env, pw);
    btn.disabled = false; btn.innerHTML = String(icon('unlock', 18)) + ' Unlock vault';
    if (!res) {
      fails++; if (fails >= 3) lockedUntil = Date.now() + Math.min(30, 2 ** (fails - 2)) * 1000;
      $('#u-pw').value = ''; $('#u-pw').focus();
      return err.textContent = 'Incorrect master password.' + (fails >= 3 ? ' Please wait before trying again.' : '');
    }
    fails = 0;
    await finishUnlock(root, S.env, res.session, normalizeData(res.data));
  });
}

async function finishUnlock(root, env, session, data) {
  if (data.settings.totp.enabled) {
    const ok = await totpGate(root, data.settings.totp.secret);
    if (!ok) return renderAuth();
  }
  if (data.settings.biometric.enabled && data.settings.biometric.credId) {
    try { await assertBiometric(data.settings.biometric.credId); }
    catch { toast('Device verification was cancelled or failed.', 'error'); return renderAuth(); }
  }
  setSession(env, session, data);
  log('vault-unlocked', 'Vault unlocked', 'success');
}

function totpGate(root, secret) {
  return new Promise((resolve) => {
    root.innerHTML = shell(html`<h2>Two-factor code</h2><p class="sub">Enter the 6-digit code from your authenticator app.</p>
      <form id="totp" novalidate><label class="field"><span>Authenticator code</span><input id="t-code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" autofocus></label>
      <div class="err" id="t-err" role="alert"></div><button class="btn primary block" type="submit">Verify</button></form>
      <div class="row mt" style="justify-content:center"><button class="link-btn small" id="t-cancel" type="button">Cancel</button></div>
      <p class="tiny faint mt" style="text-align:center">Local second step: it is checked in this browser after your master password decrypts the vault.</p>`).s;
    $('#t-cancel').onclick = () => resolve(false);
    $('#totp').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (await C.verifyTotp(secret, $('#t-code').value)) resolve(true);
      else { $('#t-err').textContent = 'That code is not valid. Check your device clock and try again.'; $('#t-code').select(); }
    });
  });
}

// ---------- recovery ----------
function renderRecovery(root) {
  root.innerHTML = shell(html`<h2>Reset with recovery key</h2><p class="sub">Enter your recovery key and choose a new master password.</p>
    <form id="rec" novalidate>
      <label class="field"><span>Recovery key</span><input id="r-key" class="mono" placeholder="XXXX-XXXX-XXXX-…" autocomplete="off" autofocus></label>
      <label class="field"><span>New master password</span><input id="r-pw" type="password" autocomplete="new-password"><div id="r-meter"></div></label>
      <label class="field"><span>Confirm new master password</span><input id="r-pw2" type="password" autocomplete="new-password"></label>
      <div class="err" id="r-err" role="alert"></div>
      <button class="btn primary block" type="submit" id="r-go">Reset and unlock</button></form>
    <div class="row mt" style="justify-content:center"><button class="link-btn small" id="back" type="button">Back</button></div>`).s;
  $('#back').onclick = () => renderAuth();
  $('#r-pw').addEventListener('input', (e) => { $('#r-meter').innerHTML = e.target.value ? meterHtml(analyzePassword(e.target.value)) : ''; });
  $('#rec').addEventListener('submit', async (e) => {
    e.preventDefault(); const err = $('#r-err'); err.textContent = '';
    const np = $('#r-pw').value;
    if (np.length < 10 || analyzePassword(np).rating === 'Weak') return err.textContent = 'Choose a stronger master password (10+ characters).';
    if (np !== $('#r-pw2').value) return err.textContent = 'Passwords do not match.';
    const btn = $('#r-go'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Working…';
    const res = await C.unlockWithRecovery(S.env, $('#r-key').value);
    if (!res) { btn.disabled = false; btn.textContent = 'Reset and unlock'; return err.textContent = 'That recovery key does not match this vault.'; }
    const { envelope, recoveryKey } = await C.rewrapMaster(S.env, res.session, np, { newRecovery: true });
    localStorage.setItem(LS_ENV, JSON.stringify(envelope));
    const data = normalizeData(res.data);
    showRecoveryKey(recoveryKey, () => { data.settings.recoveryAcknowledged = true; setSession(envelope, res.session, data); log('vault-unlocked', 'Vault unlocked with recovery key; master password changed', 'warn'); commit(); }, 'Your new recovery key');
  });
}

// ---------- connect to a synced vault ----------
function renderConnect(root) {
  root.innerHTML = shell(html`<h2>Connect a synced vault</h2><p class="sub">Download your encrypted vault from the NexiVault server, then unlock it with your master password. The server only ever holds ciphertext.</p>
    <form id="conn" novalidate>
      <label class="field"><span>Vault ID</span><input id="c-id" class="mono" autocomplete="off" autofocus></label>
      <label class="field"><span>Sync token</span><input id="c-token" type="password" class="mono" autocomplete="off"><span class="hint">Shown in Settings → Sync on the device that already has the vault.</span></label>
      <label class="field"><span>Master password</span><input id="c-pw" type="password" autocomplete="current-password"></label>
      <div class="err" id="c-err" role="alert"></div>
      <button class="btn primary block" type="submit" id="c-go">${icon('cloud', 18)} Connect</button></form>
    <div class="row mt" style="justify-content:center"><button class="link-btn small" id="back" type="button">Back</button></div>`).s;
  $('#back').onclick = () => renderAuth();
  $('#conn').addEventListener('submit', async (e) => {
    e.preventDefault(); const err = $('#c-err'); err.textContent = '';
    const id = $('#c-id').value.trim(), token = $('#c-token').value.trim(), pw = $('#c-pw').value;
    if (!id || !token || !pw) return err.textContent = 'Fill in all three fields.';
    if (S.env && !(await confirmDialog({ title: 'Replace local vault?', message: 'A vault already exists in this browser. Connecting will replace it with the synced copy.', confirmText: 'Replace', danger: true }))) return;
    const btn = $('#c-go'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Connecting…';
    try {
      const j = await fetchServerEnvelope(id, token);
      const res = await C.unlockWithMaster(j.envelope, pw);
      if (!res) throw new Error('Master password does not open that vault.');
      const data = normalizeData(res.data);
      data.settings.sync.enabled = true; data.settings.sync.token = token; data.settings.sync.version = j.version; data.settings.sync.lastSync = j.updatedAt; data.settings.sync.status = 'ok';
      const env = { ...j.envelope, serverVersion: j.version };
      localStorage.setItem(LS_ENV, JSON.stringify(env));
      setSession(env, res.session, data);
      log('vault-unlocked', 'Connected synced vault on this device', 'success');
    } catch (ex) { btn.disabled = false; btn.innerHTML = String(icon('cloud', 18)) + ' Connect'; err.textContent = ex.message === 'Failed to fetch' ? 'Cannot reach the NexiVault server.' : ex.message; }
  });
}
