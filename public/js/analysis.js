// Vault analysis: all numbers are computed from the real vault contents.
// Each check carries a `source`: 'verified' (computed locally from your data), 'live' (external service answered),
// 'not-run' (never executed), or 'unavailable'. Nothing here invents results.
import { analyzePassword, reuseMap } from './strength.js';
import { parseUrl } from './domain.js';

const DAY = 86400000;

export function analyze(data) {
  const entries = data.entries;
  const reuse = reuseMap(entries);
  const oldMs = data.settings.oldDays * DAY;
  const now = Date.now();
  const per = {};
  let strong = 0, medium = 0, weak = 0, reused = 0, old = 0, exposed = 0, noUrl = 0, httpUrl = 0;
  for (const e of entries) {
    const intrinsic = analyzePassword(e.password);
    const ex = data.breach.results[e.id]?.count;
    const full = analyzePassword(e.password, { reusedCount: reuse[e.id], exposedCount: ex ?? null });
    const isOld = now - Date.parse(e.passwordChangedAt || e.updatedAt || e.createdAt) > oldMs;
    const parsed = e.url ? parseUrl(e.url) : null;
    const flags = { reused: reuse[e.id] > 0, old: isOld, exposed: ex > 0, noUrl: !e.url, httpUrl: !!(parsed?.ok && !parsed.https), badUrl: !!(e.url && !parsed?.ok) };
    per[e.id] = { intrinsic, full, ...flags, reusedCount: reuse[e.id] };
    if (intrinsic.rating === 'Strong') strong++; else if (intrinsic.rating === 'Medium') medium++; else weak++;
    if (flags.reused) reused++; if (isOld) old++; if (flags.exposed) exposed++; if (flags.noUrl) noUrl++; if (flags.httpUrl) httpUrl++;
  }
  const total = entries.length;
  const unique = new Set(entries.map(e => e.password)).size;
  const reusedAccounts = reused; // accounts sharing a password with another account
  const breachChecked = entries.filter(e => data.breach.results[e.id]).length;
  const breachLive = data.breach.mode === 'live' && total > 0 && breachChecked === total;
  const recent = data.activity.filter(a => now - Date.parse(a.ts) < 30 * DAY);
  const siteWarnings = recent.filter(a => a.type === 'suspicious-domain' || a.type === 'autofill-blocked').length + httpUrl;
  const totp = data.settings.totp.enabled;

  // Score: weighted; components that were never verified are excluded and shown as "Not checked".
  const parts = [];
  if (total) {
    parts.push({ key: 'strength', w: 35, v: (strong + medium * 0.5) / total });
    parts.push({ key: 'unique', w: 25, v: unique / total });
    parts.push({ key: 'fresh', w: 10, v: 1 - old / total });
  }
  parts.push({ key: '2fa', w: 15, v: totp ? 1 : 0 });
  if (breachLive) parts.push({ key: 'breach', w: 15, v: 1 - exposed / total });
  const wsum = parts.reduce((a, p) => a + p.w, 0);
  const score = total ? Math.round(parts.reduce((a, p) => a + p.w * p.v, 0) / wsum * 100) : null;
  const grade = score == null ? 'No data' : score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 50 ? 'Fair' : 'At risk';

  const checks = [
    { key: 'strong', label: 'Strong passwords', value: total ? `${strong}/${total}` : '—', status: total && strong === total ? 'ok' : strong / (total || 1) >= 0.6 ? 'warn' : 'bad', source: 'verified' },
    { key: 'unique', label: 'Unique passwords', value: total ? `${unique}/${total}` : '—', status: unique === total ? 'ok' : 'warn', source: 'verified' },
    { key: 'breach', label: 'No data breaches', value: data.breach.mode === 'live' ? (breachChecked ? (exposed ? `${exposed} exposed` : 'None found') : 'Not checked') : data.breach.mode === 'unavailable' ? 'Unavailable' : 'Not checked', status: data.breach.mode === 'live' ? (exposed ? 'bad' : 'ok') : 'unverified', source: data.breach.mode === 'live' ? 'live' : data.breach.mode === 'unavailable' ? 'unavailable' : 'not-run' },
    { key: '2fa', label: '2FA enabled', value: totp ? 'Yes' : 'No', status: totp ? 'ok' : 'warn', source: 'verified' }
  ];
  return { total, strong, medium, weak, reused: reusedAccounts, unique, old, exposed, noUrl, httpUrl, siteWarnings, breachChecked, breachLive, totp, score, grade, checks, per };
}

export const SOURCE_LABEL = { verified: 'Verified locally', live: 'Live check', 'not-run': 'Not checked', unavailable: 'Unavailable', demo: 'Demo' };

/** Findings used by the dashboard, Guardian and Privacy scanner. Each has a working navigation target. */
export function buildFindings(data, an) {
  const f = [];
  const names = (pred) => data.entries.filter(e => pred(an.per[e.id])).map(e => e.name);
  const list = (arr) => arr.slice(0, 3).join(', ') + (arr.length > 3 ? ` +${arr.length - 3} more` : '');
  const add = (o) => f.push({ category: 'passwords', ...o });

  if (!an.total) add({ id: 'empty', risk: 'low', title: 'Your vault is empty', text: 'Add your first password to start tracking your security.', action: { label: 'Add password', view: 'passwords', params: { add: true } } });
  if (an.exposed) add({ id: 'exposed', risk: 'high', category: 'exposure', title: `${an.exposed} password${an.exposed > 1 ? 's' : ''} found in known breaches`, text: `${list(names(p => p.exposed))}: these passwords are public knowledge. Change them now.`, action: { label: 'Review exposed', view: 'passwords', params: { filter: 'exposed' } } });
  if (an.reused) add({ id: 'reused', risk: 'high', title: `${an.reused} password${an.reused > 1 ? 's' : ''} reused across accounts`, text: `${list(names(p => p.reused))} share a password with another account. One breach could unlock several accounts.`, action: { label: 'Review reused', view: 'passwords', params: { filter: 'reused' } } });
  if (an.weak) add({ id: 'weak', risk: 'high', title: `Review ${an.weak} weak password${an.weak > 1 ? 's' : ''}`, text: `${list(names(p => p.intrinsic.rating === 'Weak'))}: easy to guess. Replace with generated passwords.`, action: { label: 'Review weak', view: 'passwords', params: { filter: 'weak' } } });
  if (an.old) add({ id: 'old', risk: 'medium', title: `${an.old} password${an.old > 1 ? 's' : ''} not changed in ${data.settings.oldDays}+ days`, text: `${list(names(p => p.old))}. Rotate important accounts periodically.`, action: { label: 'Review old', view: 'passwords', params: { filter: 'old' } } });
  if (!an.totp) add({ id: '2fa', risk: 'medium', category: 'protection', title: 'Enable stronger account protection', text: 'Turn on two-factor authentication for NexiVault so a stolen master password is not enough.', action: { label: 'Set up 2FA', view: 'settings', params: { section: 'security' } } });
  if (an.breachChecked < an.total || data.breach.mode !== 'live') add({ id: 'breach-unchecked', risk: 'low', category: 'exposure', title: 'Check potentially exposed credentials', text: data.breach.mode === 'unavailable' ? 'The last breach check could not reach the service. Try again when online.' : 'Your passwords have not been checked against known breaches yet. Only a 5-character hash prefix leaves your device.', action: { label: 'Run breach check', view: 'security', params: { tab: 'breach' } } });
  if (an.httpUrl) add({ id: 'http', risk: 'medium', category: 'websites', title: `${an.httpUrl} saved site${an.httpUrl > 1 ? 's use' : ' uses'} unencrypted http://`, text: `${list(data.entries.filter(e => an.per[e.id].httpUrl).map(e => e.name))}. Autofill will be flagged on these.`, action: { label: 'Fix site addresses', view: 'passwords', params: { filter: 'all' } } });
  if (an.noUrl) add({ id: 'no-url', risk: 'low', category: 'websites', title: `${an.noUrl} login${an.noUrl > 1 ? 's have' : ' has'} no website saved`, text: 'Without a saved domain NexiVault cannot verify a destination before autofill; results show as Unverified.', action: { label: 'Add websites', view: 'passwords', params: { filter: 'all' } } });
  const blocked = data.activity.filter(a => (a.type === 'autofill-blocked' || a.type === 'suspicious-domain') && Date.now() - Date.parse(a.ts) < 30 * DAY);
  if (blocked.length) add({ id: 'blocked', risk: 'medium', category: 'websites', title: `${blocked.length} suspicious website event${blocked.length > 1 ? 's' : ''} in the last 30 days`, text: 'NexiVault blocked or flagged autofill on lookalike or unverified destinations. Review what happened.', action: { label: 'Open activity', view: 'timeline', params: { filter: 'autofill' } } });
  const s = data.settings;
  if (s.autoLockMinutes === 0 || s.autoLockMinutes > 15) add({ id: 'autolock', risk: 'medium', category: 'protection', title: 'Auto-lock is long or off', text: 'Lock the vault after a short idle period (15 minutes or less) in case you step away.', action: { label: 'Open settings', view: 'settings', params: { section: 'security' } } });
  if (!s.clipboardClearSeconds) add({ id: 'clipboard', risk: 'low', category: 'protection', title: 'Clipboard clearing is off', text: 'Copied passwords stay on the clipboard until replaced. Enable automatic clearing.', action: { label: 'Open settings', view: 'settings', params: { section: 'security' } } });
  if (!s.recoveryAcknowledged) add({ id: 'recovery', risk: 'medium', category: 'protection', title: 'Recovery key not confirmed', text: 'Without your recovery key or master password your vault cannot be opened. Generate a new key and store it offline.', action: { label: 'Manage recovery', view: 'settings', params: { section: 'security' } } });
  // external integrations (honesty about what is unverified)
  return f;
}

/** Privacy risk scanner: severities and categories, only from facts available in the vault/config. */
export function privacyFindings(data, an, api) {
  const out = [];
  const add = (severity, title, text, action) => out.push({ severity, title, text, action });
  if (an.weak) add('high', 'Weak passwords in use', `${an.weak} account(s) use passwords that are easy to guess.`, { label: 'Review', view: 'passwords', params: { filter: 'weak' } });
  if (an.reused) add('high', 'Reused passwords', `${an.reused} account(s) share a password with another account.`, { label: 'Review', view: 'passwords', params: { filter: 'reused' } });
  if (an.exposed) add('high', 'Passwords found in breaches', `${an.exposed} password(s) appear in a public breach corpus.`, { label: 'Review', view: 'passwords', params: { filter: 'exposed' } });
  if (!an.totp) add('medium', 'No second factor on the vault', 'Only the master password protects the vault.', { label: 'Set up 2FA', view: 'settings', params: { section: 'security' } });
  const sens = data.entries.filter(e => /\b(\d[ -]?){12,19}\b|\b(ssn|aadhaar|passport|cvv|pin)\b/i.test(e.notes || ''));
  if (sens.length) add('medium', 'Notes may hold sensitive identifiers', `Heuristic match in notes of: ${sens.slice(0, 3).map(e => e.name).join(', ')}. Consider moving identifiers to Secure Notes or removing them.`, { label: 'Open vault', view: 'passwords', params: { filter: 'all' } });
  if (an.httpUrl) add('medium', 'Unencrypted website addresses saved', `${an.httpUrl} saved site(s) use http://.`, { label: 'Review', view: 'passwords', params: { filter: 'all' } });
  if (an.noUrl) add('low', 'Logins without a saved domain', 'Autofill safety checks cannot verify these destinations.', { label: 'Review', view: 'passwords', params: { filter: 'all' } });
  const blocked = data.activity.filter(a => a.type === 'autofill-blocked' || a.type === 'suspicious-domain').length;
  if (blocked) add('medium', 'Suspicious destinations encountered', `${blocked} suspicious-site or blocked-autofill event(s) are in your activity log.`, { label: 'Open activity', view: 'timeline', params: { filter: 'autofill' } });
  const overrides = data.activity.filter(a => a.type === 'autofill-override').length;
  if (overrides) add('medium', 'Warnings overridden manually', `You proceeded past a safety warning ${overrides} time(s). Make sure those sites were verified.`, { label: 'Open activity', view: 'timeline', params: { filter: 'autofill' } });
  // integrations: what leaves the device
  add('info', 'Threat intelligence', api?.threatIntel?.configured ? `Enabled via ${api.threatIntel.provider}. Only the site origin (no path or query) is sent from your server.` : 'Not configured on the server. Website checks use local heuristics only.', { label: 'How it works', view: 'scanner' });
  add('info', 'Breach check privacy', data.settings.privacy.useBreachRange ? 'Uses a k-anonymity range lookup: only the first 5 characters of a SHA-1 hash leave your device (via your NexiVault server).' : 'Disabled in privacy settings.', { label: 'Privacy settings', view: 'settings', params: { section: 'privacy' } });
  add('info', 'Cloud sync', data.settings.sync.enabled ? 'Enabled: the vault is encrypted in your browser before upload, but the server learns metadata like size and timing.' : 'Off. Your vault never leaves this browser.', { label: 'Sync settings', view: 'settings', params: { section: 'sync' } });
  if (!out.some(o => o.severity === 'high' || o.severity === 'medium')) out.unshift({ severity: 'good', title: 'No privacy risks detected from available data', text: 'This reflects only what NexiVault can verify locally. It cannot see accounts outside this vault.', action: null });
  return out;
}
