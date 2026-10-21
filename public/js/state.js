// Central application state, persistence (encrypted), activity log, and vault mutations.
import * as C from './crypto.js';
import { uid, toast } from './util.js';
import { parseUrl } from './domain.js';

export const LS_ENV = 'nexivault.envelope';
export const LS_THEME = 'nexivault.theme';
export const LS_DEVICE = 'nexivault.device';

export const DEFAULT_SETTINGS = {
  theme: 'dark', autoLockMinutes: 5, clipboardClearSeconds: 30, oldDays: 180,
  gen: { length: 20, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: false, words: 5 },
  notifications: { suspicious: true, breach: true, old: true },
  privacy: { useThreatIntel: true, useBreachRange: true, recordScanHistory: true },
  biometric: { enabled: false, credId: null },
  totp: { enabled: false, secret: null },
  sync: { enabled: false, token: null, version: 0, lastSync: null, status: 'off', error: null, conflict: null, devices: [] },
  recoveryAcknowledged: false
};

export const S = { env: null, session: null, data: null, unlocked: false, view: 'dashboard', params: {}, lastActivity: Date.now(), sessionStart: null, api: null };

const listeners = new Set();
export const subscribe = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
const emit = (what) => listeners.forEach(fn => { try { fn(what); } catch (e) { console.error(e); } });

export const loadEnvelope = () => { try { return JSON.parse(localStorage.getItem(LS_ENV)); } catch { return null; } };
export function deviceInfo() {
  let d; try { d = JSON.parse(localStorage.getItem(LS_DEVICE)); } catch { /* ignore */ }
  if (!d) {
    const ua = navigator.userAgent;
    const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Device';
    d = { id: uid().slice(0, 12), name: `${browser} on ${os}` };
    localStorage.setItem(LS_DEVICE, JSON.stringify(d));
  }
  return d;
}

export function newData(name) {
  return { profile: { name: name || 'there' }, entries: [], notes: [], activity: [], scans: [], breach: { lastChecked: null, mode: 'never', results: {} }, settings: structuredClone(DEFAULT_SETTINGS), lastSecurityCheck: null };
}
/** Fill in any missing settings keys after upgrades or imports. */
export function normalizeData(d) {
  const s = structuredClone(DEFAULT_SETTINGS);
  const merge = (a, b) => { for (const k of Object.keys(b || {})) a[k] = (a[k] && typeof a[k] === 'object' && !Array.isArray(a[k]) && b[k] && typeof b[k] === 'object') ? merge(a[k], b[k]) : b[k]; return a; };
  d.settings = merge(s, d.settings);
  d.entries ||= []; d.notes ||= []; d.activity ||= []; d.scans ||= []; d.breach ||= { lastChecked: null, mode: 'never', results: {} }; d.profile ||= { name: 'there' };
  return d;
}

// ---- persistence ----
let saving = Promise.resolve();
let syncTimer = null;
export function commit() {
  emit('data');
  saving = saving.then(async () => {
    if (!S.unlocked) return;
    try {
      S.env = await C.sealVault(S.env, S.session, S.data);
      localStorage.setItem(LS_ENV, JSON.stringify(S.env));
    } catch (e) { toast('Could not save the vault: ' + (e.name === 'QuotaExceededError' ? 'browser storage is full.' : 'unexpected error.'), 'error'); }
  });
  if (!syncing && S.data?.settings.sync.enabled && S.data.settings.sync.status !== 'conflict') { clearTimeout(syncTimer); syncTimer = setTimeout(() => syncNow({ quiet: true }), 4000); }
  return saving;
}
let syncing = false;
export const whenSaved = () => saving;

// ---- activity log (never receives secrets; callers pass names only) ----
export function log(type, text, severity = 'info') {
  if (!S.data) return;
  S.data.activity.unshift({ id: uid(), ts: new Date().toISOString(), type, text: String(text).slice(0, 200), severity });
  if (S.data.activity.length > 400) S.data.activity.length = 400;
  commit();
}

// ---- entries ----
export const DEFAULT_CATEGORIES = ['Social', 'Finance', 'Work', 'Email', 'Shopping', 'Entertainment', 'Developer', 'Other'];
const MAX_HISTORY = 10;

export function addEntry(f) {
  const now = new Date().toISOString();
  const e = { id: uid(), name: f.name.trim(), username: f.username.trim(), email: f.email.trim(), password: f.password, url: normalizeSavedUrl(f.url), category: f.category || 'Other', tags: f.tags, notes: f.notes, favorite: !!f.favorite, createdAt: now, updatedAt: now, passwordChangedAt: now, lastUsedAt: null, history: [] };
  S.data.entries.push(e);
  log('password-added', `Added "${e.name}"`, 'info');
  return e;
}
export function updateEntry(id, f) {
  const e = S.data.entries.find(x => x.id === id); if (!e) return null;
  const now = new Date().toISOString();
  if (f.password !== e.password) { e.history.unshift({ password: e.password, changedAt: e.passwordChangedAt || e.updatedAt }); e.history.length = Math.min(e.history.length, MAX_HISTORY); e.passwordChangedAt = now; }
  Object.assign(e, { name: f.name.trim(), username: f.username.trim(), email: f.email.trim(), password: f.password, url: normalizeSavedUrl(f.url), category: f.category || 'Other', tags: f.tags, notes: f.notes, favorite: !!f.favorite, updatedAt: now });
  delete S.data.breach.results[e.id]; // stale once the password changed
  log('password-updated', `Updated "${e.name}"`, 'info');
  return e;
}
export function restoreVersion(id, idx) {
  const e = S.data.entries.find(x => x.id === id); const v = e?.history[idx]; if (!v) return false;
  const now = new Date().toISOString();
  e.history.splice(idx, 1);
  e.history.unshift({ password: e.password, changedAt: e.passwordChangedAt || e.updatedAt });
  e.history.length = Math.min(e.history.length, MAX_HISTORY);
  e.password = v.password; e.passwordChangedAt = now; e.updatedAt = now;
  delete S.data.breach.results[e.id];
  log('password-restored', `Restored an earlier password for "${e.name}"`, 'info');
  return true;
}
export function deleteEntry(id) {
  const i = S.data.entries.findIndex(x => x.id === id); if (i < 0) return;
  const [e] = S.data.entries.splice(i, 1); delete S.data.breach.results[id];
  log('password-deleted', `Deleted "${e.name}"`, 'warn');
}
export function touchUsed(id) { const e = S.data.entries.find(x => x.id === id); if (e) { e.lastUsedAt = new Date().toISOString(); commit(); } }
export function toggleFavorite(id) { const e = S.data.entries.find(x => x.id === id); if (e) { e.favorite = !e.favorite; e.updatedAt = new Date().toISOString(); commit(); } return e; }
export function normalizeSavedUrl(u) {
  const t = (u || '').trim(); if (!t) return '';
  const p = parseUrl(t); return p.ok ? p.displayOrigin + (p.https ? '' : '') : t;
}

// ---- notes ----
export function saveNote(id, f) {
  const now = new Date().toISOString();
  if (id) { const n = S.data.notes.find(x => x.id === id); Object.assign(n, { title: f.title.trim(), body: f.body, category: f.category, tags: f.tags, updatedAt: now }); log('note-updated', `Updated note "${n.title}"`); return n; }
  const n = { id: uid(), title: f.title.trim(), body: f.body, category: f.category, tags: f.tags, createdAt: now, updatedAt: now };
  S.data.notes.unshift(n); log('note-added', `Added note "${n.title}"`); return n;
}
export function deleteNote(id) { const i = S.data.notes.findIndex(n => n.id === id); if (i < 0) return; const [n] = S.data.notes.splice(i, 1); log('note-deleted', `Deleted note "${n.title}"`, 'warn'); }

export const parseTags = (s) => [...new Set(String(s || '').split(',').map(t => t.trim().toLowerCase()).filter(Boolean))].slice(0, 12);

// ---- lock / unlock ----
export function setSession(env, session, data) { S.env = env; S.session = session; S.data = normalizeData(data); S.unlocked = true; S.sessionStart = new Date().toISOString(); S.lastActivity = Date.now(); localStorage.setItem(LS_THEME, S.data.settings.theme); emit('unlock'); }
export function lock(reason = 'Vault locked') {
  if (!S.unlocked) return;
  log('vault-locked', reason, 'info');
  const done = saving.then(() => { S.session = null; S.data = null; S.unlocked = false; emit('lock'); });
  return done;
}

// ---- sync (client-side E2EE: only the encrypted envelope is uploaded) ----
const syncHeaders = (token) => ({ 'Content-Type': 'application/json', 'X-Sync-Token': token });
export async function enableSync() {
  const sy = S.data.settings.sync;
  sy.token = sy.token || (crypto.randomUUID().replace(/-/g, '') + Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''));
  sy.enabled = true; sy.status = 'idle'; sy.error = null; sy.conflict = null;
  log('settings-changed', 'Encrypted sync enabled', 'info');
  await whenSaved();
  return syncNow();
}
export async function syncNow({ quiet = false, force = false } = {}) {
  const sy = S.data?.settings.sync; if (!sy?.enabled || syncing) return { ok: false };
  syncing = true; sy.status = 'syncing'; emit('data');
  await whenSaved();
  try { return await doSync(sy, quiet, force); }
  finally { await commit(); syncing = false; emit('data'); }
}
async function doSync(sy, quiet, force) {
  {
    try {
    const dev = deviceInfo();
    const r = await fetch('/api/sync/' + S.env.vaultId, { method: 'PUT', headers: syncHeaders(sy.token), body: JSON.stringify({ envelope: S.env, baseVersion: sy.version, deviceId: dev.id, deviceName: dev.name, force }) });
    const j = await r.json().catch(() => ({}));
    if (r.status === 409) { sy.status = 'conflict'; sy.conflict = { serverVersion: j.version, serverUpdatedAt: j.updatedAt }; sy.error = null; log('sync-failed', 'Sync conflict: another device uploaded newer changes', 'warn'); emit('data'); return { ok: false, conflict: true }; }
    if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
    sy.version = j.version; sy.lastSync = j.updatedAt; sy.status = 'ok'; sy.error = null; sy.conflict = null;
    await refreshDevices();
    log('sync-completed', quiet ? 'Encrypted vault auto-synced' : 'Encrypted vault synced', 'success');
    return { ok: true };
  } catch (e) {
    sy.status = 'error'; sy.error = e.message === 'Failed to fetch' ? 'Cannot reach the NexiVault server.' : e.message;
    log('sync-failed', 'Sync failed: ' + sy.error, 'error'); return { ok: false, error: sy.error };
  }
  }
}
export async function refreshDevices() {
  const sy = S.data.settings.sync;
  try {
    const r = await fetch('/api/sync/' + S.env.vaultId, { headers: { 'X-Sync-Token': sy.token } });
    if (r.ok) { const j = await r.json(); sy.devices = j.devices || []; }
  } catch { /* leave previous list */ }
}
export async function fetchServerEnvelope(vaultId, token) {
  const r = await fetch('/api/sync/' + encodeURIComponent(vaultId), { headers: { 'X-Sync-Token': token } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}

export async function loadApiStatus() {
  try { const r = await fetch('/api/status'); S.api = r.ok ? await r.json() : null; } catch { S.api = null; }
  return S.api;
}
