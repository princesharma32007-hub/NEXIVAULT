// NexiVault server: zero dependencies (Node 18+).
//   - serves ./public
//   - POST /api/scan            URL reputation (optional Google Safe Browsing; key stays server-side)
//   - GET  /api/breach/range/:p k-anonymity proxy for Have I Been Pwned password ranges (5-char SHA-1 prefix only)
//   - GET/PUT /api/sync/:id     stores an opaque, client-encrypted vault envelope (server never sees plaintext)
//   - GET  /api/status          which integrations are configured
//
// Env: PORT (3000), HOST (127.0.0.1), GOOGLE_SAFE_BROWSING_KEY (optional), HIBP_DISABLED=1 (optional)

import http from 'node:http';
import fs from 'node:fs/promises';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseUrl } from './public/js/domain.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const SYNC_FILE = path.join(DATA_DIR, 'sync.json');
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || '';
const HIBP_ENABLED = process.env.HIBP_DISABLED !== '1';

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store'
};

// ---- tiny in-memory rate limiter (per IP, per bucket) ----
const buckets = new Map();
function rateLimit(ip, bucket, max, windowMs) {
  const k = bucket + '|' + ip, now = Date.now();
  const rec = (buckets.get(k) || []).filter(t => now - t < windowMs);
  if (rec.length >= max) { buckets.set(k, rec); return false; }
  rec.push(now); buckets.set(k, rec); return true;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of buckets) if (!v.some(t => now - t < 120000)) buckets.delete(k); }, 60000).unref();

function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': isObj ? 'application/json' : 'text/plain; charset=utf-8', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}

async function readJson(req, limit = 2_000_000) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > limit) throw Object.assign(new Error('Payload too large'), { status: 413 }); chunks.push(c); }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}

// Reject cross-origin browser requests to the API (CSRF-style). Same-origin fetches send matching Origin or none.
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}

// ---- sync storage (opaque ciphertext only) ----
let syncDb = {};
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
try { syncDb = JSON.parse(await fs.readFile(SYNC_FILE, 'utf8')); } catch { syncDb = {}; }
let writing = Promise.resolve();
const persist = () => (writing = writing.then(() => fs.writeFile(SYNC_FILE, JSON.stringify(syncDb))).catch(() => {}));
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const tokenOk = (rec, token) => {
  if (!token) return false;
  const a = Buffer.from(sha256(token)), b = Buffer.from(rec.tokenHash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---- Google Safe Browsing (v4 threatMatches:find). Only the origin (no path/query) is sent. ----
async function safeBrowsing(origin) {
  const body = {
    client: { clientId: 'nexivault', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: origin + '/' }]
    }
  };
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
  try {
    const r = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(GSB_KEY), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal });
    if (!r.ok) return { configured: true, available: false, source: 'Google Safe Browsing', error: 'Service returned HTTP ' + r.status };
    const j = await r.json();
    const matches = j.matches || [];
    return { configured: true, available: true, source: 'Google Safe Browsing', malicious: matches.length > 0, threats: [...new Set(matches.map(m => m.threatType))] };
  } catch (e) {
    return { configured: true, available: false, source: 'Google Safe Browsing', error: e.name === 'AbortError' ? 'Timed out' : 'Network error' };
  } finally { clearTimeout(t); }
}

async function handleApi(req, res, url) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!sameOrigin(req)) return send(res, 403, { error: 'Cross-origin request blocked.' });

  if (url.pathname === '/api/status' && req.method === 'GET') {
    return send(res, 200, { threatIntel: { configured: !!GSB_KEY, provider: GSB_KEY ? 'Google Safe Browsing' : null }, breachRange: { enabled: HIBP_ENABLED, provider: 'Have I Been Pwned (k-anonymity range API)' }, sync: { enabled: true, e2ee: true, note: 'Server stores client-encrypted envelopes only.' } });
  }

  if (url.pathname === '/api/scan' && req.method === 'POST') {
    if (!rateLimit(ip, 'scan', 30, 60000)) return send(res, 429, { error: 'Too many scans. Please wait a minute.' }, { 'Retry-After': '60' });
    const body = await readJson(req, 10_000);
    const p = parseUrl(body.url);
    if (!p.ok) return send(res, 400, { error: p.error });
    if (!GSB_KEY) return send(res, 200, { configured: false, available: false, status: 'not-configured', note: 'No threat-intelligence API key configured on the server. Local heuristics only.' });
    // Log only the hostname, never path or query.
    console.log('[scan]', p.hostname);
    return send(res, 200, { ...(await safeBrowsing(p.displayOrigin)), status: 'checked' });
  }

  const range = url.pathname.match(/^\/api\/breach\/range\/([0-9A-Fa-f]{5})$/);
  if (range && req.method === 'GET') {
    if (!HIBP_ENABLED) return send(res, 503, { error: 'Breach range lookups are disabled on this server.' });
    if (!rateLimit(ip, 'breach', 120, 60000)) return send(res, 429, { error: 'Too many breach checks. Please wait.' }, { 'Retry-After': '60' });
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
    try {
      const r = await fetch('https://api.pwnedpasswords.com/range/' + range[1].toUpperCase(), { headers: { 'Add-Padding': 'true', 'User-Agent': 'NexiVault-prototype' }, signal: ctrl.signal });
      if (!r.ok) return send(res, 502, { error: 'Breach service returned HTTP ' + r.status });
      return send(res, 200, await r.text(), { 'Content-Type': 'text/plain; charset=utf-8' });
    } catch { return send(res, 502, { error: 'Breach service unreachable from this server.' }); }
    finally { clearTimeout(t); }
  }

  const sync = url.pathname.match(/^\/api\/sync\/([A-Za-z0-9]{8,32})$/);
  if (sync) {
    if (!rateLimit(ip, 'sync', 60, 60000)) return send(res, 429, { error: 'Too many sync requests.' });
    const id = sync[1]; const token = req.headers['x-sync-token'];
    const rec = syncDb[id];
    if (req.method === 'GET') {
      if (!rec) return send(res, 404, { error: 'No synced vault with that ID.' });
      if (!tokenOk(rec, token)) return send(res, 401, { error: 'Invalid sync token.' });
      return send(res, 200, { version: rec.version, updatedAt: rec.updatedAt, envelope: rec.envelope, devices: Object.entries(rec.devices || {}).map(([id, d]) => ({ id, ...d })) });
    }
    if (req.method === 'PUT') {
      const b = await readJson(req, 5_000_000);
      const env = b.envelope;
      if (!env || env.vaultId !== id || !env.data?.ct || !env.wrapM?.ct || typeof token !== 'string' || token.length < 24 || token.length > 200) return send(res, 400, { error: 'Malformed sync upload.' });
      if (JSON.stringify(env).includes('"password"')) return send(res, 400, { error: 'Envelope must be encrypted.' });
      const device = { name: String(b.deviceName || 'Unknown device').slice(0, 60), lastSeen: new Date().toISOString() };
      if (!rec) {
        syncDb[id] = { tokenHash: sha256(token), version: 1, updatedAt: device.lastSeen, envelope: env, devices: { [String(b.deviceId || 'dev').slice(0, 40)]: device } };
        persist(); return send(res, 200, { version: 1, updatedAt: device.lastSeen });
      }
      if (!tokenOk(rec, token)) return send(res, 401, { error: 'Invalid sync token.' });
      if (Number(b.baseVersion) !== rec.version && !b.force) {
        return send(res, 409, { error: 'Conflict: the server has a newer version.', version: rec.version, updatedAt: rec.updatedAt });
      }
      rec.version += 1; rec.updatedAt = device.lastSeen; rec.envelope = env;
      rec.devices = { ...(rec.devices || {}), [String(b.deviceId || 'dev').slice(0, 40)]: device };
      persist(); return send(res, 200, { version: rec.version, updatedAt: rec.updatedAt });
    }
    return send(res, 405, { error: 'Method not allowed' });
  }
  return send(res, 404, { error: 'Unknown API route.' });
}

async function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel.endsWith('/')) rel += 'index.html';
  const full = path.normalize(path.join(PUBLIC, rel));
  if (!full.startsWith(PUBLIC + path.sep) && full !== PUBLIC) return send(res, 403, 'Forbidden');
  try {
    const st = await fs.stat(full);
    if (!st.isFile()) throw new Error('nf');
    const buf = await fs.readFile(full);
    send(res, 200, buf, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
  } catch {
    if (!path.extname(rel)) { // SPA fallback
      const buf = await fs.readFile(path.join(PUBLIC, 'index.html'));
      return send(res, 200, buf, { 'Content-Type': MIME['.html'] });
    }
    send(res, 404, 'Not found');
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    return await serveStatic(req, res, url);
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error('[error]', e.message);
    send(res, status, { error: status === 500 ? 'Internal server error' : e.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`NexiVault running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Threat intelligence : ${GSB_KEY ? 'Google Safe Browsing configured' : 'not configured (local heuristics only)'}`);
  console.log(`  Breach range lookup : ${HIBP_ENABLED ? 'enabled (k-anonymity)' : 'disabled'}`);
});
