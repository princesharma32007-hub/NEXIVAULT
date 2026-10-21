// NexiVault cryptography (WebCrypto only; no custom primitives).
//
// Design:
//   - A random 256-bit data key (DEK) encrypts the whole vault with AES-256-GCM.
//   - The DEK is wrapped twice: by a key derived from the master password (PBKDF2-SHA256)
//     and by a key derived from a one-time recovery key. Neither secret is stored.
//   - Changing the master password only re-wraps the DEK.
// The envelope (what is stored locally and synced) contains ONLY ciphertext, salts and IVs.

const enc = new TextEncoder();
const dec = new TextDecoder();
export const KDF_ITERATIONS = 600000;

export const b64 = {
  enc: (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); },
  dec: (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0))
};
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

async function deriveKek(secret, salt, iterations, usages = ['encrypt', 'decrypt']) {
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, usages);
}
async function aesEncrypt(key, bytes, aad) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes);
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function aesDecrypt(key, box, aad) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(box.iv), additionalData: aad }, key, b64.dec(box.ct)));
}
const importDek = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
const normRecovery = (s) => String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');

export function generateRecoveryKey() {
  const raw = rand(20); // 160 bits
  const s = base32Encode(raw);
  return s.match(/.{1,4}/g).join('-');
}

const aadFor = (vaultId) => enc.encode('nexivault:v1:' + vaultId);

async function sealData(session, data, vaultId) {
  return aesEncrypt(session.dek, enc.encode(JSON.stringify(data)), aadFor(vaultId));
}

/** Create a brand-new vault. Returns { envelope, session, recoveryKey }. */
export async function createVault(master, data) {
  const vaultId = b64.enc(rand(12)).replace(/[+/=]/g, '').slice(0, 16);
  const rawDek = rand(32);
  const saltM = rand(16), saltR = rand(16);
  const recoveryKey = generateRecoveryKey();
  const kekM = await deriveKek(master, saltM, KDF_ITERATIONS);
  const kekR = await deriveKek(normRecovery(recoveryKey), saltR, KDF_ITERATIONS);
  const session = { dek: await importDek(rawDek), rawDek, vaultId };
  const envelope = {
    v: 1, vaultId, rev: 1, serverVersion: 0,
    kdf: { name: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, saltM: b64.enc(saltM), saltR: b64.enc(saltR) },
    wrapM: await aesEncrypt(kekM, rawDek, aadFor(vaultId)),
    wrapR: await aesEncrypt(kekR, rawDek, aadFor(vaultId)),
    data: await sealData(session, data, vaultId),
    updatedAt: new Date().toISOString()
  };
  return { envelope, session, recoveryKey };
}

async function openWith(envelope, secret, which) {
  const salt = b64.dec(envelope.kdf[which === 'wrapM' ? 'saltM' : 'saltR']);
  const kek = await deriveKek(which === 'wrapM' ? secret : normRecovery(secret), salt, envelope.kdf.iterations);
  let rawDek;
  try { rawDek = await aesDecrypt(kek, envelope[which], aadFor(envelope.vaultId)); }
  catch { return null; } // wrong secret (GCM tag mismatch)
  const session = { dek: await importDek(rawDek), rawDek, vaultId: envelope.vaultId };
  const plain = await aesDecrypt(session.dek, envelope.data, aadFor(envelope.vaultId));
  return { data: JSON.parse(dec.decode(plain)), session };
}
export const unlockWithMaster = (envelope, master) => openWith(envelope, master, 'wrapM');
export const unlockWithRecovery = (envelope, recoveryKey) => openWith(envelope, recoveryKey, 'wrapR');

/** Re-encrypt the vault contents. Returns a new envelope. */
export async function sealVault(envelope, session, data) {
  return { ...envelope, rev: (envelope.rev || 0) + 1, data: await sealData(session, data, envelope.vaultId), updatedAt: new Date().toISOString() };
}

/** Re-wrap the DEK under a new master password (and optionally a fresh recovery key). */
export async function rewrapMaster(envelope, session, newMaster, { newRecovery = false } = {}) {
  const saltM = rand(16);
  const kekM = await deriveKek(newMaster, saltM, KDF_ITERATIONS);
  const next = { ...envelope, kdf: { ...envelope.kdf, iterations: KDF_ITERATIONS, saltM: b64.enc(saltM) }, wrapM: await aesEncrypt(kekM, session.rawDek, aadFor(envelope.vaultId)), rev: (envelope.rev || 0) + 1, updatedAt: new Date().toISOString() };
  let recoveryKey = null;
  if (newRecovery) {
    const saltR = rand(16);
    recoveryKey = generateRecoveryKey();
    const kekR = await deriveKek(normRecovery(recoveryKey), saltR, KDF_ITERATIONS);
    next.kdf.saltR = b64.enc(saltR);
    next.wrapR = await aesEncrypt(kekR, session.rawDek, aadFor(envelope.vaultId));
  }
  return { envelope: next, recoveryKey };
}

export async function verifyMaster(envelope, master) { return !!(await openWith(envelope, master, 'wrapM')); }

// ---- hashing / TOTP -------------------------------------------------------
export async function sha1Hex(text) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-1', enc.encode(text)));
  return [...h].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(str) {
  const clean = normRecovery(str); let bits = 0, value = 0; const out = [];
  for (const ch of clean) { value = (value << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
export const newTotpSecret = () => base32Encode(rand(20));

export async function totpCode(secretB32, timeMs = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(timeMs / 1000 / step);
  const msg = new ArrayBuffer(8); const dv = new DataView(msg);
  dv.setUint32(0, Math.floor(counter / 0x100000000)); dv.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey('raw', base32Decode(secretB32), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}
export async function verifyTotp(secretB32, code, timeMs = Date.now()) {
  const c = String(code).replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  for (const w of [-1, 0, 1]) if (await totpCode(secretB32, timeMs + w * 30000) === c) return true;
  return false;
}
