// WebAuthn "biometric / device unlock" gate.
// IMPORTANT: this is a convenience check performed in the browser. It does NOT derive or protect the
// encryption key (that would need the WebAuthn PRF extension plus server-side verification).
import { b64 } from './crypto.js';

export async function biometricSupported() {
  try {
    if (!window.PublicKeyCredential || !window.isSecureContext) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch { return false; }
}
export async function registerBiometric(name) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: 'NexiVault' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'nexivault-' + (name || 'user'), displayName: name || 'NexiVault user' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' }, timeout: 60000
  } });
  return b64.enc(cred.rawId);
}
export async function assertBiometric(credId) {
  const r = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: [{ type: 'public-key', id: b64.dec(credId) }], userVerification: 'required', timeout: 60000 } });
  return !!r;
}
