# NexiVault: password manager prototype

Dark-navy password manager with a **Website Safety Scanner** that blocks autofill on lookalike / phishing domains.
Frontend: plain HTML, CSS and JavaScript (ES modules, no build step). Backend: Node.js with **zero dependencies**.

## Run

```bash
npm start              # needs Node 18+ ; opens on http://127.0.0.1:3000
npm test               # unit tests (domain analysis, strength, generator, crypto, TOTP)
```

Open http://127.0.0.1:3000, create a vault (tick “sample entries” to try it out). Use `localhost`/HTTPS: WebCrypto and the clipboard need a secure context.

Optional environment variables

| Variable | Purpose |
|---|---|
| `PORT`, `HOST` | default `3000`, `127.0.0.1` |
| `GOOGLE_SAFE_BROWSING_KEY` | enables real threat intelligence (key stays on the server; only the site origin is sent) |
| `HIBP_DISABLED=1` | disable the breach-range proxy |

## Project layout

```
server.js                    static hosting + /api/scan, /api/breach/range/:prefix, /api/sync/:id, /api/status
public/index.html            app entry
public/css/styles.css        dark + light themes, responsive layout
public/js/crypto.js          PBKDF2 + AES-256-GCM vault, recovery key, TOTP
public/js/domain.js          registrable-domain parsing, lookalike / punycode / subdomain-trick detection
public/js/strength.js        strength estimator   public/js/generator.js  CSPRNG generator
public/js/analysis.js        score, findings, privacy scanner (all computed from real vault data)
public/js/state.js           state, encrypted persistence, activity log, sync client
public/js/auth.js            setup / unlock / recovery / 2FA gate / connect synced vault
public/js/views/*.js         dashboard, passwords, notes, generator, security, guardian, scanner, timeline, settings, autofill
extension/                   Manifest V3 skeleton (see below)
test/core.test.js            16 unit tests
```

## Real vs simulated

**Real (works as described)**
- Vault encrypted in the browser: random data key, AES-256-GCM, wrapped by PBKDF2-SHA256 (600k iterations) of the master password and, separately, a recovery key. Master password and recovery key are never stored. Auto-lock, change master password, new recovery key, encrypted backup/restore.
- Strength checker, CSPRNG generator (`crypto.getRandomValues`, rejection sampling), passphrases.
- Domain verification (no substring matching): registrable-domain comparison, look-alike characters (`1/l`, `0/o`, `rn/m`, Cyrillic), typo-squats, brand-in-other-domain (`paypal-security.example.net`), `paypal.com.evil.net`, `user@host` tricks, punycode, raw IPs, http. Autofill is blocked unless the result is **Safe match**; “Suspicious/Unverified” needs an explicit override that is logged; a **Potentially malicious** result cannot be overridden.
- Breach check: SHA-1 prefix k-anonymity through your server to Have I Been Pwned. If the server cannot reach HIBP, the UI says **Unavailable**; nothing is marked safe.
- Encrypted sync to the included server (client-side encrypted envelope, optimistic versioning, conflict handling, device list).
- Activity log (never contains secrets), password history with restore, TOTP (RFC 6238 verified in tests).

**Simulated / limited (clearly labelled in the UI)**
- **“Potentially malicious” verdicts need `GOOGLE_SAFE_BROWSING_KEY`.** Without it, local heuristics can only produce Suspicious / Unverified / Safe match, never “malicious”.
- **Autofill is a simulation inside the web app** (copy buttons + a fake login form). A web page cannot read other tabs or fill other sites; that needs the extension.
- **Extension is a skeleton**, not a finished product: it re-uses `domain.js`, takes the URL from the browser (not the page), refuses messages from content scripts/pages, fills only the top frame of a verified tab after a click. Missing: secure credential hand-off from the web app (native messaging or an unlock flow inside the extension), packaging, per-site permissions UX. Run `npm run sync-extension` after editing `domain.js`.
- **Guardian is rule-based**, not an AI model; it reads only metadata.
- **2FA and biometric unlock are local gates** checked in the browser after the master password decrypts the vault. They do not protect the encryption key and are not server-verified.
- **Sync has no accounts**: access is a random token; the server sees metadata (size, timing). Use only on a trusted network / HTTPS.
- No account-level dark-web monitoring (needs a paid email-breach API).
- Strength / crack-time numbers are rough estimates.

## Security notes
- CSP is strict (`script-src 'self'`), cross-origin API requests are rejected, API routes are rate-limited and validated, scan logs record hostnames only.
- Passwords are never logged, put in notifications, or sent to scanners. The plain-text CSV export is opt-in with a warning.
- This is a prototype: it has not had an independent security review. Do not store real high-value credentials in it.

## Remaining limitations
- Public-suffix list is an embedded subset; ship the full list for production.
- Lookalike detection compares against *your saved domains only*, not a global brand list.
- Browser storage (`localStorage`) holds the encrypted vault; clearing site data deletes it, so keep the recovery key and an encrypted backup.
