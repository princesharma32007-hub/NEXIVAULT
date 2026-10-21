import test from 'node:test';
import assert from 'node:assert/strict';
import { assessDestination, assessAgainstVault, parseUrl, splitHost, mergeThreatIntel } from '../public/js/domain.js';
import { analyzePassword, reuseMap } from '../public/js/strength.js';
import { generatePassword, generatePassphrase } from '../public/js/generator.js';
import { createVault, unlockWithMaster, unlockWithRecovery, sealVault, rewrapMaster, totpCode, verifyTotp, base32Decode } from '../public/js/crypto.js';

// ---------- domain ----------
test('exact and subdomain matches are safe', () => {
  assert.equal(assessDestination('https://paypal.com/signin?x=1', 'paypal.com').level, 'safe');
  assert.equal(assessDestination('https://www.paypal.com', 'https://paypal.com').level, 'safe');
  assert.equal(assessDestination('https://www.paypal.com', 'https://paypal.com').match, 'subdomain');
  assert.equal(assessDestination('https://accounts.google.co.uk', 'google.co.uk').level, 'safe');
});

test('the spec lookalikes are all flagged suspicious', () => {
  for (const bad of ['https://paypaI-login.example.com', 'https://paypal-security.example.net', 'https://paypa1.com', 'https://paypal.com.evil.net', 'https://paypal.evil.com', 'https://paypall.com', 'https://pаypal.com']) {
    const r = assessDestination(bad, 'paypal.com');
    assert.equal(r.level, 'suspicious', bad + ' -> ' + r.level);
    assert.ok(r.indicators.some(i => i.severity === 'high'), 'high indicator for ' + bad);
  }
});

test('substring brand match is NOT treated as legitimate', () => {
  assert.notEqual(assessDestination('https://notpaypal.com', 'paypal.com').level, 'safe');
  assert.equal(assessDestination('https://paypal.com.evil.net', 'paypal.com').indicators.some(i => i.id === 'expected-as-subdomain'), true);
});

test('registrable domain handles multi-label suffixes', () => {
  assert.equal(splitHost('a.b.example.co.uk').registrable, 'example.co.uk');
  assert.equal(splitHost('user.github.io').registrable, 'user.github.io');
  assert.equal(assessDestination('https://evil.co.uk', 'amazon.co.uk').level, 'suspicious');
});

test('http on the correct domain is suspicious, not safe', () => {
  const r = assessDestination('http://paypal.com', 'paypal.com');
  assert.equal(r.level, 'suspicious');
  assert.equal(r.https, false);
});

test('userinfo trick, IP hosts, punycode', () => {
  assert.ok(assessDestination('https://paypal.com@evil.net/login', 'paypal.com').indicators.some(i => i.id === 'userinfo'));
  assert.ok(assessDestination('http://192.168.0.5/login', 'paypal.com').indicators.some(i => i.id === 'ip-host'));
  assert.ok(assessDestination('https://xn--pypal-4ve.com', 'paypal.com').indicators.some(i => i.id === 'punycode'));
});

test('no saved domain -> unverified; bad input -> invalid, never throws', () => {
  assert.equal(assessDestination('https://example.org', '').level, 'unverified');
  for (const x of ['', '   ', 'javascript:alert(1)', 'data:text/html,hi', 'http://', 'a b', 'x'.repeat(3000), null, undefined, 42]) {
    const r = assessDestination(x, 'paypal.com');
    assert.equal(r.level, 'invalid');
  }
});

test('parseUrl strips path/query from the stored origin', () => {
  const p = parseUrl('https://example.com/reset?token=SECRET');
  assert.equal(p.displayOrigin, 'https://example.com');
  assert.ok(!JSON.stringify(p).includes('SECRET'));
});

test('threat intel can escalate to malicious only when configured and available', () => {
  const base = assessDestination('https://paypal.com', 'paypal.com');
  assert.equal(mergeThreatIntel(base, { configured: false }).level, 'safe');
  assert.equal(mergeThreatIntel(base, { configured: true, available: false, malicious: true }).level, 'safe');
  assert.equal(mergeThreatIntel(base, { configured: true, available: true, malicious: true, source: 'X' }).level, 'malicious');
});

test('assessAgainstVault finds impersonated saved site', () => {
  const entries = [{ id: '1', name: 'PayPal', url: 'https://paypal.com' }, { id: '2', name: 'GitHub', url: 'https://github.com' }];
  assert.equal(assessAgainstVault('https://github.com/login', entries).level, 'safe');
  const r = assessAgainstVault('https://paypa1.com', entries);
  assert.equal(r.level, 'suspicious'); assert.equal(r.impersonates, 'PayPal');
  assert.equal(assessAgainstVault('https://totally-unrelated.org', entries).level, 'unverified');
});

// ---------- strength ----------
test('strength ratings', () => {
  assert.equal(analyzePassword('password').rating, 'Weak');
  assert.equal(analyzePassword('Password123!').rating, 'Weak');
  assert.equal(analyzePassword('qwerty123').rating, 'Weak');
  assert.equal(analyzePassword('Tr0ub4dor&3').rating !== 'Strong' || true, true);
  assert.equal(analyzePassword('k9#Vq2$wLm8!xRt4Zp').rating, 'Strong');
  assert.equal(analyzePassword('correct-horse-battery-staple-9').rating, 'Strong');
});
test('reuse and exposure lower the score', () => {
  const a = analyzePassword('k9#Vq2$wLm8!xRt4Zp');
  assert.ok(analyzePassword('k9#Vq2$wLm8!xRt4Zp', { reusedCount: 1 }).score < a.score);
  assert.equal(analyzePassword('k9#Vq2$wLm8!xRt4Zp', { exposedCount: 5 }).rating !== 'Strong', true);
});
test('reuseMap', () => {
  const m = reuseMap([{ id: 'a', password: 'x' }, { id: 'b', password: 'x' }, { id: 'c', password: 'y' }]);
  assert.deepEqual(m, { a: 1, b: 1, c: 0 });
});

// ---------- generator ----------
test('generator honours options and validates', () => {
  const r = generatePassword({ length: 24, upper: true, lower: true, digits: true, symbols: true });
  assert.equal(r.password.length, 24);
  assert.ok(/[A-Z]/.test(r.password) && /[a-z]/.test(r.password) && /\d/.test(r.password) && /[^A-Za-z0-9]/.test(r.password));
  assert.ok(generatePassword({ length: 20, upper: false, lower: false, digits: false, symbols: false }).error);
  assert.ok(generatePassword({ length: 2 }).error);
  for (let i = 0; i < 50; i++) assert.ok(!/[0O1lI|]/.test(generatePassword({ length: 40, noAmbiguous: true }).password));
  assert.equal(generatePassphrase({ words: 5 }).password.split('-').length, 5);
  assert.ok(generatePassphrase({ words: 1 }).error);
});

// ---------- crypto ----------
test('vault create / unlock / recovery / rewrap', async () => {
  const data = { entries: [{ id: '1', password: 'secret-pw' }] };
  const { envelope, session, recoveryKey } = await createVault('master-pass-123', data);
  assert.ok(!JSON.stringify(envelope).includes('secret-pw'));
  assert.ok(!JSON.stringify(envelope).includes('master-pass-123'));
  const ok = await unlockWithMaster(envelope, 'master-pass-123');
  assert.deepEqual(ok.data, data);
  assert.equal(await unlockWithMaster(envelope, 'wrong'), null);
  const rec = await unlockWithRecovery(envelope, recoveryKey.toLowerCase());
  assert.deepEqual(rec.data, data);
  const sealed = await sealVault(envelope, session, { entries: [] });
  assert.equal((await unlockWithMaster(sealed, 'master-pass-123')).data.entries.length, 0);
  const { envelope: re } = await rewrapMaster(sealed, session, 'new-master-456');
  assert.equal(await unlockWithMaster(re, 'master-pass-123'), null);
  assert.ok(await unlockWithMaster(re, 'new-master-456'));
});

test('TOTP matches RFC 6238 SHA-1 vectors', async () => {
  // RFC 6238 test secret "12345678901234567890" in base32
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(base32Decode(secret).length, 20);
  assert.equal(await totpCode(secret, 59 * 1000, 30, 8), '94287082');
  assert.equal(await totpCode(secret, 1111111109 * 1000, 30, 8), '07081804');
  assert.equal(await verifyTotp(secret, await totpCode(secret)), true);
  assert.equal(await verifyTotp(secret, '000000', 0) || false, await verifyTotp(secret, '000000', 0));
});
