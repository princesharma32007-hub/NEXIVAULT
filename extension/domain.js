// NexiVault domain analysis: pure functions, no DOM, no network.
// Used by the web app (and mirrored by the extension skeleton).
// These are LOCAL HEURISTICS. They are not threat intelligence.

// Small embedded list of multi-label public suffixes. A real build should ship the full
// Public Suffix List (https://publicsuffix.org). Unknown suffixes fall back to "last two labels".
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'firm.in', 'gen.in', 'ind.in',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  'co.za', 'org.za', 'gov.za', 'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.sg', 'com.my', 'com.tr', 'com.mx', 'com.ar',
  'co.kr', 'or.kr', 'co.id', 'co.il', 'com.pk', 'com.bd', 'com.ng', 'com.eg', 'com.sa', 'com.ua', 'com.tw',
  // hosting platforms that hand out sub-sites to unrelated people
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'herokuapp.com',
  'blogspot.com', 'wordpress.com', 'web.app', 'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net',
  'amazonaws.com', 'weebly.com', 'wixsite.com', '000webhostapp.com', 'glitch.me', 'repl.co', 'ngrok.io'
]);

// TLDs frequently abused. This is a weak signal only, never proof.
const RISKY_TLDS = new Set(['zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link', 'work', 'support', 'rest', 'country', 'kim', 'loan', 'men', 'icu', 'cyou', 'buzz']);

const SUSPICIOUS_WORDS = ['login', 'signin', 'sign-in', 'secure', 'security', 'verify', 'verification', 'account', 'update', 'support', 'helpdesk', 'billing', 'wallet', 'recover', 'unlock', 'confirm', 'auth', 'alert'];

// Characters that look like other characters. Maps lookalike -> canonical.
const CONFUSABLES = {
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '$': 's', '|': 'l', '!': 'i', '@': 'a',
  'і': 'i', 'ӏ': 'l', 'ɩ': 'i', 'о': 'o', 'ο': 'o', 'а': 'a', 'е': 'e', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'ѕ': 's', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g', 'ν': 'v', 'ⅼ': 'l'
};

export function isIPv4(host) {
  return /^(\d{1,3})(\.\d{1,3}){3}$/.test(host) && host.split('.').every(n => Number(n) <= 255);
}
export function isIPv6(host) { return host.includes(':'); }

/**
 * Parse user input into a safe structure. Never throws.
 * Accepts "paypal.com", "https://paypal.com/login?x=1", etc. Rejects non-http(s) schemes.
 */
export function parseUrl(input) {
  if (typeof input !== 'string') return { ok: false, error: 'Enter a URL as text.' };
  let raw = input.trim();
  if (!raw) return { ok: false, error: 'Enter a website address to check.' };
  if (raw.length > 2048) return { ok: false, error: 'That address is too long (limit 2048 characters).' };
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) return { ok: false, error: 'Addresses cannot contain spaces or control characters.' };
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//.test(raw);
  if (!hasScheme) {
    if (/^(javascript|data|file|vbscript|blob|about|mailto|tel):/i.test(raw)) return { ok: false, error: 'Only http:// and https:// addresses can be checked.' };
    raw = 'https://' + raw; // assume https for bare hosts; we record that we assumed it
  }
  let u;
  try { u = new URL(raw); } catch { return { ok: false, error: 'This does not look like a valid web address.' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: 'Only http:// and https:// addresses can be checked.' };
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return { ok: false, error: 'No hostname found in that address.' };
  const hasUserinfo = raw.slice(raw.indexOf('://') + 3).split('/')[0].includes('@');
  return {
    ok: true,
    assumedScheme: !hasScheme,
    protocol: u.protocol,
    https: u.protocol === 'https:',
    hostname: host,            // already punycode (ASCII) per WHATWG URL
    port: u.port,
    hasUserinfo,
    username: u.username ? '(present)' : '',
    // path/query deliberately dropped so sensitive tokens never get stored or logged
    displayOrigin: u.protocol + '//' + host + (u.port ? ':' + u.port : '')
  };
}

/** Best-effort conversion of an xn-- label to Unicode for display (uses the URL API's inverse when available). */
export function toUnicodeHost(host) {
  try {
    if (typeof globalThis.URL !== 'undefined' && host.includes('xn--')) {
      // Node and browsers expose domainToUnicode only in Node; try Intl-free decoding with punycode below.
      return host.split('.').map(decodePunycodeLabel).join('.');
    }
  } catch { /* ignore */ }
  return host;
}

function decodePunycodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  try { return punycodeDecode(label.slice(4)); } catch { return label; }
}

// RFC 3492 decoder (small, self-contained).
function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const output = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; ++j) output.push(input.charCodeAt(j));
  const adapt = (delta, numPoints, first) => {
    let k = 0;
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) throw new Error('bad');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Split a hostname into { registrable, sld, tld, subdomain, labels } using the embedded suffix list. */
export function splitHost(hostname) {
  const host = hostname.toLowerCase();
  if (isIPv4(host) || isIPv6(host)) return { registrable: host, sld: host, suffix: '', subdomain: '', labels: [host], isIp: true };
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 1) return { registrable: host, sld: host, suffix: '', subdomain: '', labels, isIp: false };
  let suffixLen = 1;
  const last2 = labels.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(last2)) suffixLen = 2;
  if (labels.length <= suffixLen) return { registrable: host, sld: labels[0], suffix: labels.slice(1).join('.'), subdomain: '', labels, isIp: false };
  const suffix = labels.slice(-suffixLen).join('.');
  const sld = labels[labels.length - suffixLen - 1];
  const registrable = sld + '.' + suffix;
  const subdomain = labels.slice(0, labels.length - suffixLen - 1).join('.');
  return { registrable, sld, suffix, subdomain, labels, isIp: false };
}

/** Fold lookalike characters so "paypa1" and "paypaI" fold to "paypal". */
export function foldConfusables(s) {
  let out = '';
  for (const ch of s.toLowerCase().normalize('NFKC')) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd');
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

function scriptsIn(str) {
  const s = new Set();
  for (const ch of str) {
    if (/[a-z0-9\-.]/i.test(ch)) s.add('latin');
    else if (/\p{Script=Cyrillic}/u.test(ch)) s.add('cyrillic');
    else if (/\p{Script=Greek}/u.test(ch)) s.add('greek');
    else if (/\p{Script=Latin}/u.test(ch)) s.add('latin');
    else s.add('other');
  }
  return s;
}

/**
 * Core check. `current` and `expected` are URLs/hostnames (strings).
 * Returns a structured assessment. Level is one of: safe | suspicious | unverified | invalid.
 * "malicious" is NEVER produced here; it requires threat intelligence (see mergeThreatIntel).
 */
export function assessDestination(currentInput, expectedInput) {
  const cur = parseUrl(currentInput);
  if (!cur.ok) return { level: 'invalid', error: cur.error, indicators: [], checks: [] };

  const indicators = []; // {id, severity: info|low|medium|high, text}
  const flag = (id, severity, text) => indicators.push({ id, severity, text });

  const curSplit = splitHost(cur.hostname);
  const curUnicode = toUnicodeHost(cur.hostname);

  let exp = null, expSplit = null;
  if (expectedInput && String(expectedInput).trim()) {
    exp = parseUrl(expectedInput);
    if (exp.ok) expSplit = splitHost(exp.hostname);
  }

  // --- Generic structure checks (apply even without an expected domain) ---
  if (!cur.https) flag('no-https', 'medium', 'Connection is not encrypted (http://). Never enter a password on an unencrypted page.');
  if (cur.hasUserinfo) flag('userinfo', 'high', 'The address contains "user@" before the host, a trick used to disguise the real destination.');
  if (curSplit.isIp) flag('ip-host', 'high', 'The site is addressed by a raw IP address instead of a domain name.');
  if (cur.port && !['80', '443'].includes(cur.port)) flag('odd-port', 'low', `Unusual port :${cur.port}.`);
  if (cur.hostname.includes('xn--')) {
    flag('punycode', 'high', `Internationalized (punycode) domain. It may display as "${curUnicode}" in some browsers, which can mimic a familiar name.`);
  }
  if (/[^\x00-\x7f]/.test(curUnicode) || scriptsIn(curUnicode).size > 1) {
    flag('mixed-script', 'high', 'The domain mixes writing systems or uses look-alike letters from other alphabets.');
  }
  if (!curSplit.isIp) {
    const tld = curSplit.suffix.split('.').pop();
    if (RISKY_TLDS.has(tld)) flag('risky-tld', 'low', `".${tld}" is a top-level domain often abused for throwaway sites (weak signal on its own).`);
    if (curSplit.labels.length - (curSplit.suffix.split('.').length) - 1 >= 3) flag('deep-subdomain', 'medium', 'Unusually many subdomain levels, which can push the real domain out of view.');
    if (cur.hostname.length > 60) flag('long-host', 'low', 'Unusually long hostname.');
    const hy = (curSplit.sld.match(/-/g) || []).length;
    if (hy >= 3) flag('many-hyphens', 'low', 'Domain name contains many hyphens.');
    const words = SUSPICIOUS_WORDS.filter(w => cur.hostname.replace(curSplit.suffix, '').includes(w));
    if (words.length) flag('keywords', 'low', `Hostname contains account-related words (${words.slice(0, 3).join(', ')}), common in phishing pages.`);
  }

  // --- Comparison with the saved domain ---
  let match = 'none';        // exact | subdomain | different | no-expected
  let expectedRegistrable = null;
  if (!expSplit) {
    match = 'no-expected';
  } else {
    expectedRegistrable = expSplit.registrable;
    const sameRegistrable = curSplit.registrable === expSplit.registrable;
    if (sameRegistrable && curSplit.labels.join('.') === expSplit.labels.join('.')) match = 'exact';
    else if (sameRegistrable) match = 'subdomain';
    else match = 'different';

    if (match === 'different') {
      const e = expSplit.sld, c = curSplit.sld;
      // Expected full domain appearing as a subdomain of someone else: paypal.com.evil.net
      if (curSplit.subdomain && ('.' + curSplit.subdomain + '.').includes('.' + expSplit.registrable + '.')) {
        flag('expected-as-subdomain', 'high', `"${expSplit.registrable}" appears as part of the subdomain, but the real domain is "${curSplit.registrable}".`);
      }
      const eFold = foldConfusables(e), cFold = foldConfusables(c);
      if (c !== e && eFold === cFold) flag('lookalike-chars', 'high', `"${c}" uses look-alike characters to imitate "${e}" (for example 1/l, 0/o, rn/m, capital I/l).`);
      else if (c !== e && c.length > 3 && levenshtein(c, e) <= (e.length >= 8 ? 2 : 1)) flag('typosquat', 'high', `"${c}" is very close to "${e}" (possible typo-squatting).`);
      else if (c !== e && c.length > 3 && levenshtein(cFold, eFold) <= 1) flag('typosquat', 'high', `"${c}" is nearly identical to "${e}" after normalising look-alike letters.`);
      // Brand token inside a different domain: paypal-security.example.net / paypalsecure.com
      const tokens = (curSplit.labels.join('-')).split(/[^a-z0-9]+/);
      const brandInOther = e.length >= 4 && (tokens.includes(e) || curSplit.sld.includes(e) || curSplit.subdomain.split(/[^a-z0-9]+/).includes(e) || foldConfusables(curSplit.labels.join('-')).includes(eFold));
      const tokenSquat = tokens.find(t => t.length >= 4 && t !== e && levenshtein(foldConfusables(t), eFold) <= 1);
      if (tokenSquat && !brandInOther && !indicators.some(i => i.id === 'lookalike-chars' || i.id === 'typosquat')) {
        flag('typosquat', 'high', `"${tokenSquat}" in this address is almost identical to "${e}" (possible look-alike).`);
      }
      if (brandInOther && !indicators.some(i => i.id === 'lookalike-chars' || i.id === 'expected-as-subdomain')) {
        flag('brand-in-other-domain', 'high', `The name "${e}" appears in this address, but the registrable domain is "${curSplit.registrable}", not "${expSplit.registrable}".`);
      }
      flag('domain-mismatch', 'medium', `Domain "${curSplit.registrable}" does not match the saved domain "${expSplit.registrable}".`);
    }
    if (match === 'subdomain') {
      flag('subdomain-info', 'info', `Subdomain of the saved domain (${cur.hostname}). Usually fine; confirm it is a page you expect.`);
    }
  }

  const sev = s => indicators.some(i => i.severity === s);
  let level;
  if (match === 'no-expected') level = 'unverified';
  else if (match === 'different') level = 'suspicious';
  else if (sev('high') || sev('medium')) level = 'suspicious';  // e.g. http:// on the right domain, IP-in-userinfo
  else level = 'safe';

  const checks = [
    { id: 'https', label: 'HTTPS', ok: cur.https, detail: cur.https ? 'Encrypted connection (necessary, but not proof the site is genuine).' : 'Not encrypted.' },
    { id: 'match', label: 'Domain match', ok: match === 'exact' || match === 'subdomain', detail: ({ exact: 'Exact match with saved domain.', subdomain: 'Subdomain of the saved domain.', different: 'Different from saved domain.', 'no-expected': 'No saved domain to compare against.' })[match] },
    { id: 'lookalike', label: 'Impersonation indicators', ok: !indicators.some(i => i.severity === 'high'), detail: indicators.filter(i => i.severity === 'high').length ? `${indicators.filter(i => i.severity === 'high').length} high-risk indicator(s).` : 'None found by local heuristics.' }
  ];

  return {
    level, match,
    hostname: cur.hostname, hostnameUnicode: curUnicode,
    registrable: curSplit.registrable,
    https: cur.https, displayOrigin: cur.displayOrigin, assumedScheme: cur.assumedScheme,
    expectedHostname: exp && exp.ok ? exp.hostname : null,
    expectedRegistrable,
    indicators, checks
  };
}

/** Compare a hostname against every saved domain; returns best (closest) match info. Used by the scanner page with no chosen credential. */
export function assessAgainstVault(currentInput, entries) {
  const cur = parseUrl(currentInput);
  if (!cur.ok) return { level: 'invalid', error: cur.error, indicators: [], checks: [] };
  const withUrl = entries.filter(e => e.url && parseUrl(e.url).ok);
  const results = withUrl.map(e => ({ entry: e, a: assessDestination(currentInput, e.url) }));
  const good = results.find(r => r.a.match === 'exact' || (r.a.match === 'subdomain' && r.a.level === 'safe'));
  if (good) return { ...good.a, matchedEntryId: good.entry.id, matchedEntryName: good.entry.name };
  const lookalike = results.find(r => r.a.indicators.some(i => ['lookalike-chars', 'typosquat', 'brand-in-other-domain', 'expected-as-subdomain'].includes(i.id)));
  if (lookalike) return { ...lookalike.a, matchedEntryId: lookalike.entry.id, matchedEntryName: lookalike.entry.name, impersonates: lookalike.entry.name };
  const base = assessDestination(currentInput, '');
  base.matchedEntryId = null;
  return base;
}

/**
 * Merge a threat-intel response ({configured, available, malicious, source, ...}) into an assessment.
 * Only a configured, available source reporting a match can escalate to "malicious".
 */
export function mergeThreatIntel(assessment, ti) {
  const out = { ...assessment, threatIntel: ti || { configured: false, available: false, status: 'not-run' } };
  if (ti && ti.configured && ti.available && ti.malicious) {
    out.level = 'malicious';
    out.indicators = [...out.indicators, { id: 'threat-intel', severity: 'high', text: `Flagged by ${ti.source || 'a threat-intelligence service'}${ti.threats?.length ? ' (' + ti.threats.join(', ') + ')' : ''}.` }];
  }
  return out;
}

export const LEVEL_LABEL = {
  safe: 'Safe match', suspicious: 'Suspicious website', malicious: 'Potentially malicious', unverified: 'Unverified', invalid: 'Invalid address'
};

/** Normalise any stored URL to "host" for display. */
export function hostOf(url) {
  const p = parseUrl(url || '');
  return p.ok ? p.hostname : '';
}
