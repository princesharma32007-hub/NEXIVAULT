// Password strength estimation. Heuristic and approximate, NOT a guarantee of safety.

const COMMON = new Set(('password,123456,12345678,123456789,qwerty,abc123,111111,123123,password1,iloveyou,admin,welcome,monkey,dragon,letmein,login,master,sunshine,princess,football,baseball,shadow,superman,michael,trustno1,passw0rd,p@ssw0rd,qwerty123,1q2w3e4r,zaq12wsx,qazwsx,starwars,whatever,freedom,hello,hello123,charlie,donald,batman,access,flower,696969,mustang,jordan,harley,ranger,buster,thomas,tigger,robert,soccer,hockey,killer,george,andrew,jennifer,joshua,pepper,daniel,summer,winter,spring,autumn,cheese,computer,internet,ginger,cookie,orange,banana,welcome1,changeme,secret,test,test123,guest,root,toor,administrator,default,temp123,qwertyuiop,asdfghjkl,zxcvbnm,1234,12345,1234567,1234567890,0987654321,987654321,000000,121212,654321,666666,7777777,nexivault,vault,india,cricket,krishna,sartaj,passw0rd1,pass,pass123,abcd1234,abcdef,letmein1,iloveyou1,welcome123,admin123,qwer1234,google,facebook,amazon,netflix').split(','));

const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];

function hasSequence(pw, len = 4) {
  const s = pw.toLowerCase();
  const runs = ['abcdefghijklmnopqrstuvwxyz', '0123456789', ...KEYBOARD_ROWS];
  for (const run of runs) {
    for (let i = 0; i + len <= run.length; i++) {
      const frag = run.slice(i, i + len);
      if (s.includes(frag) || s.includes([...frag].reverse().join(''))) return true;
    }
  }
  return false;
}

function leetFold(s) {
  return s.toLowerCase().replace(/[@4]/g, 'a').replace(/[3]/g, 'e').replace(/[1!|]/g, 'i').replace(/[0]/g, 'o').replace(/[5$]/g, 's').replace(/[7]/g, 't');
}

export function charsetSize(pw) {
  let n = 0;
  if (/[a-z]/.test(pw)) n += 26;
  if (/[A-Z]/.test(pw)) n += 26;
  if (/[0-9]/.test(pw)) n += 10;
  if (/[^A-Za-z0-9]/.test(pw)) n += 33;
  return n || 1;
}

function formatDuration(seconds) {
  if (!isFinite(seconds)) return 'centuries and beyond';
  if (seconds < 1) return 'less than a second';
  const units = [['year', 31557600], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  if (seconds > 31557600 * 1e9) return 'billions of years';
  if (seconds > 31557600 * 1e6) return 'millions of years';
  if (seconds > 31557600 * 1000) return 'thousands of years';
  for (const [name, s] of units) {
    if (seconds >= s) { const v = Math.floor(seconds / s); return `about ${v.toLocaleString()} ${name}${v === 1 ? '' : 's'}`; }
  }
  return 'seconds';
}

/**
 * @param {string} pw
 * @param {{reusedCount?: number, exposedCount?: number|null}} ctx  reusedCount = how many OTHER saved accounts share it;
 *        exposedCount = known-breach count (null/undefined = not checked)
 */
export function analyzePassword(pw, ctx = {}) {
  const tips = [];
  const flags = [];
  if (!pw) return { score: 0, rating: 'Weak', label: 'Empty', bits: 0, guessTime: '-', tips: ['Enter a password to evaluate it.'], flags: [] };

  const len = [...pw].length;
  let pool = charsetSize(pw);
  let bits = len * Math.log2(pool);

  // Repeated characters/blocks reduce effective length.
  const unique = new Set(pw).size;
  if (unique <= Math.ceil(len / 3)) { bits *= 0.5; flags.push('Heavy character repetition'); tips.push('Avoid repeating the same characters or blocks.'); }
  else if (/(.)\1{2,}/.test(pw)) { bits -= 6; flags.push('Repeated characters'); }
  if (/^(.{1,4})\1+$/.test(pw)) { bits = Math.min(bits, 20); flags.push('Repeating pattern'); }

  if (hasSequence(pw)) { bits -= 12; flags.push('Sequential or keyboard pattern'); tips.push('Avoid predictable sequences like "1234", "abcd" or "qwerty".'); }
  if (/(19|20)\d{2}/.test(pw)) { bits -= 6; flags.push('Contains a year'); tips.push('Avoid years, birthdays and other personal information.'); }

  const lower = pw.toLowerCase();
  const folded = leetFold(pw);
  const stripped = folded.replace(/[^a-z]/g, '');
  const baseWord = lower.replace(/[^a-z0-9]/g, '');
  let common = COMMON.has(lower) || COMMON.has(folded) || COMMON.has(baseWord);
  if (!common) {
    // common word plus a few digits/symbols (e.g., "Password123!")
    const core = folded.replace(/[^a-z]/g, '');
    for (const c of COMMON) { if (c.length >= 5 && /^[a-z]+$/.test(c) && core === c) { common = true; break; } }
    if (!common) for (const c of COMMON) { if (c.length >= 5 && /^[a-z]+$/.test(c) && (stripped.startsWith(c) || stripped.endsWith(c)) && stripped.length <= c.length + 4) { flags.push('Built on a common word'); bits = Math.min(bits, 28); tips.push('Avoid common words, even with digits or symbols added.'); break; } }
  }
  if (common) { bits = Math.min(bits, 10); flags.push('Appears in common-password lists'); tips.push('This is a commonly used password. Replace it immediately.'); }

  bits = Math.max(0, bits);

  // Reuse and exposure override
  let penalty = 0;
  if (ctx.reusedCount > 0) { penalty += 30; flags.push(`Reused on ${ctx.reusedCount} other account${ctx.reusedCount > 1 ? 's' : ''}`); tips.push('Use a unique password for every account.'); }
  if (ctx.exposedCount > 0) { penalty += 50; flags.push('Found in known data breaches'); tips.push('Replace compromised credentials now: it is public knowledge.'); }

  if (len < 12) tips.push('Increase length. 14+ characters (or a 5-word passphrase) is a strong baseline.');
  if (len >= 12 && pool < 36 && !flags.length) tips.push('Mix in more character types or use a longer passphrase.');

  let score = Math.round(Math.min(100, (bits / 80) * 100));
  score = Math.max(0, Math.min(100, score - penalty));
  if (common) score = Math.min(score, 8);
  if (len < 8) score = Math.min(score, 30);

  const rating = score >= 70 ? 'Strong' : score >= 40 ? 'Medium' : 'Weak';
  // Offline fast-hash attacker, 1e10 guesses/second. Very rough; real hashing is usually slower.
  const guessTime = formatDuration(Math.pow(2, Math.min(bits, 200)) / 2 / 1e10);
  if (!tips.length) tips.push('Looks good. Keep it unique and enable two-factor authentication where possible.');
  return { score, rating, bits: Math.round(bits), guessTime, tips: [...new Set(tips)], flags, length: len, charset: pool };
}

export const strengthClass = r => r === 'Strong' ? 'good' : r === 'Medium' ? 'warn' : 'bad';

/** Build a map entryId -> reuse count across vault entries, without exposing passwords. */
export function reuseMap(entries) {
  const by = new Map();
  for (const e of entries) { if (!e.password) continue; (by.get(e.password) || by.set(e.password, []).get(e.password)).push(e.id); }
  const out = {};
  for (const ids of by.values()) for (const id of ids) out[id] = ids.length - 1;
  return out;
}
