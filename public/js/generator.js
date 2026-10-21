// Cryptographically secure password / passphrase generation. Uses crypto.getRandomValues only.

const SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~'
};
const AMBIGUOUS = /[0O1lI|`'"]/g;

// Unbiased random integer in [0, max) using rejection sampling.
export function randomInt(max) {
  if (max <= 0 || max > 0xffffffff) throw new RangeError('max out of range');
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) { const j = randomInt(i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; }
  return arr;
}

export function generatePassword(opts) {
  const o = { length: 20, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: false, ...opts };
  const length = Math.floor(Number(o.length));
  if (!Number.isFinite(length) || length < 4 || length > 128) return { error: 'Length must be between 4 and 128.' };
  const pools = [];
  for (const k of ['upper', 'lower', 'digits', 'symbols']) {
    if (!o[k]) continue;
    let set = SETS[k];
    if (o.noAmbiguous) set = set.replace(AMBIGUOUS, '');
    if (set) pools.push(set);
  }
  if (!pools.length) return { error: 'Select at least one character type.' };
  if (length < pools.length) return { error: `Length must be at least ${pools.length} to include every selected type.` };
  // Guarantee one from each selected pool, fill the rest from the union, then shuffle.
  const all = pools.join('');
  const chars = pools.map(p => p[randomInt(p.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  return { password: shuffle(chars).join(''), bits: Math.round(length * Math.log2(all.length)) };
}

// 256-word list => exactly 8 bits per word.
const WORDS = ('able acid aged also area army atom aunt away baby back ball band bank barn base bath bead beam bean bear beat bell belt bend bike bird blow blue boat body bold bolt bomb bone book boom boot born boss bowl bulb bulk burn bush busy cafe cage cake calm camp card care cart case cash cast cave cell chef chip city clay clip club coal coat code coin cold cook cool cope copy cord core corn cost crew crop crow cube curl dark dart dash data dawn deal dear deck deep deer desk dial dice diet dish dive dock dome door dose down draw drop drum duck dust duty each earn ease east easy edge emit epic even exam exit face fact fair fall farm fast fate fern file film find fine fire firm fish fist flag flat flex flip flow foam fold folk food foot fork form fort four frog fuel full fund gain game gate gear gift glad glow glue goal goat gold golf gown grab gray grid grin grip grow gulf hair half hall hand hard harp hawk heal heat helm help herb hero hill hint hive hold hole home hood hook hope horn host hour hunt hush icon idea inch iron isle item jade jazz jelly join joke jump jury keen keep kelp kind king kite knee knot lake lamp land lane lark last lawn leaf lean lens life lift lime line lion list live loaf lock loft long loop lore lush mail main mango maple mask mast math maze meal melt menu mesh mild milk mind mint moon moss myth nail navy neat nest news nice node noon note oath oval pace pack page palm park path peak pear pine plum pond pool port pure quay quiz race rain ramp reef rice ring road rock roof rope rose ruby sail salt sand seed silk snow soil song star tide tile tree').split(' ').slice(0, 256);

export function generatePassphrase({ words = 5, separator = '-', capitalize = true, addNumber = false } = {}) {
  const n = Math.floor(Number(words));
  if (!Number.isFinite(n) || n < 3 || n > 12) return { error: 'Use between 3 and 12 words.' };
  const list = WORDS.length === 256 ? WORDS : WORDS;
  const picked = Array.from({ length: n }, () => list[randomInt(list.length)]).map(w => capitalize ? w[0].toUpperCase() + w.slice(1) : w);
  let phrase = picked.join(separator);
  let bits = Math.round(n * Math.log2(list.length));
  if (addNumber) { phrase += separator + randomInt(100); bits += Math.round(Math.log2(100)); }
  return { password: phrase, bits, wordlistSize: list.length };
}

export function randomBytesB64(n) {
  const b = new Uint8Array(n); crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b));
}
