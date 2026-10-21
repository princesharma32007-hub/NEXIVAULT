import { S, commit } from '../state.js';
import { html, icon, $, toast, copyText } from '../util.js';
import { registerView, registerActions, registerInputs } from '../router.js';
import { generatePassword, generatePassphrase } from '../generator.js';
import { analyzePassword, strengthClass } from '../strength.js';
import { openEntryForm } from './passwords.js';

let mode = 'password', current = '';

function generate() {
  const g = S.data.settings.gen;
  const r = mode === 'password' ? generatePassword(g) : generatePassphrase({ words: g.words, separator: g.separator ?? '-', capitalize: g.capitalize ?? true, addNumber: g.addNumber ?? false });
  const out = $('#gen-out'), err = $('#gen-err'); if (!out) return;
  if (r.error) { err.textContent = r.error; out.textContent = ''; current = ''; $('#gen-strength').innerHTML = ''; $$btns(true); return; }
  err.textContent = ''; current = r.password; out.textContent = r.password; $$btns(false);
  const a = analyzePassword(r.password);
  $('#gen-strength').innerHTML = `<div class="meter"><i class="${strengthClass(a.rating)}" style="width:${Math.max(4, a.score)}%"></i></div>
    <div class="row between small mt-sm"><b class="text-${strengthClass(a.rating)}">${a.rating}</b><span class="muted">Generated entropy ≈ ${r.bits} bits · guess time ${a.guessTime}</span></div>
    <p class="tiny faint mt-sm">Estimates are approximate and assume an offline attacker; real-world resistance depends on how the site stores passwords.</p>`;
}
const $$btns = (dis) => ['#gen-copy', '#gen-save'].forEach(s => { const b = $(s); if (b) b.disabled = dis; });

registerView('generator', {
  title: 'Password Generator',
  render(el) {
    const g = S.data.settings.gen;
    const chk = (k, l) => html`<label class="check"><input type="checkbox" data-change="gen-opt" data-k="${k}" ${g[k] ? 'checked' : ''}><span>${l}</span></label>`;
    el.innerHTML = html`<div class="page-head"><div><h2>Password Generator</h2><p>Created with your browser’s cryptographic random number generator. Nothing is sent anywhere.</p></div></div>
      <div class="grid g2"><div class="card">
        <div class="tabs" role="tablist"><button class="tab ${mode === 'password' ? 'active' : ''}" role="tab" data-action="gen-mode" data-mode="password">Password</button><button class="tab ${mode === 'passphrase' ? 'active' : ''}" role="tab" data-action="gen-mode" data-mode="passphrase">Passphrase</button></div>
        <div class="gen-out" aria-live="polite"><span id="gen-out"></span><button class="icon-btn" data-action="gen-new" aria-label="Regenerate" title="Regenerate">${icon('refresh', 18)}</button></div>
        <div id="gen-strength" class="mt"></div><div class="err mt-sm" id="gen-err" role="alert"></div>
        <div class="row wrap mt"><button class="btn primary" id="gen-copy" data-action="gen-copy">${icon('copy', 16)} Copy</button><button class="btn" data-action="gen-new">${icon('refresh', 16)} Regenerate</button><button class="btn" id="gen-save" data-action="gen-save">${icon('plus', 16)} Save as new login</button></div></div>
        <div class="card"><h3>Options</h3>
          ${mode === 'password' ? html`
            <label class="field"><span>Length: <b id="len-v">${g.length}</b></span><input type="range" min="8" max="64" value="${g.length}" data-input="gen-len" aria-label="Password length"></label>
            <div class="grid g2" style="gap:10px">${chk('upper', 'Uppercase (A–Z)')}${chk('lower', 'Lowercase (a–z)')}${chk('digits', 'Numbers (0–9)')}${chk('symbols', 'Symbols (!@#$…)')}</div>
            <div class="mt">${chk('noAmbiguous', 'Exclude ambiguous characters (0 O 1 l I |)')}</div>` : html`
            <label class="field"><span>Words: <b id="len-v">${g.words}</b></span><input type="range" min="3" max="10" value="${g.words}" data-input="gen-words" aria-label="Number of words"></label>
            <label class="field"><span>Separator</span><select data-change="gen-sep">${[['-', 'Hyphen (-)'], ['.', 'Dot (.)'], ['_', 'Underscore (_)'], [' ', 'Space'], ['', 'None']].map(([v, l]) => html`<option value="${v}" ${(g.separator ?? '-') === v ? 'selected' : ''}>${l}</option>`)}</select></label>
            ${chk('capitalize', 'Capitalise words')}<div class="mt-sm">${chk('addNumber', 'Add a number')}</div>
            <p class="tiny muted mt">Words are drawn uniformly from a 256-word list (8 bits per word). Use 5+ words for important accounts.</p>`}
          <p class="tiny faint mt">These choices are saved as your defaults (Settings → Generator).</p></div></div>`.s;
    generate();
  }
});

registerActions({
  'gen-mode': (el) => { mode = el.dataset.mode; window.dispatchEvent(new Event('nv:render')); },
  'gen-new': () => generate(),
  'gen-copy': async () => { if (current) await copyText(current, { sensitive: true, clearAfter: S.data.settings.clipboardClearSeconds, label: 'Copied' }); },
  'gen-save': () => { if (current) openEntryForm({ name: '', username: '', email: '', password: current, url: '', category: 'Other', tags: [], notes: '', favorite: false }); },
  'gen-opt': (el) => { const g = S.data.settings.gen; g[el.dataset.k] = el.checked; if (mode === 'password' && !['upper', 'lower', 'digits', 'symbols'].some(k => g[k])) { generate(); return; } commit(); generate(); },
  'gen-sep': (el) => { S.data.settings.gen.separator = el.value; commit(); generate(); }
});
registerInputs({
  'gen-len': (el) => { S.data.settings.gen.length = +el.value; $('#len-v').textContent = el.value; commit(); generate(); },
  'gen-words': (el) => { S.data.settings.gen.words = +el.value; $('#len-v').textContent = el.value; commit(); generate(); }
});
