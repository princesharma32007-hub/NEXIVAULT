import { S, log, commit, addEntry, updateEntry, deleteEntry, restoreVersion, toggleFavorite, touchUsed, parseTags, DEFAULT_CATEGORIES } from '../state.js';
import { html, icon, raw, $, $$, openModal, confirmDialog, copyText, toast, fmtDate, fmtDateTime, timeAgo } from '../util.js';
import { registerView, registerActions, registerInputs, ui, go, rerender } from '../router.js';
import { analyze } from '../analysis.js';
import { analyzePassword, strengthClass } from '../strength.js';
import { generatePassword } from '../generator.js';
import { parseUrl, hostOf } from '../domain.js';
import { startAutofill } from './autofill.js';

const DAY = 86400000;
const PALETTE = ['#6d4cf5', '#0ea5e9', '#d97706', '#db2777', '#059669', '#7c3aed', '#2563eb', '#e11d48'];
export const avatarColor = (s) => PALETTE[[...String(s)].reduce((a, c) => a + c.charCodeAt(0), 0) % PALETTE.length];
export const avatar = (name, size) => html`<div class="avatar" style="background:${avatarColor(name)};${size ? `width:${size}px;height:${size}px` : ''}" aria-hidden="true">${(name || '?')[0].toUpperCase()}</div>`;

const FILTERS = [['all', 'All'], ['favorites', 'Favorites'], ['recent', 'Recently used'], ['strong', 'Strong'], ['weak', 'Weak'], ['reused', 'Reused'], ['old', 'Old'], ['exposed', 'Exposed']];

function visibleEntries() {
  const f = ui.pw, an = analyze(S.data), q = f.q.trim().toLowerCase();
  let list = S.data.entries.filter(e => {
    const p = an.per[e.id];
    if (f.category !== 'all' && e.category !== f.category) return false;
    switch (f.filter) {
      case 'favorites': if (!e.favorite) return false; break;
      case 'recent': if (!e.lastUsedAt || Date.now() - Date.parse(e.lastUsedAt) > 14 * DAY) return false; break;
      case 'strong': if (p.intrinsic.rating !== 'Strong') return false; break;
      case 'weak': if (p.intrinsic.rating !== 'Weak') return false; break;
      case 'reused': if (!p.reused) return false; break;
      case 'old': if (!p.old) return false; break;
      case 'exposed': if (!p.exposed) return false; break;
    }
    if (!q) return true;
    const hay = [e.name, e.username, e.email, hostOf(e.url), e.url, e.category, ...(e.tags || [])].join(' ').toLowerCase();
    return q.split(/\s+/).every(t => hay.includes(t.replace(/^#/, '')));
  });
  const by = { name: (a, b) => a.name.localeCompare(b.name), category: (a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name), created: (a, b) => b.createdAt.localeCompare(a.createdAt), updated: (a, b) => b.updatedAt.localeCompare(a.updatedAt), used: (a, b) => (b.lastUsedAt || '').localeCompare(a.lastUsedAt || '') };
  list.sort(f.filter === 'recent' ? by.used : by[f.sort] || by.name);
  return { list, an };
}

function rowHtml(e, p) {
  const rating = p.intrinsic.rating;
  return html`<div class="entry" role="button" tabindex="0" data-action="view-entry" data-id="${e.id}" aria-label="View ${e.name}">
    ${avatar(e.name)}
    <div class="grow"><div class="name"><span class="truncate">${e.name}</span>${e.favorite ? html`<span class="fav-on">${icon('star', 15)}</span>` : ''}</div><div class="sub truncate">${e.username || e.email || 'No username'}</div>
      <div class="flags mt-sm"><span class="badge ${strengthClass(rating)}">${rating}</span>${p.reused ? html`<span class="badge bad">Reused</span>` : ''}${p.exposed ? html`<span class="badge bad">Exposed</span>` : ''}${p.old ? html`<span class="badge warn">Old</span>` : ''}${p.noUrl ? html`<span class="badge neutral">No site</span>` : ''}${p.httpUrl ? html`<span class="badge warn">http://</span>` : ''}</div></div>
    <div class="meta small"><div class="truncate muted">${hostOf(e.url) || '—'}</div><span class="badge purple mt-sm">${e.category}</span> ${(e.tags || []).slice(0, 2).map(t => html`<span class="badge neutral">#${t}</span> `)}</div>
    <div class="actions">
      <button class="icon-btn sm hide-sm ${e.favorite ? 'fav-on' : ''}" data-action="fav-entry" data-id="${e.id}" aria-label="${e.favorite ? 'Remove from' : 'Add to'} favorites" aria-pressed="${!!e.favorite}">${icon('star', 15)}</button>
      <button class="icon-btn sm hide-sm" data-action="copy-user" data-id="${e.id}" aria-label="Copy username for ${e.name}" title="Copy username">${icon('user', 15)}</button>
      <button class="icon-btn sm" data-action="copy-pw" data-id="${e.id}" aria-label="Copy password for ${e.name}" title="Copy password">${icon('copy', 15)}</button>
      <button class="icon-btn sm" data-action="autofill" data-id="${e.id}" aria-label="Safe autofill check for ${e.name}" title="Safe autofill check">${icon('shieldcheck', 15)}</button>
      <button class="icon-btn sm hide-sm" data-action="open-url" data-id="${e.id}" aria-label="Open ${e.name} website" title="Open website">${icon('ext', 15)}</button>
    </div></div>`;
}

function renderList() {
  const box = $('#pw-list'); if (!box) return;
  const { list, an } = visibleEntries();
  $('#pw-count').textContent = `${list.length} of ${S.data.entries.length}`;
  $$('.chip[data-filter]').forEach(c => { const on = c.dataset.filter === ui.pw.filter; c.classList.toggle('active', on); c.setAttribute('aria-pressed', on); });
  if (!S.data.entries.length) box.innerHTML = html`<div class="empty"><div class="ei">${icon('key', 28)}</div><h3>No passwords yet</h3><p>Save your first login. It is encrypted before it touches storage.</p><button class="btn primary mt" data-action="pw-add">${icon('plus', 16)} Add password</button></div>`.s;
  else if (!list.length) box.innerHTML = html`<div class="empty"><div class="ei">${icon('search', 28)}</div><h3>No matches</h3><p>Nothing fits the current search or filter.</p><button class="btn mt" data-action="pw-reset">Clear filters</button></div>`.s;
  else box.innerHTML = list.map(e => rowHtml(e, an.per[e.id])).map(String).join('');
}

registerView('passwords', {
  title: 'Passwords',
  render(el, params) {
    if (params.filter) ui.pw.filter = params.filter; else if (!params.keepQuery && !params.add) ui.pw.filter = 'all';
    if (params.q !== undefined) ui.pw.q = params.q;
    const cats = [...new Set([...DEFAULT_CATEGORIES, ...S.data.entries.map(e => e.category)])];
    el.innerHTML = html`
      <div class="page-head"><div><h2>Passwords</h2><p>Search, organise and safely use your saved logins. <span class="badge neutral" id="pw-count"></span></p></div><button class="btn primary" data-action="pw-add">${icon('plus', 16)} Add password</button></div>
      <div class="chips mb" role="group" aria-label="Filters">${FILTERS.map(([id, l]) => html`<button class="chip" data-action="pw-filter" data-filter="${id}">${l}</button>`)}</div>
      <div class="toolbar mt-sm"><label class="sr-only" for="pw-cat">Category</label><select id="pw-cat" data-change="pw-category"><option value="all">All categories</option>${cats.map(c => html`<option ${ui.pw.category === c ? 'selected' : ''}>${c}</option>`)}</select>
        <label class="sr-only" for="pw-sort">Sort</label><select id="pw-sort" data-change="pw-sort">${[['name', 'Sort: Name'], ['category', 'Sort: Category'], ['created', 'Sort: Newest'], ['updated', 'Sort: Recently updated'], ['used', 'Sort: Recently used']].map(([v, l]) => html`<option value="${v}" ${ui.pw.sort === v ? 'selected' : ''}>${l}</option>`)}</select>
        <span class="muted small">Use the search bar above to match name, username, website or #tag.</span></div>
      <div id="pw-list"></div>`.s;
    const gs = $('#global-search'); if (gs) gs.value = ui.pw.q;
    renderList();
    if (params.add) openEntryForm();
  }
});
window.addEventListener('nv:pw-refresh', () => { if (S.view === 'passwords') renderList(); });

const find = (el) => S.data.entries.find(e => e.id === el.dataset.id);

registerActions({
  'pw-add': () => openEntryForm(),
  'pw-filter': (el) => { ui.pw.filter = el.dataset.filter; renderList(); },
  'pw-reset': () => { ui.pw = Object.assign(ui.pw, { q: '', filter: 'all', category: 'all' }); const gs = $('#global-search'); if (gs) gs.value = ''; rerender(); },
  'pw-category': (el) => { ui.pw.category = el.value; renderList(); },
  'pw-sort': (el) => { ui.pw.sort = el.value; renderList(); },
  'view-entry': (el) => openDetail(el.dataset.id),
  'edit-entry': (el) => { const e = find(el); if (e) openEntryForm(e); },
  'fav-entry': (el) => { const e = toggleFavorite(el.dataset.id); toast(e.favorite ? 'Added to favorites' : 'Removed from favorites', 'success'); renderList(); },
  'copy-user': async (el) => { const e = find(el); if (e && await copyText(e.username || e.email, { label: 'Username copied' })) { touchUsed(e.id); log('username-copied', `Copied username for "${e.name}"`); } },
  'copy-pw': async (el) => {
    const e = find(el); if (!e) return;
    // Direct copy skips the destination check; make that explicit and offer the safe route.
    if (await copyText(e.password, { sensitive: true, clearAfter: S.data.settings.clipboardClearSeconds, label: 'Password copied' })) { touchUsed(e.id); log('password-copied', `Copied password for "${e.name}" (manual copy, no site check)`); }
  },
  autofill: (el) => startAutofill(el.dataset.id),
  'open-url': (el) => openUrl(find(el))
});

function openUrl(e) {
  if (!e) return;
  const p = parseUrl(e.url || '');
  if (!p.ok) return toast(e.url ? 'The saved address is not a valid web URL.' : 'No website saved for this login.', 'warn');
  window.open(p.displayOrigin, '_blank', 'noopener,noreferrer');
  touchUsed(e.id); log('website-opened', `Opened ${p.hostname} for "${e.name}"`);
}

// ---------- add / edit form ----------
export function openEntryForm(entry = null) {
  const editing = !!entry, e = entry || { name: '', username: '', email: '', password: '', url: '', category: 'Other', tags: [], notes: '', favorite: false };
  const cats = [...new Set([...DEFAULT_CATEGORIES, ...S.data.entries.map(x => x.category)])];
  const m = openModal(String(html`
    <div class="modal-head"><h3>${editing ? 'Edit password' : 'Add password'}</h3><button class="icon-btn sm" data-x aria-label="Close">${icon('x', 16)}</button></div>
    <form id="ef" novalidate><div class="modal-body">
      <label class="field"><span>Website or app name *</span><input id="f-name" value="${e.name}" maxlength="80" autofocus></label>
      <label class="field"><span>Website URL</span><input id="f-url" value="${e.url}" placeholder="https://example.com" autocomplete="off"><span class="hint">Used to verify the destination before autofill. Path and query parameters are not saved.</span></label>
      <div class="grid g2" style="gap:12px"><label class="field"><span>Username</span><input id="f-user" value="${e.username}" autocomplete="off"></label>
        <label class="field"><span>Email</span><input id="f-email" type="email" value="${e.email}" autocomplete="off"></label></div>
      <label class="field"><span>Password *</span><div class="input-group"><input id="f-pw" type="password" autocomplete="new-password" spellcheck="false"><button class="btn" type="button" id="f-show" aria-label="Show password">${icon('eye', 16)}</button><button class="btn" type="button" id="f-gen" title="Generate">${icon('zap', 16)}</button></div><div id="f-meter"></div></label>
      <div class="grid g2" style="gap:12px"><label class="field"><span>Category</span><input id="f-cat" list="cats" value="${e.category}"><datalist id="cats">${cats.map(c => html`<option value="${c}">`)}</datalist></label>
        <label class="field"><span>Tags (comma separated)</span><input id="f-tags" value="${(e.tags || []).join(', ')}"></label></div>
      <label class="field"><span>Notes</span><textarea id="f-notes" maxlength="2000">${e.notes}</textarea></label>
      <label class="check"><input type="checkbox" id="f-fav" ${e.favorite ? 'checked' : ''}><span>Mark as favorite</span></label>
      <div class="err mt-sm" id="f-err" role="alert"></div>
    </div><div class="modal-foot"><button class="btn ghost" type="button" data-x>Cancel</button><button class="btn primary" type="submit">${editing ? 'Save changes' : 'Add password'}</button></div></form>`), { wide: true, label: editing ? 'Edit password' : 'Add password' });
  const el = m.el, pw = $('#f-pw', el);
  pw.value = e.password; // set via property so special characters are never parsed as markup
  $$('[data-x]', el).forEach(b => b.onclick = () => m.close());
  const meter = () => {
    if (!pw.value) { $('#f-meter', el).innerHTML = ''; return; }
    const others = S.data.entries.filter(x => x.id !== entry?.id && x.password === pw.value).length;
    const r = analyzePassword(pw.value, { reusedCount: others });
    $('#f-meter', el).innerHTML = `<div class="meter mt-sm"><i class="${strengthClass(r.rating)}" style="width:${Math.max(4, r.score)}%"></i></div><div class="tiny muted mt-sm"><b class="text-${strengthClass(r.rating)}">${r.rating}</b>${r.flags.length ? ' · ' + r.flags.join(' · ').replace(/</g, '&lt;') : ''}</div>`;
  };
  pw.addEventListener('input', meter); meter();
  $('#f-show', el).onclick = (ev) => { const show = pw.type === 'password'; pw.type = show ? 'text' : 'password'; ev.currentTarget.innerHTML = String(icon(show ? 'eyeoff' : 'eye', 16)); ev.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password'); };
  $('#f-gen', el).onclick = () => { const r = generatePassword(S.data.settings.gen); if (r.error) return toast(r.error, 'error'); pw.value = r.password; pw.type = 'text'; meter(); };
  $('#ef', el).addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = { name: $('#f-name', el).value, url: $('#f-url', el).value, username: $('#f-user', el).value, email: $('#f-email', el).value, password: pw.value, category: $('#f-cat', el).value.trim() || 'Other', tags: parseTags($('#f-tags', el).value), notes: $('#f-notes', el).value, favorite: $('#f-fav', el).checked };
    const err = $('#f-err', el), bad = (id, msg) => { $(id, el).classList.add('invalid'); $(id, el).focus(); err.textContent = msg; };
    $$('.invalid', el).forEach(i => i.classList.remove('invalid')); err.textContent = '';
    if (!f.name.trim()) return bad('#f-name', 'Enter a name for this login.');
    if (f.url.trim() && !parseUrl(f.url).ok) return bad('#f-url', parseUrl(f.url).error);
    if (!f.username.trim() && !f.email.trim()) return bad('#f-user', 'Enter a username or an email address.');
    if (f.email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email.trim())) return bad('#f-email', 'That email address does not look valid.');
    if (!f.password) return bad('#f-pw', 'Enter a password (or generate one).');
    if (editing) updateEntry(entry.id, f); else addEntry(f);
    toast(editing ? 'Changes saved.' : 'Password added.', 'success');
    m.close(); rerender();
  });
}

// ---------- detail view ----------
function openDetail(id) {
  const e = S.data.entries.find(x => x.id === id); if (!e) return;
  const an = analyze(S.data), p = an.per[id], r = p.full;
  const ex = S.data.breach.results[id];
  const row = (k, v) => html`<dt>${k}</dt><dd>${v}</dd>`;
  const m = openModal(String(html`
    <div class="modal-head"><div class="row">${avatar(e.name)}<div><h3>${e.name}</h3><span class="badge purple">${e.category}</span></div></div><button class="icon-btn sm" data-x aria-label="Close">${icon('x', 16)}</button></div>
    <div class="modal-body">
      <dl class="kv">
        ${row('Username', html`<span class="row"><span class="grow">${e.username || '—'}</span>${e.username ? html`<button class="icon-btn sm" data-d="user" aria-label="Copy username">${icon('copy', 14)}</button>` : ''}</span>`)}
        ${row('Email', html`<span class="row"><span class="grow">${e.email || '—'}</span>${e.email ? html`<button class="icon-btn sm" data-d="email" aria-label="Copy email">${icon('copy', 14)}</button>` : ''}</span>`)}
        ${row('Password', html`<span class="row"><span class="grow pw-display" id="d-pw">••••••••••••</span><button class="icon-btn sm" data-d="reveal" aria-label="Reveal password">${icon('eye', 14)}</button><button class="icon-btn sm" data-d="pw" aria-label="Copy password">${icon('copy', 14)}</button></span>`)}
        ${row('Website', e.url ? html`<span class="row"><span class="grow truncate">${hostOf(e.url) || e.url}</span><button class="icon-btn sm" data-d="open" aria-label="Open website">${icon('ext', 14)}</button><button class="icon-btn sm" data-d="check" aria-label="Safe autofill check">${icon('shieldcheck', 14)}</button></span>` : html`<span class="muted">None saved (autofill checks will show Unverified)</span>`)}
        ${row('Tags', (e.tags || []).length ? e.tags.map(t => html`<span class="badge neutral">#${t}</span> `) : '—')}
        ${row('Notes', e.notes || '—')}
        ${row('Created', fmtDate(e.createdAt))}${row('Updated', fmtDate(e.updatedAt))}${row('Password changed', fmtDate(e.passwordChangedAt))}${row('Last used', e.lastUsedAt ? timeAgo(e.lastUsedAt) : 'never')}
      </dl>
      <div class="card flat mt"><div class="row between"><b>Password health</b><span class="badge ${strengthClass(p.intrinsic.rating)}">${p.intrinsic.rating} · ${r.score}/100</span></div>
        <div class="meter mt-sm"><i class="${strengthClass(r.rating)}" style="width:${Math.max(4, r.score)}%"></i></div>
        <p class="tiny muted mt-sm">Estimated resistance to offline guessing: <b>${p.intrinsic.guessTime}</b> (~${p.intrinsic.bits} bits). This is an approximation under assumed attacker speed, not a guarantee.</p>
        <p class="small mt-sm">${ex ? (ex.count > 0 ? html`<span class="text-bad">Found in ${ex.count.toLocaleString()} known breach record(s) on ${fmtDate(ex.checkedAt)}.</span>` : html`<span class="text-good">Not found in the breach corpus on ${fmtDate(ex.checkedAt)}.</span>`) : html`<span class="text-info">Breach status: not checked.</span>`}</p>
        <ul class="small muted" style="margin:8px 0 0 18px;padding:0">${[...new Set([...(p.reused ? ['Use a unique password for every account.'] : []), ...p.intrinsic.tips])].slice(0, 4).map(t => html`<li>${t}</li>`)}</ul></div>
      <div class="mt"><b>Password history</b> <span class="tiny muted">(last ${e.history.length} of max 10)</span>
        ${e.history.length ? e.history.map((h, i) => html`<div class="row mt-sm small"><span class="faint">${fmtDateTime(h.changedAt)}</span><span class="grow pw-display" data-h="${i}">••••••••</span><button class="icon-btn sm" data-hr="${i}" aria-label="Reveal old password">${icon('eye', 14)}</button><button class="btn sm" data-restore="${i}">${icon('history', 13)} Restore</button></div>`) : html`<p class="muted small mt-sm">No earlier versions yet. Changing the password keeps the previous one here.</p>`}</div>
    </div>
    <div class="modal-foot"><button class="btn danger" data-d="delete">${icon('trash', 15)} Delete</button><button class="btn" data-d="edit">${icon('edit', 15)} Edit</button><button class="btn primary" data-x>Close</button></div>`), { wide: true, label: e.name + ' details' });
  const el = m.el, clear = S.data.settings.clipboardClearSeconds;
  $$('[data-x]', el).forEach(b => b.onclick = () => m.close());
  const reveal = (node, text, btn) => { const shown = node.dataset.shown === '1'; node.textContent = shown ? '••••••••••••' : text; node.dataset.shown = shown ? '0' : '1'; btn.innerHTML = String(icon(shown ? 'eye' : 'eyeoff', 14)); if (!shown) setTimeout(() => { if (node.dataset.shown === '1') { node.textContent = '••••••••••••'; node.dataset.shown = '0'; btn.innerHTML = String(icon('eye', 14)); } }, 15000); };
  const on = (k, fn) => { const b = $(`[data-d="${k}"]`, el); if (b) b.onclick = fn; };
  on('user', async () => { if (await copyText(e.username, { label: 'Username copied' })) { touchUsed(e.id); log('username-copied', `Copied username for "${e.name}"`); } });
  on('email', () => copyText(e.email, { label: 'Email copied' }));
  on('pw', async () => { if (await copyText(e.password, { sensitive: true, clearAfter: clear, label: 'Password copied' })) { touchUsed(e.id); log('password-copied', `Copied password for "${e.name}" (manual copy, no site check)`); } });
  on('reveal', (ev) => { reveal($('#d-pw', el), e.password, ev.currentTarget); });
  on('open', () => openUrl(e));
  on('check', () => { m.close(); startAutofill(e.id); });
  on('edit', () => { m.close(); setTimeout(() => openEntryForm(e), 200); });
  on('delete', async () => { if (await confirmDialog({ title: `Delete “${e.name}”?`, message: 'This removes the login and its password history from your vault. This cannot be undone.', confirmText: 'Delete', danger: true })) { deleteEntry(id); m.close(); toast('Deleted.', 'success'); rerender(); } });
  $$('[data-hr]', el).forEach(b => b.onclick = () => reveal($(`[data-h="${b.dataset.hr}"]`, el), e.history[+b.dataset.hr].password, b));
  $$('[data-restore]', el).forEach(b => b.onclick = async () => {
    const i = +b.dataset.restore;
    if (await confirmDialog({ title: 'Restore this password?', message: `Your current password will be saved to history and replaced with the version from ${fmtDateTime(e.history[i].changedAt)}. Remember the change must also be made on the website itself.`, confirmText: 'Restore' })) { restoreVersion(id, i); toast('Previous password restored.', 'success'); m.close(); rerender(); setTimeout(() => openDetail(id), 220); }
  });
}
