import { S, saveNote, deleteNote, parseTags, log } from '../state.js';
import { html, icon, $, $$, openModal, confirmDialog, copyText, toast, fmtDate, debounce } from '../util.js';
import { registerView, registerActions, registerInputs, ui, rerender } from '../router.js';

const NOTE_CATS = ['General', 'Personal', 'Work', 'Finance', 'Recovery codes', 'Licenses'];
const noteFind = (id) => S.data.notes.find(n => n.id === id);

function filtered() {
  const q = ui.noteQ.trim().toLowerCase(), cat = ui.noteCat || 'all';
  return S.data.notes.filter(n => (cat === 'all' || n.category === cat) && (!q || [n.title, n.body, n.category, ...(n.tags || [])].join(' ').toLowerCase().includes(q.replace(/^#/, ''))))
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function renderGrid() {
  const box = $('#notes-grid'); if (!box) return;
  const list = filtered();
  if (!S.data.notes.length) box.innerHTML = html`<div class="empty" style="grid-column:1/-1"><div class="ei">${icon('note', 28)}</div><h3>No secure notes</h3><p>Store recovery codes, licence keys and private text, encrypted with your vault.</p><button class="btn primary mt" data-action="note-add">${icon('plus', 16)} New note</button></div>`.s;
  else if (!list.length) box.innerHTML = html`<div class="empty" style="grid-column:1/-1"><div class="ei">${icon('search', 28)}</div><h3>No matching notes</h3><p>Try a different search or category.</p></div>`.s;
  else box.innerHTML = list.map(n => String(html`<article class="note-card" role="button" tabindex="0" data-action="note-edit" data-id="${n.id}" aria-label="Edit note ${n.title}">
    <div class="row between"><b class="truncate">${n.title}</b><span class="badge purple">${n.category}</span></div>
    <div class="body">${n.body ? '•••• Hidden. Open to view' : 'Empty note'}</div>
    <div class="row between tiny faint"><span>${(n.tags || []).map(t => '#' + t).join(' ')}</span><span>${fmtDate(n.updatedAt)}</span></div></article>`)).join('');
}

registerView('notes', {
  title: 'Secure Notes',
  render(el) {
    el.innerHTML = html`<div class="page-head"><div><h2>Secure Notes</h2><p>Private text, encrypted together with your vault. Contents stay hidden until you open a note.</p></div><button class="btn primary" data-action="note-add">${icon('plus', 16)} New note</button></div>
      <div class="toolbar"><div class="search-lite">${icon('search', 16)}<label class="sr-only" for="note-q">Search notes</label><input id="note-q" type="search" data-input="note-q" placeholder="Search notes by title, text or #tag" value="${ui.noteQ}" autocomplete="off"></div>
        <label class="sr-only" for="note-cat">Category</label><select id="note-cat" data-change="note-cat"><option value="all">All categories</option>${[...new Set([...NOTE_CATS, ...S.data.notes.map(n => n.category)])].map(c => html`<option ${ui.noteCat === c ? 'selected' : ''}>${c}</option>`)}</select></div>
      <div class="grid g3" id="notes-grid"></div>`.s;
    renderGrid();
  }
});

registerInputs({ 'note-q': debounce((el) => { ui.noteQ = el.value; renderGrid(); }, 100) });
registerActions({
  'note-cat': (el) => { ui.noteCat = el.value; renderGrid(); },
  'note-add': () => openNote(null),
  'note-edit': (el) => openNote(noteFind(el.dataset.id))
});

function openNote(note) {
  const n = note || { title: '', body: '', category: 'General', tags: [] };
  const m = openModal(String(html`
    <div class="modal-head"><h3>${note ? 'Edit note' : 'New secure note'}</h3><button class="icon-btn sm" data-x aria-label="Close">${icon('x', 16)}</button></div>
    <form id="nf" novalidate><div class="modal-body">
      <label class="field"><span>Title *</span><input id="n-title" value="${n.title}" maxlength="100" autofocus></label>
      <div class="grid g2" style="gap:12px"><label class="field"><span>Category</span><input id="n-cat" list="n-cats" value="${n.category}"><datalist id="n-cats">${NOTE_CATS.map(c => html`<option value="${c}">`)}</datalist></label>
        <label class="field"><span>Tags (comma separated)</span><input id="n-tags" value="${(n.tags || []).join(', ')}"></label></div>
      <label class="field"><span>Note</span><textarea id="n-body" style="min-height:180px" maxlength="20000"></textarea></label>
      <div class="err" id="n-err" role="alert"></div>
    </div><div class="modal-foot">${note ? html`<button class="btn danger" type="button" id="n-del" style="margin-right:auto">${icon('trash', 15)} Delete</button><button class="btn" type="button" id="n-copy">${icon('copy', 15)} Copy contents</button>` : ''}<button class="btn ghost" type="button" data-x>Cancel</button><button class="btn primary" type="submit">Save note</button></div></form>`), { wide: true, label: 'Secure note' });
  const el = m.el; $('#n-body', el).value = n.body;
  $$('[data-x]', el).forEach(b => b.onclick = () => m.close());
  $('#nf', el).addEventListener('submit', (ev) => {
    ev.preventDefault();
    const title = $('#n-title', el).value; if (!title.trim()) { $('#n-err', el).textContent = 'Give the note a title.'; return $('#n-title', el).focus(); }
    saveNote(note?.id, { title, body: $('#n-body', el).value, category: $('#n-cat', el).value.trim() || 'General', tags: parseTags($('#n-tags', el).value) });
    toast('Note saved.', 'success'); m.close(); rerender();
  });
  if (note) {
    $('#n-copy', el).onclick = () => copyText($('#n-body', el).value, { sensitive: true, clearAfter: S.data.settings.clipboardClearSeconds, label: 'Note copied' });
    $('#n-del', el).onclick = async () => { if (await confirmDialog({ title: `Delete “${note.title}”?`, message: 'This permanently removes the note.', confirmText: 'Delete', danger: true })) { deleteNote(note.id); m.close(); toast('Note deleted.', 'success'); rerender(); } };
  }
}
