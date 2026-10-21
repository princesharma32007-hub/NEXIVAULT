import { S, commit } from '../state.js';
import { html, icon, toast, confirmDialog, fmtDateTime } from '../util.js';
import { registerView, registerActions, ui, rerender } from '../router.js';

const FILTERS = [['all', 'All'], ['vault', 'Vault'], ['passwords', 'Passwords'], ['autofill', 'Autofill & websites'], ['scans', 'Scans'], ['sync', 'Sync'], ['settings', 'Settings']];
const GROUP = (t) => /^vault/.test(t) ? 'vault' : /^(password|username|note)/.test(t) ? 'passwords' : /^(autofill|suspicious|website)/.test(t) ? 'autofill' : /^scan/.test(t) ? 'scans' : /^sync/.test(t) ? 'sync' : /^settings/.test(t) ? 'settings' : 'other';
const ICON = (t) => ({ vault: 'lock', passwords: 'key', autofill: 'shieldcheck', scans: 'globe', sync: 'cloud', settings: 'settings', other: 'activity' })[GROUP(t)];

registerView('timeline', {
  title: 'Activity Timeline',
  render(el, params) {
    if (params.filter) ui.activityFilter = params.filter;
    const f = ui.activityFilter, list = S.data.activity.filter(a => f === 'all' || GROUP(a.type) === f);
    const days = new Map();
    for (const a of list) { const k = new Date(a.ts).toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' }); (days.get(k) || days.set(k, []).get(k)).push(a); }
    el.innerHTML = html`<div class="page-head"><div><h2>Activity Timeline</h2><p>A local record of important events. Passwords and secrets are never written here.</p></div><button class="btn" data-action="tl-clear" ${S.data.activity.length ? '' : 'disabled'}>${icon('trash', 15)} Clear</button></div>
      <div class="chips">${FILTERS.map(([id, l]) => html`<button class="chip ${f === id ? 'active' : ''}" data-action="tl-filter" data-f="${id}">${l}</button>`)}</div>
      ${list.length ? [...days].map(([day, items]) => html`<div class="tl-day">${day}</div>${items.map(a => html`<div class="tl"><div class="ti ${a.severity}">${icon(ICON(a.type), 18)}</div><div class="grow"><div>${a.text}</div><div class="tiny faint">${fmtDateTime(a.ts)} · ${a.type}</div></div></div>`)}`) : html`<div class="empty mt"><div class="ei">${icon('activity', 28)}</div><h3>No events</h3><p>Nothing matches this filter yet.</p></div>`}`.s;
  }
});
registerActions({
  'tl-filter': (el) => { ui.activityFilter = el.dataset.f; rerender(); },
  'tl-clear': async () => { if (await confirmDialog({ title: 'Clear activity log?', message: 'This removes the local activity history. Security statistics that rely on it (like website warnings) reset too.', confirmText: 'Clear', danger: true })) { S.data.activity = []; commit(); toast('Activity cleared.', 'success'); rerender(); } }
});
