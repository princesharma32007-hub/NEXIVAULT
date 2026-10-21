// NexiVault app shell: sidebar, header, routing, global event delegation, auto-lock.
import { S, subscribe, lock, loadApiStatus, commit, log } from './state.js';
import { html, icon, $, $$, toast, closeAllModals, debounce } from './util.js';
import { actions, inputs, views, registerActions, registerInputs, go, currentFromHash, rerender, ui } from './router.js';
import { renderAuth } from './auth.js';
import { analyze } from './analysis.js';

import './views/dashboard.js';
import './views/passwords.js';
import './views/notes.js';
import './views/generator.js';
import './views/security.js';
import './views/guardian.js';
import './views/scanner.js';
import './views/timeline.js';
import './views/settings.js';

const NAV = [
  ['dashboard', 'Dashboard', 'home'], ['passwords', 'Passwords', 'key'], ['notes', 'Secure Notes', 'note'], ['generator', 'Password Generator', 'zap'],
  ['security', 'Security Check', 'shield'], ['guardian', 'NexiVault Guardian', 'shieldcheck'], ['scanner', 'Website Safety Scanner', 'globe'], ['timeline', 'Activity Timeline', 'activity'], ['settings', 'Settings', 'settings']
];

export function applyTheme(t) {
  const eff = t === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : t;
  document.documentElement.dataset.theme = eff;
  try { localStorage.setItem('nexivault.theme', t); } catch { /* ignore */ }
  const b = $('#theme-btn'); if (b) b.innerHTML = String(icon(eff === 'dark' ? 'sun' : 'moon', 18));
}

function renderShell() {
  $('#root').innerHTML = html`<div class="app" id="app">
    <aside class="sidebar" id="sidebar" aria-label="Main navigation">
      <div class="brand"><span class="brand-mark">${icon('lock', 22)}</span><span class="brand-name">NexiVault</span></div>
      <nav class="grid" style="gap:6px">${NAV.map(([id, label, ic]) => html`<button class="nav-btn" data-action="nav" data-view="${id}" id="nav-${id}">${icon(ic, 19)}<span class="nav-label">${label}</span>${id === 'scanner' ? html`<span class="nav-new">NEW</span>` : ''}${id === 'guardian' ? html`<span class="badge-dot hidden" id="guardian-count"></span>` : ''}</button>`)}</nav>
      <div class="sidebar-foot">
        <button class="btn" data-action="lock-now">${icon('lock', 16)}<span>Lock vault</span></button>
        <button class="btn ghost" id="collapse-btn" data-action="collapse" aria-label="Collapse sidebar">${icon('panel', 16)}<span>Collapse</span></button>
      </div>
    </aside>
    <div class="scrim" data-action="nav-close"></div>
    <div class="main">
      <header class="topbar">
        <button class="icon-btn" id="menu-btn" data-action="nav-toggle" aria-label="Open navigation">${icon('menu', 20)}</button>
        <div class="titles"><div class="eyebrow">Personal security workspace</div><div class="tagline">Your passwords, under your control.</div></div>
        <div class="search"><label class="sr-only" for="global-search">Search passwords and websites</label>${icon('search', 18)}<input id="global-search" type="search" data-input="global-search" placeholder="Search passwords, websites…" autocomplete="off"></div>
        <button class="icon-btn" id="theme-btn" data-action="toggle-theme" aria-label="Toggle light or dark theme"></button>
        <button class="icon-btn" data-action="lock-now" aria-label="Lock vault" title="Lock vault">${icon('lock', 18)}</button>
      </header>
      <main class="content" id="view" tabindex="-1"></main>
    </div></div>`.s;
  applyTheme(S.data.settings.theme);
  if (localStorage.getItem('nexivault.collapsed') === '1') $('#app').classList.add('collapsed');
  currentFromHash(); renderView(); updateBadge();
}

function renderView() {
  if (!S.unlocked) return;
  const v = views[S.view] || views.dashboard;
  $$('.nav-btn').forEach(b => { const on = b.dataset.view === S.view; b.classList.toggle('active', on); on ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current'); });
  const el = $('#view'); if (!el) return;
  el.innerHTML = '';
  document.title = `${v.title} · NexiVault`;
  try { v.render(el, S.params || {}); } catch (e) { console.error(e); el.innerHTML = '<div class="empty"><h3>Something went wrong</h3><p>This section failed to load. Check the browser console.</p></div>'; }
  $('#app').classList.remove('nav-open');
}

function updateBadge() {
  if (!S.unlocked) return;
  const b = $('#guardian-count'); if (!b) return;
  const high = analyze(S.data); const n = [high.exposed, high.reused, high.weak].reduce((a, c) => a + (c ? 1 : 0), 0);
  b.textContent = n; b.classList.toggle('hidden', !n);
}

// ---------- global actions ----------
registerActions({
  nav: (el) => go(el.dataset.view),
  'nav-toggle': () => $('#app').classList.toggle('nav-open'),
  'nav-close': () => $('#app').classList.remove('nav-open'),
  collapse: () => { const a = $('#app'); a.classList.toggle('collapsed'); localStorage.setItem('nexivault.collapsed', a.classList.contains('collapsed') ? '1' : '0'); },
  'toggle-theme': () => { const cur = document.documentElement.dataset.theme; S.data.settings.theme = cur === 'dark' ? 'light' : 'dark'; applyTheme(S.data.settings.theme); log('settings-changed', 'Theme set to ' + S.data.settings.theme); if (S.view === 'settings') rerender(); },
  'lock-now': () => { closeAllModals(); lock('Vault locked manually'); },
  go: (el) => { let p = {}; try { p = JSON.parse(el.dataset.params || '{}'); } catch { /* ignore */ } go(el.dataset.view, p); }
});
registerInputs({
  'global-search': (el) => { ui.pw.q = el.value; if (S.view !== 'passwords') go('passwords', { keepQuery: true }); else window.dispatchEvent(new Event('nv:pw-refresh')); }
});

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]'); if (!el || el.disabled) return;
  const fn = actions[el.dataset.action];
  if (fn) { e.stopPropagation?.(); Promise.resolve(fn(el, e)).catch(err => { console.error(err); toast('Something went wrong. Please try again.', 'error'); }); }
});
document.addEventListener('input', (e) => { const el = e.target.closest('[data-input]'); if (el && inputs[el.dataset.input]) inputs[el.dataset.input](el, e); });
document.addEventListener('change', (e) => { const el = e.target.closest('[data-change]'); if (el && actions[el.dataset.change]) Promise.resolve(actions[el.dataset.change](el, e)).catch(console.error); });
document.addEventListener('keydown', (e) => {
  const el = e.target.closest?.('[data-key-enter]');
  if (el && e.key === 'Enter' && actions[el.dataset.keyEnter]) { e.preventDefault(); actions[el.dataset.keyEnter](el, e); }
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('[data-action][role="button"]')) { e.preventDefault(); e.target.click(); }
});

window.addEventListener('hashchange', () => { if (S.unlocked) { currentFromHash(); renderView(); window.scrollTo(0, 0); } });
window.addEventListener('nv:render', () => renderView());

// ---------- auto-lock ----------
const bump = debounce(() => { S.lastActivity = Date.now(); }, 400);
['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(ev => window.addEventListener(ev, () => { if (S.unlocked) bump(); }, { passive: true }));
setInterval(() => {
  if (!S.unlocked) return;
  const m = S.data.settings.autoLockMinutes;
  if (m > 0 && Date.now() - S.lastActivity > m * 60000) { closeAllModals(); lock(`Auto-locked after ${m} min of inactivity`); toast('Vault locked due to inactivity.', 'info'); }
}, 5000);

// ---------- lifecycle ----------
subscribe((what) => {
  if (what === 'lock') { closeAllModals(); renderAuth(); }
  else if (what === 'unlock') renderShell();
  else if (what === 'data') updateBadge();
});

window.matchMedia?.('(prefers-color-scheme: light)').addEventListener?.('change', () => { if (S.unlocked && S.data.settings.theme === 'system') applyTheme('system'); });

loadApiStatus();
renderAuth();
