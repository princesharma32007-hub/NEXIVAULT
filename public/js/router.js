// Tiny router + shared action registry (event delegation keeps views simple and CSP-friendly).
import { S } from './state.js';

export const actions = {};
export const inputs = {};
export const views = {};
export const registerActions = (o) => Object.assign(actions, o);
export const registerInputs = (o) => Object.assign(inputs, o);
export const registerView = (id, v) => { views[id] = v; };

/** UI-only (non-persisted) state shared between header search and the passwords view. */
export const ui = { pw: { q: '', filter: 'all', category: 'all', sort: 'name' }, noteQ: '', securityTab: 'health', activityFilter: 'all', settingsSection: 'appearance' };

let pending = null;
export function go(view, params = {}) {
  pending = params;
  if (location.hash === '#' + view) { S.view = view; S.params = params; pending = null; window.dispatchEvent(new Event('nv:render')); }
  else location.hash = view;
}
export function currentFromHash() {
  const h = location.hash.replace(/^#\/?/, '');
  S.view = views[h] ? h : 'dashboard';
  S.params = pending || {}; pending = null;
}
export const rerender = () => window.dispatchEvent(new Event('nv:render'));
