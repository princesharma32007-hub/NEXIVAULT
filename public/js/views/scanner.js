// Website Safety Scanner page.
import { S, log, commit } from '../state.js';
import { html, icon, $, toast, timeAgo } from '../util.js';
import { registerView, registerActions, rerender } from '../router.js';
import { assessAgainstVault, mergeThreatIntel, parseUrl, LEVEL_LABEL } from '../domain.js';
import { checkThreatIntel, verdictBanner, assessmentDetails, recommendations, recordScan, tiText } from './autofill.js';

let last = null, lastInput = '', scanning = false;
const LVL_BADGE = { safe: 'good', suspicious: 'warn', malicious: 'bad', unverified: 'info', invalid: 'neutral' };
const EXAMPLES = ['https://paypa1.com/login', 'https://paypal.com.account-verify.net', 'http://github.com', 'https://xn--pypal-4ve.com'];

async function scan(input) {
  lastInput = input; scanning = true; last = null; rerender();
  const p = parseUrl(input);
  if (!p.ok) { last = { level: 'invalid', error: p.error, indicators: [], checks: [] }; scanning = false; return rerender(); }
  const local = assessAgainstVault(input, S.data.entries);
  const ti = await checkThreatIntel(p.displayOrigin);
  last = mergeThreatIntel(local, ti);
  recordScan(last.hostname, last.level, 'scanner', last.matchedEntryName);
  log(last.level === 'safe' ? 'scan-completed' : 'suspicious-domain', `Scanned ${last.hostname}: ${LEVEL_LABEL[last.level]}`, last.level === 'safe' ? 'success' : last.level === 'malicious' ? 'error' : 'warn');
  scanning = false; await commit(); rerender();
}

registerView('scanner', {
  title: 'Website Safety Scanner',
  render(el, params) {
    const api = S.api, ti = api?.threatIntel;
    el.innerHTML = html`<div class="page-head"><div><h2>Website Safety Scanner</h2><p>Check a link against your saved logins <b>before</b> visiting or entering a password. The address is never opened.</p></div></div>
      <div class="grid g-score"><div class="card"><form id="sc-form" class="input-group" novalidate><label class="sr-only" for="sc-url">Website address</label><input id="sc-url" placeholder="https://example.com/login" autocomplete="off" autofocus><button class="btn primary" type="submit" ${scanning ? 'disabled' : ''}>${scanning ? html`<span class="spinner"></span> Scanning` : html`${icon('globe', 16)} Scan Website`}</button></form>
        <div class="chips mt-sm"><span class="tiny faint" style="align-self:center">Try:</span>${EXAMPLES.map(x => html`<button class="chip" data-action="sc-example" data-url="${x}">${x.replace('https://', '')}</button>`)}</div>
        <div class="mt">${last ? html`${verdictBanner(last)}${last.level !== 'invalid' ? html`<div class="mt">${assessmentDetails(last)}</div>${last.impersonates ? html`<div class="note-banner warn mt">${icon('alert', 16)}<div>This address looks like an imitation of your saved login <b>${last.impersonates}</b>.</div></div>` : ''}<h4 class="mt">Recommended actions</h4><ul class="small muted" style="margin:6px 0 0 18px">${recommendations(last).map(r => html`<li>${r}</li>`)}</ul>` : ''}` : html`<div class="empty"><div class="ei">${icon('globe', 28)}</div><h3>No scan yet</h3><p>Enter a URL above. Only the domain is analysed; your passwords are never involved.</p></div>`}</div></div>
        <div class="grid" style="align-content:start">
          <div class="card"><h3>Check sources</h3>
            <div class="row between small" style="padding:6px 0"><span>Domain &amp; lookalike analysis</span><span class="badge good">Local heuristics</span></div>
            <div class="row between small" style="padding:6px 0"><span>Threat intelligence</span><span class="badge ${ti?.configured ? 'good' : 'neutral'}">${ti?.configured ? ti.provider : 'Not configured'}</span></div>
            <p class="tiny faint mt-sm">${ti?.configured ? 'Only the site origin (no path or query) is sent from your server to the provider. Your passwords are never sent.' : 'To enable real reputation checks, set GOOGLE_SAFE_BROWSING_KEY on the server (see README). Without it, results never claim a site is “malicious”; they show Suspicious, Unverified or Safe match from local checks.'}</p>
            <p class="tiny faint">HTTPS is shown as a transport indicator only: phishing sites commonly use it too.</p></div>
          <div class="card"><div class="row between"><h3>Recent scans</h3>${S.data.scans.length ? html`<button class="btn sm ghost" data-action="sc-clear">Clear</button>` : ''}</div>
            ${S.data.scans.length ? S.data.scans.slice(0, 8).map(s => html`<div class="row small" style="padding:6px 0"><span class="badge ${LVL_BADGE[s.level]}">${LEVEL_LABEL[s.level]}</span><span class="grow truncate">${s.host}</span><span class="tiny faint">${timeAgo(s.ts)}</span></div>`) : html`<p class="muted small">History shows hostnames only (never paths or queries).</p>`}</div>
          <div class="card"><h3>Browser extension</h3><p class="small muted">A web page cannot read other tabs or fill other sites. The <code>extension/</code> folder contains a Manifest V3 skeleton that reads the active tab’s hostname, runs these same checks, and only fills after you click, never on mismatched domains. See the README for the integration plan.</p></div>
        </div></div>`.s;
    $('#sc-form').addEventListener('submit', (e) => { e.preventDefault(); scan($('#sc-url').value); });
    $('#sc-url').value = params.url ?? lastInput;
    if (params.auto && params.url) { params.auto = false; scan(params.url); }
  }
});
registerActions({
  'sc-example': (el) => scan(el.dataset.url),
  'sc-clear': () => { S.data.scans = []; commit(); rerender(); toast('Scan history cleared.', 'success'); }
});
