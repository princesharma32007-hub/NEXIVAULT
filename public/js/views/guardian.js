// NexiVault Guardian: transparent rule-based assistant. No AI service is called; no passwords leave the vault.
import { S } from '../state.js';
import { html, icon, $, esc } from '../util.js';
import { registerView, registerActions, registerInputs, ui } from '../router.js';
import { analyze, buildFindings } from '../analysis.js';
import { sortFindings } from './dashboard.js';

const chat = [];
const RISK = { high: 'bad', medium: 'warn', low: 'neutral', info: 'info' };

function answer(q, findings, an) {
  const t = q.toLowerCase();
  const pick = (id) => findings.find(f => f.id === id);
  if (/weak/.test(t)) return pick('weak') ? pick('weak').title + '. ' + pick('weak').text : 'No weak passwords detected right now.';
  if (/reus|same|duplicate/.test(t)) return pick('reused') ? pick('reused').title + '. ' + pick('reused').text : 'No reused passwords detected.';
  if (/breach|leak|expos|dark/.test(t)) return an.breachLive ? `${an.exposed} of ${an.total} passwords were found in known breaches.` : 'Breach status is unverified: run a breach check in Security Check → Breach monitoring.';
  if (/2fa|two|factor|auth/.test(t)) return an.totp ? 'Two-factor is on for NexiVault.' : 'Two-factor is off. Enable it in Settings → Security.';
  if (/phish|fake|website|domain|scam/.test(t)) return 'Use the Website Safety Scanner before signing in anywhere unfamiliar. It compares the destination’s registrable domain with your saved site and flags lookalikes, punycode and deceptive subdomains.';
  if (/score/.test(t)) return an.score == null ? 'Add passwords to get a score.' : `Your score is ${an.score}/100 (${an.grade}). It combines strength, uniqueness, age, 2FA, and breach status when that check has been run.`;
  if (/first|priority|start|what should/.test(t)) return findings.length ? 'Start with: ' + sortFindings(findings)[0].title + '. ' + sortFindings(findings)[0].text : 'Nothing urgent. You are in good shape.';
  return 'I am a rule-based helper: I can explain your weak or reused passwords, breach status, 2FA, phishing protection, your score, or what to fix first.';
}

registerView('guardian', {
  title: 'NexiVault Guardian',
  render(el) {
    const an = analyze(S.data), all = sortFindings(buildFindings(S.data, an));
    el.innerHTML = html`<div class="page-head"><div><h2>NexiVault Guardian</h2><p>A transparent, rule-based security assistant that reads vault <b>metadata</b> only. No AI service is connected and no passwords are shared.</p></div></div>
      <div class="grid g-score"><div class="card"><div class="row between"><h3>Recommendations</h3><span class="badge ${all.length ? 'warn' : 'good'}">${all.length} open</span></div>
        ${all.length ? all.map(f => html`<div class="sugg"><div class="si ${f.risk}">${icon(f.risk === 'low' ? 'info' : 'alert', 20)}</div><div class="grow"><b>${f.title}</b> <span class="badge ${RISK[f.risk]}">${f.risk} risk</span><span class="d">${f.text}</span></div><button class="btn sm" data-action="go" data-view="${f.action.view}" data-params="${JSON.stringify(f.action.params || {})}">${f.action.label}</button></div>`) : html`<div class="empty"><div class="ei">${icon('shieldcheck', 28)}</div><h3>All clear</h3><p>No open recommendations.</p></div>`}</div>
        <div class="card"><h3>Ask Guardian</h3><div class="chat" id="g-chat" aria-live="polite"><div class="bubble bot">Hi ${esc(S.data.profile.name)}. Ask about weak or reused passwords, breaches, 2FA, phishing, or “what should I fix first?”</div>${chat.map(m => html`<div class="bubble ${m.who}">${m.text}</div>`)}</div>
          <div class="chips mt-sm">${['What should I fix first?', 'Any reused passwords?', 'How do I spot phishing?'].map(q => html`<button class="chip" data-action="g-ask" data-q="${q}">${q}</button>`)}</div>
          <form id="g-form" class="input-group mt-sm" novalidate><label class="sr-only" for="g-q">Question</label><input id="g-q" placeholder="Ask a question…" autocomplete="off"><button class="btn primary" type="submit">Ask</button></form></div></div>`.s;
    $('#g-form').addEventListener('submit', (e) => { e.preventDefault(); const i = $('#g-q'); if (i.value.trim()) ask(i.value.trim()); });
    const c = $('#g-chat'); c.scrollTop = c.scrollHeight;
  }
});

function ask(q) {
  const an = analyze(S.data), f = buildFindings(S.data, an);
  chat.push({ who: 'me', text: q }, { who: 'bot', text: answer(q, f, an) });
  if (chat.length > 20) chat.splice(0, 2);
  window.dispatchEvent(new Event('nv:render'));
}
registerActions({ 'g-ask': (el) => ask(el.dataset.q) });
