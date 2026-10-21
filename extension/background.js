// Service worker. Holds the *decrypted* credential list only in memory (chrome.storage.session) after the user
// unlocks via the popup; it is never exposed to web pages. Pages only ever receive the single credential the
// user explicitly chose, and only after assessDestination() returns "safe" for the TAB'S OWN URL.
import { assessDestination } from './domain.js';

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only accept messages from this extension's own pages (popup), never from content scripts or web pages.
  if (sender.id !== chrome.runtime.id || sender.tab) return false;
  if (msg.type === 'assess') {
    chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
      const entries = (await chrome.storage.session.get('entries')).entries || [];
      const a = (entries.find(e => e.id === msg.entryId));
      sendResponse(assessDestination(tab?.url || '', a?.url || ''));   // URL comes from the browser, not the page
    });
    return true;
  }
  if (msg.type === 'fill') {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const entries = (await chrome.storage.session.get('entries')).entries || [];
      const e = entries.find(x => x.id === msg.entryId);
      const verdict = assessDestination(tab?.url || '', e?.url || '');
      if (!e || verdict.level !== 'safe') return sendResponse({ ok: false, reason: 'blocked', level: verdict.level });
      // Fill only the top frame of the verified tab; never subframes (avoids third-party iframe exposure).
      await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: fillFields, args: [e.username || e.email, e.password] });
      sendResponse({ ok: true });
    })();
    return true;
  }
});

function fillFields(user, pass) {
  const pw = document.querySelector('input[type=password]');
  if (!pw) return;
  const form = pw.form || document;
  const u = form.querySelector('input[type=email], input[autocomplete=username], input[type=text]');
  const set = (el, v) => { const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value'); d.set.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); };
  if (u) set(u, user); set(pw, pass);
}
