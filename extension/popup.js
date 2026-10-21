const sel = document.getElementById('entry'), vd = document.getElementById('verdict'), btn = document.getElementById('fill');
const LABEL = { safe: 'Safe match', suspicious: 'Suspicious: fill blocked', malicious: 'Potentially malicious: fill blocked', unverified: 'Unverified: fill blocked', invalid: 'Cannot check this page' };
async function refresh() {
  const r = await chrome.runtime.sendMessage({ type: 'assess', entryId: sel.value });
  vd.className = 'v ' + r.level; vd.textContent = `${LABEL[r.level]} · ${r.hostname || ''}`; btn.disabled = r.level !== 'safe';
}
(async () => {
  const entries = (await chrome.storage.session.get('entries')).entries || [];
  sel.innerHTML = entries.map(e => `<option value="${e.id}"></option>`).join('');
  [...sel.options].forEach((o, i) => { o.textContent = entries[i].name; });
  if (!entries.length) { vd.textContent = 'No credentials loaded.'; return; }
  sel.onchange = refresh; refresh();
})();
btn.onclick = async () => { const r = await chrome.runtime.sendMessage({ type: 'fill', entryId: sel.value }); vd.textContent = r.ok ? 'Filled.' : 'Blocked: ' + r.level; };
