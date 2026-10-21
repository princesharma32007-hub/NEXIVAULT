// Runs before first paint (loaded synchronously from <head>) so there is no theme flash.
(function () {
  try {
    var t = localStorage.getItem('nexivault.theme') || 'dark';
    if (t === 'system') t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    document.documentElement.dataset.theme = t;
  } catch (e) { /* storage unavailable: keep default */ }
})();
