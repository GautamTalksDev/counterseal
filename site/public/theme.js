// Applies the theme the visitor picked (shared with the app: localStorage "cs.theme" = light | dark | system).
// Loaded in <head> without defer so the page never flashes the wrong theme. No storage: follows the system.
try { const t = localStorage.getItem('cs.theme'); if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t); } catch (e) { /* private mode */ }
// A light/dark switch in the outer pages' nav (built with DOM calls, no innerHTML).
document.addEventListener('DOMContentLoaded', () => {
  const bar = document.querySelector('.nav .nav-r');
  if (!bar || document.getElementById('theme')) return;
  const b = document.createElement('button');
  b.type = 'button'; b.className = 'theme-sw'; b.setAttribute('aria-label', 'Switch light or dark theme');
  b.textContent = '◐';
  b.addEventListener('click', () => {
    const r = document.documentElement; const cur = r.getAttribute('data-theme');
    const dark = cur ? cur === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark'; r.setAttribute('data-theme', next);
    try { localStorage.setItem('cs.theme', next); } catch (e) { /* private mode */ }
  });
  bar.prepend(b);
});
