// Inner pages (docs, verify, checker, log, security, privacy, terms): the wax light behind the page and the current
// section highlighted in the table of contents.
import { waxLight } from '/js/bg.js';
waxLight();
const links = new Map([...document.querySelectorAll('.toc a')].map((a) => [a.getAttribute('href').slice(1), a]));
const io = new IntersectionObserver((es) => {
  for (const e of es) if (e.isIntersecting) { for (const a of links.values()) a.classList.remove('cur'); links.get(e.target.id)?.classList.add('cur'); }
}, { rootMargin: '-15% 0px -75% 0px' });
for (const id of links.keys()) { const h = document.getElementById(id); if (h) io.observe(h); }
