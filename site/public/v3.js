(() => {
  'use strict';
  const root = document.documentElement;

  // Theme: remembered per browser when storage works; page is fine without it.
  try { const t = localStorage.getItem('cs.theme'); if (t === 'light' || t === 'dark') root.dataset.theme = t; } catch (e) { /* no storage */ }
  const themeBtn = document.getElementById('theme');
  if (themeBtn) themeBtn.addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark';
    root.dataset.theme = next;
    try { localStorage.setItem('cs.theme', next); } catch (e) { /* no storage */ }
  });

  // Copy buttons
  for (const b of document.querySelectorAll('button.copy')) {
    b.addEventListener('click', async () => {
      const cp = b.querySelector('.cp');
      try { await navigator.clipboard.writeText(b.dataset.copy); cp.textContent = 'Copied'; } catch (e) { cp.textContent = 'Select it'; }
      b.classList.add('done');
      setTimeout(() => { b.classList.remove('done'); cp.textContent = 'Copy'; }, 1800);
    });
  }

  // Warden demo: a scripted picture of what the product answers. Nothing is sent.
  const sprite = document.getElementById('sprite');
  const warden = document.getElementById('warden');
  const req = document.getElementById('req');
  const res = document.getElementById('res');
  const approveBtn = document.getElementById('approveBtn');
  if (!sprite) return;
  const still = matchMedia('(prefers-reduced-motion: reduce)');

  const STATES = {
    calm: { label: 'calm', m: 'GET', path: 'api.stripe.com/v1/customers', code: '200', cls: 'ok', text: 'Reads run. Nothing to approve. Press 1 to try a delete.' },
    held: { label: 'holding the call', m: 'DELETE', path: 'api.stripe.com/v1/customers/cus_42', code: '428', cls: 'warn', text: 'Held. Waiting for your passkey (press 2).' },
    approved: { label: 'approved', m: 'DELETE', path: 'api.stripe.com/v1/customers/cus_42', code: '200', cls: 'ok', text: 'Sealed with your passkey. Receipt logged.' },
    cap: { label: 'cap hit', m: 'POST', path: 'model API /v1/messages', code: '402', cls: 'bad', text: 'budget_exhausted. The call was never sent.' }
  };

  function line(el, a, b) {
    el.replaceChildren();
    const s = document.createElement('span');
    s.className = a.cls;
    s.textContent = a.text;
    el.append(s, document.createTextNode(' ' + b));
  }

  function show(name) {
    const st = STATES[name];
    if (!st) return;
    sprite.classList.remove('anim');
    sprite.dataset.s = name;
    if (!still.matches) { void sprite.offsetWidth; sprite.classList.add('anim'); }
    warden.setAttribute('aria-label', 'Warden, ' + st.label);
    line(req, { cls: 'm', text: st.m }, st.path);
    line(res, { cls: 'code ' + st.cls, text: st.code }, st.text);
    approveBtn.disabled = name !== 'held';
  }

  for (const b of document.querySelectorAll('.acts button')) b.addEventListener('click', () => show(b.dataset.act));
  sprite.dataset.s = 'held';

  // Warm the sprite sheets after load so the first press does not flash.
  addEventListener('load', () => {
    if (still.matches) return;
    for (const k of Object.keys(STATES)) { const i = new Image(); i.decoding = 'async'; i.src = '/img/warden/' + k + '.webp'; }
  });
})();
