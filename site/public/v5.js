(() => {
  'use strict';
  const root = document.documentElement;
  root.classList.add('js');

  // Theme: remembered per browser when storage works; page is fine without it.
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

  // Scroll reveals
  const still = matchMedia('(prefers-reduced-motion: reduce)');
  const rv = document.querySelectorAll('.rv');
  if (still.matches || !('IntersectionObserver' in window)) {
    for (const el of rv) el.classList.add('in');
  } else {
    const io = new IntersectionObserver((es) => {
      for (const e of es) if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
    }, { rootMargin: '0px 0px -8% 0px' });
    for (const el of rv) io.observe(el);
  }

  // Install tabs (ARIA tabs, arrow keys move between them)
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  function sel(t) {
    for (const x of tabs) {
      const on = x === t;
      x.setAttribute('aria-selected', String(on));
      x.tabIndex = on ? 0 : -1;
      document.getElementById(x.getAttribute('aria-controls')).hidden = !on;
    }
  }
  if (tabs.length) {
    sel(tabs[0]);
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => sel(t));
      t.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
        sel(n); n.focus();
      });
    });
  }

  // Typed last word of the headline (the full sentence stays in the h1 label)
  const ty = document.getElementById('ty');
  if (ty && !still.matches) {
    const word = ty.textContent;
    ty.textContent = '';
    ty.classList.add('typing');
    let i = 0;
    setTimeout(function step() {
      ty.textContent = word.slice(0, ++i);
      if (i < word.length) setTimeout(step, 70);
      else setTimeout(() => ty.classList.remove('typing'), 700);
    }, 500);
  }

  // Hero demo: a scripted picture of what the broker answers. Nothing is sent.
  const stage = document.getElementById('stage');
  if (!stage) return;
  const $ = (id) => document.getElementById(id);
  const warden = $('warden');
  const STATES = {
    held: { who: 'billing-bot', m: 'DELETE', path: 'api.stripe.com/v1/customers/cus_42', code: '428', cls: '', txt: 'Held. Waiting for your passkey.', rcpt: 'Receipt pending', label: 'holding the call' },
    approved: { who: 'billing-bot', m: 'DELETE', path: 'api.stripe.com/v1/customers/cus_42', code: '200', cls: 'ok', txt: 'Sealed with your passkey.', rcpt: 'Receipt written to the public log', label: 'showing a green approved seal' },
    cap: { who: 'research-bot', m: 'POST', path: 'model API /v1/messages', code: '402', cls: 'bad', txt: 'Budget cap hit. Never sent.', rcpt: '$15.00 of $15.00 today', label: 'showing a red cap seal' }
  };
  const order = ['held', 'approved', 'cap'];
  let cur = 'held';
  let timer = 0;

  function show(name) {
    const st = STATES[name];
    if (!st) return;
    cur = name;
    stage.dataset.s = name;
    $('who').textContent = st.who;
    $('m').textContent = st.m;
    $('path').textContent = st.path;
    const code = $('code');
    code.textContent = st.code;
    code.className = 'code' + (st.cls ? ' ' + st.cls : '');
    $('txt').textContent = st.txt;
    $('rcpt').textContent = st.rcpt;
    for (const img of warden.querySelectorAll('.w')) img.classList.toggle('on', img.dataset.w === name);
    warden.setAttribute('aria-label', 'Warden, the Counterseal mascot, ' + st.label);
    for (const b of stage.querySelectorAll('.acts button')) b.setAttribute('aria-pressed', String(b.dataset.act === name));
  }

  function stop() { if (timer) { clearInterval(timer); timer = 0; } }
  for (const b of stage.querySelectorAll('.acts button')) b.addEventListener('click', () => { stop(); show(b.dataset.act); });

  // Gentle auto play until the visitor interacts; off with reduced motion or a hidden tab.
  if (!still.matches) {
    timer = setInterval(() => {
      if (document.hidden) return;
      show(order[(order.indexOf(cur) + 1) % order.length]);
    }, 3200);
    stage.addEventListener('pointerenter', stop, { once: true });
    stage.addEventListener('focusin', stop, { once: true });
  }
})();
