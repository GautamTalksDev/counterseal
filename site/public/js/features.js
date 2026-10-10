// The homepage's feature demos: no approval no key, the coding-agent shell map, the MCP wrapper, the two-person seal,
// Deploy Gate, Brakes and the app badge. The shell map and the MCP policy are the product's own code (copies of
// sdk/shellmap.mjs and cli/mcp-policy.mjs, loaded only when their section comes near); the other demos simulate the
// server with its real rule ids and messages. Nothing is sent anywhere. DOM is built with createElement/textContent.
const $ = (id) => document.getElementById(id);
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const wait = (ms) => new Promise((r) => setTimeout(r, RM ? 0 : ms));
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('aria-') || k.startsWith('data-')) n.setAttribute(k, v); else n[k] = v;
  }
  for (const c of kids) if (c != null) n.append(c);
  return n;
}
const out = (pre, parts) => pre.replaceChildren(...parts.map((x) => (typeof x === 'string' ? x : el('span', { class: x[0], text: x[1] }))));
const near = (node, fn) => {
  if (!node) return;
  const o = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { o.disconnect(); fn(); } }, { rootMargin: '600px 0px' });
  o.observe(node);
};
const S = (await import('/js/strings.js')).STRINGS;

// ------------------------------------------------------------------ no approval, no key
(() => {
  const FILES = {
    env: { file: '# .env, readable by the agent\nSTRIPE_SECRET_KEY=sk_live_••••••••\nGITHUB_TOKEN=ghp_••••••••\nRAILWAY_TOKEN=••••••••', leak: 'Whoever has this file holds your real keys. They can refund, pay out, delete repositories and volumes, from anywhere, at machine speed, until you rotate every one of them.' },
    token: { file: '# .env, readable by the agent\nLEASH_TOKENS=stripe=lsh_7c1e••••,github=lsh_2b9a••••\n# no real key on this machine', leak: 'Whoever has this file holds tokens, not keys. A token only works through Counterseal, within its policy, until it expires or you revoke it, and everything on the irreversible map still waits for your passkey.' },
    bound: { file: '# .env, readable by the agent\nLEASH_TOKENS=stripe=lsh_7c1e••••,github=lsh_2b9a••••\nLEASH_AGENT_KEY=agent-key.json\n# tokens bound to the agent\'s own Ed25519 key', leak: 'The tokens alone are useless: every request must be signed by the agent\'s own key, or the broker answers 401 agent_signature_required. If the key file leaks too, revoke the agent key and every token bound to it stops at once.' },
  };
  let cur = 'env';
  const show = (k, leaked = false) => {
    cur = k;
    document.querySelectorAll('.kr-tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.k === k)));
    $('krFile').textContent = FILES[k].file;
    $('krStamp').hidden = !leaked;
    $('krStamp').className = 'kr-stamp ' + (k === 'env' ? 'bad' : 'ok');
    $('krStamp').textContent = leaked ? (k === 'env' ? 'LEAKED: REAL KEYS' : 'LEAKED: NO KEY') : '';
    $('krOut').textContent = leaked ? FILES[k].leak : 'Press "Leak this file" to see what someone gets.';
    $('krOut').className = 'kr-text' + (leaked ? (k === 'env' ? ' bad' : ' ok') : '');
  };
  document.querySelectorAll('.kr-tab').forEach((t) => t.addEventListener('click', () => show(t.dataset.k)));
  $('krLeak').addEventListener('click', () => show(cur, true));
  show('env');
})();

// ------------------------------------------------------------------ the coding-agent shell map (sdk/shellmap.mjs, real)
(() => {
  const EX = ['terraform destroy -auto-approve', 'git push --force origin main', 'psql "$DATABASE_URL" -c "DROP TABLE users"', 'rm -rf ../other-project', 'railway volume delete', 'npm test', 'git status', 'ls -la src'];
  for (const c of EX) {
    const b = el('button', { class: 'chip', type: 'button', text: c });
    b.addEventListener('click', () => { $('shCmd').value = c; ask(); });
    $('shChips').append(b);
  }
  let map = null;
  const flow = $('shFlow');
  const step = (cls, who, text) => el('div', { class: 'fl ' + cls }, el('span', { class: 'fl-who', text: who }), el('span', { class: 'fl-t mono', text }));
  async function ask(e) {
    if (e) e.preventDefault();
    if (!map) return;
    const cmd = $('shCmd').value;
    const r = map.classify(cmd, { cwd: '/home/you/app', root: '/home/you/app', home: '/home/you' });
    if (r.hold) {
      const h = r.hits[0];
      out($('shOut'), [['s4', 'HELD'], `  rule ${h.rule}\n${h.why}\n`, r.hits.length > 1 ? `(+${r.hits.length - 1} more on the map)\n` : '', `\nThe agent reads:\n${S.guardHeld.replace('<why>', h.why)}`]);
      flow.replaceChildren(step('a', 'agent', cmd.length > 60 ? cmd.slice(0, 60) + '…' : cmd), step('h', 'hook', S.guardWaiting), step('p', 'your phone', 'Approve with passkey  ·  Deny'));
    } else {
      out($('shOut'), [['s2', 'NOT ON THE MAP'], `\n${r.unreadable ? 'Read piece by piece. ' : ''}Left to your agent's own permission settings.`]);
      flow.replaceChildren(step('a', 'agent', cmd.length > 60 ? cmd.slice(0, 60) + '…' : cmd), step('ok', 'hook', 'not on the map: the agent decides as usual'));
    }
  }
  $('shForm').addEventListener('submit', ask);
  near($('guard'), async () => {
    try {
      map = await import('/shellmap.js');
      $('shOut').textContent = `Shell map ${map.SHELL_MAP_VERSION}, ${map.SHELL_RULES.length} rules. Type a command or pick one.`;
      ask();
    } catch { $('shOut').textContent = 'The shell map could not load here.'; }
  });
})();

// ------------------------------------------------------------------ the MCP wrapper (cli/mcp-policy.mjs, real)
(() => {
  const CALLS = [
    { server: 'github', name: 'delete_repository', args: { owner: 'acme', repo: 'app' } },
    { server: 'postgres', name: 'query', args: { sql: 'DELETE FROM orders' } },
    { server: 'postgres', name: 'query', args: { sql: 'SELECT id, total FROM orders LIMIT 20' } },
    { server: 'stripe', name: 'create_refund', args: { charge: 'ch_demo_3Pq', amount: 4200 } },
    { server: 'slack', name: 'send_message', args: { channel: '#general', text: 'Shipping now' } },
    { server: 'files', name: 'write_file', args: { path: 'notes.md', content: '...' } },
    { server: 'linear', name: 'list_issues', args: { team: 'ENG' } },
  ];
  let P = null, policy = null, changed = false;
  const PINS = ['delete_repository', 'list_issues', 'create_refund', 'send_message', 'query'];
  const pins = () => $('mcPins').replaceChildren(...PINS.map((t) => el('li', { class: changed && t === 'list_issues' ? 'ch' : '' }, el('code', { text: t }), el('span', { text: changed && t === 'list_issues' ? 'changed: hidden from the model' : 'pinned' }))));
  pins();
  const box = $('mcCalls');
  CALLS.forEach((c) => {
    const b = el('button', { class: 'try', type: 'button', 'aria-pressed': 'false' }, el('b', { text: `${c.server}.${c.name}` }), el('span', { class: 'v', text: '' }), el('code', { text: JSON.stringify(c.args) }));
    b.addEventListener('click', () => {
      if (!P) return;
      box.querySelectorAll('.try').forEach((x) => x.setAttribute('aria-pressed', 'false'));
      b.setAttribute('aria-pressed', 'true');
      let r = P.classifyTool({ name: c.name, args: c.args }, policy);
      if (changed && c.name === 'list_issues') r = { rule: 'mcp.changed', why: P.WHY['mcp.changed'] };
      if (r) out($('mcOut'), [`tools/call ${c.name}\n\n`, ['s4', 'HELD'], `  ${r.rule}\n\nThe client reads:\n${S.mcpHeld.replace('<tool>', c.name).replace('<why>', r.why)}`]);
      else out($('mcOut'), [`tools/call ${c.name}\n\n`, ['s2', 'PASSED THROUGH'], '\nNot on the wrapper\'s lists: the server answers as usual.']);
    });
    box.append(b);
  });
  $('mcChange').addEventListener('click', () => {
    changed = !changed;
    pins();
    $('mcChange').textContent = changed ? 'Pin it again' : 'The server changes a tool';
    $('mcPinNote').textContent = changed ? P?.WHY['mcp.changed'] || '' : 'Pinned on first use, so the first look is trusted as it is.';
  });
  near($('mcp'), async () => {
    try {
      P = await import('/mcp/mcp-policy.mjs');
      policy = P.normalisePolicy(undefined);
      box.querySelectorAll('.try').forEach((b, i) => {
        const c = CALLS[i], r = P.classifyTool({ name: c.name, args: c.args }, policy);
        const v = b.querySelector('.v'); v.textContent = r ? 'held' : 'passes'; v.className = 'v ' + (r ? 'h' : 'a');
      });
    } catch { $('mcOut').textContent = 'The policy code could not load here.'; }
  });
})();

// ------------------------------------------------------------------ two-person seal
(() => {
  const st = { seals: new Set(), done: false, asker: 'ada' };
  const res = (who, t) => { const p = document.querySelector(`[data-res="${who}"]`); p.textContent = t; };
  const render = () => {
    const n = st.seals.size;
    $('tmCount').querySelectorAll('i').forEach((d, i) => d.classList.toggle('on', i < n));
    if (st.done === 'denied') return;
    $('tmState').textContent = st.done ? S.teamApproved : n === 0 ? S.teamNeeds : S.teamOneOfTwo(st.first);
  };
  const reset = () => {
    st.seals.clear(); st.done = false;
    document.querySelectorAll('[data-res]').forEach((p) => { p.textContent = ''; });
    document.querySelectorAll('#team .ph-card').forEach((c) => c.classList.remove('gone'));
    $('tmState').className = 'tm-state'; render();
  };
  document.querySelectorAll('[data-seal]').forEach((b) => b.addEventListener('click', () => {
    const who = b.dataset.seal;
    if (st.done) return;
    if ($('tmSelf').checked && who === st.asker) { res(who, 'Your own token asked, so with self-approval off your seal does not count. Two other people must approve.'); return; }
    if (st.seals.has(who)) { res(who, 'You already approved. One person counts once.'); return; }
    if (!st.seals.size) st.first = who[0].toUpperCase() + who.slice(1);
    st.seals.add(who); res(who, 'Your seal is in.');
    b.closest('.ph-card').classList.add('gone');
    if (st.seals.size >= 2) { st.done = true; $('tmState').className = 'tm-state ok'; }
    render();
  }));
  document.querySelectorAll('[data-deny]').forEach((b) => b.addEventListener('click', () => {
    if (st.done) return;
    st.done = 'denied'; res(b.dataset.deny, 'Denied.');
    $('tmState').textContent = 'Denied. Any member\'s denial ends it.'; $('tmState').className = 'tm-state bad';
    document.querySelectorAll('#team .ph-card').forEach((c) => c.classList.add('gone'));
  }));
  $('tmSelf').addEventListener('change', reset);
  $('tmReset').addEventListener('click', reset);
  render();
})();

// ------------------------------------------------------------------ Deploy Gate
(() => {
  const log = $('ghLog'), phone = $('ghPhone');
  let busy = false;
  const line = (t, cls = '') => { log.append(el('span', { class: cls, text: t + '\n' })); log.scrollTop = log.scrollHeight; };
  const idle = () => phone.replaceChildren(el('div', { class: 'ph-idle' }, el('b', { text: 'All clear' }), el('span', { text: 'No calls waiting' })));
  idle();
  log.textContent = 'Press "Run the workflow".\n';
  $('chatMsg').textContent = S.channelMessage;
  $('ghRun').addEventListener('click', async () => {
    if (busy) return;
    busy = true; $('ghRun').disabled = true; log.textContent = ''; idle();
    for (const [t, c] of S.gateLogStart) { line(t, c); await wait(380); }
    const card = el('div', { class: 'ph-card' },
      el('p', { class: 'ph-lbl', text: 'Deploy' }),
      el('b', { class: 'ph-what', text: 'acme/app to production' }),
      el('dl', { class: 'ph-facts' }, ...[['Repository', 'acme/app'], ['Commit', '9f3c1e0'], ['Workflow', 'deploy.yml'], ['Run', '#412, attempt 1'], ['Environment', 'production'], ['Started by', 'ada']].flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { class: 'mono', text: v })])),
      el('p', { class: 'ph-nv', text: 'Not verified: "Release 2.4.1"' }),
      el('div', { class: 'ph-acts' }));
    const ok = el('button', { class: 'btn btn-pri sm', type: 'button', text: 'Approve with passkey' }), no = el('button', { class: 'btn btn-ghost sm', type: 'button', text: 'Deny' });
    card.querySelector('.ph-acts').append(ok, no);
    phone.replaceChildren(card);
    const done = async (approved) => {
      phone.replaceChildren(el('div', { class: 'ph-res' }, el('b', { text: approved ? 'Approved.' : 'Denied.' }), approved ? 'That one run, once.' : 'The job fails.'));
      for (const [t, c] of approved ? S.gateLogApproved : S.gateLogDenied) { line(t, c); await wait(380); }
      busy = false; $('ghRun').disabled = false; $('ghRun').textContent = 'Run it again';
    };
    ok.addEventListener('click', () => done(true), { once: true });
    no.addEventListener('click', () => done(false), { once: true });
  });
})();

// ------------------------------------------------------------------ Brakes
(() => {
  const CALL = 5000, DAY = 50000;
  let day = 0, frozen = false, repeats = 0, tripped = false;
  const money = (c) => '$' + (c / 100).toFixed(2);
  const amt = () => Number($('bkAmt').value);
  const bar = () => { $('bkDay').textContent = money(day); $('bkBar').style.width = Math.min(100, (day / DAY) * 100) + '%'; };
  $('bkAmt').addEventListener('input', () => { $('bkAmtV').textContent = money(amt()); });
  const say = (parts) => out($('bkOut'), parts);
  const frozenAnswer = () => say(['POST /p/stripe/v1/refunds\n\n', ['s5', 'HTTP 423'], '\n' + JSON.stringify({ error: 'account_frozen', message: S.frozen }, null, 2)]);
  $('bkSend').addEventListener('click', () => {
    if (frozen) return frozenAnswer();
    const a = amt(), body = `charge=ch_demo_3Pq&amount=${a}`;
    let rule = null;
    if (a > CALL) rule = 'brake.money-per-call';
    else if (day + a > DAY) rule = 'brake.money-per-day';
    if (rule) return say([`POST /p/stripe/v1/refunds\n${body}\n\n`, ['s4', 'HTTP 428'], `  held_for_approval\nrule ${rule}\n${S.brakeWhy[rule](a, day)}\n\nYour phone asks for a passkey.`]);
    day += a; bar();
    say([`POST /p/stripe/v1/refunds\n${body}\n\n`, ['s2', 'HTTP 200'], `  x-leash-decision: allowed\nrule st.money:capped\nUnder both caps: ${money(a)} of ${money(CALL)} a call, ${money(day)} of ${money(DAY)} today (UTC).`]);
  });
  $('bkRepeat').addEventListener('click', () => {
    if (frozen) return frozenAnswer();
    repeats = Math.min(3, repeats + 1);
    $('bkDots').querySelectorAll('i').forEach((d, i) => { d.className = i < repeats ? (i === 2 ? 'trip' : 'on') : ''; });
    if (repeats >= 3 && !tripped) tripped = true;
    if (tripped) say(['PATCH /p/github/repos/acme/app\n\n', ['s4', 'HTTP 428'], `  held_for_approval\nrule brake.tripped\n${S.trippedWhy}`]);
    else say(['PATCH /p/github/repos/acme/app\n\n', ['s2', 'HTTP 200'], `  x-leash-decision: allowed\nThe same request, ${repeats} of 2 in 5 minutes.`]);
  });
  $('bkFreeze').addEventListener('click', () => {
    frozen = true; document.body.classList.add('frozen-demo');
    $('bkFreeze').disabled = true; $('bkUnfreeze').hidden = false;
    frozenAnswer();
  });
  $('bkUnfreeze').addEventListener('click', () => {
    frozen = false; tripped = false; repeats = 0; document.body.classList.remove('frozen-demo');
    $('bkFreeze').disabled = false; $('bkUnfreeze').hidden = true;
    $('bkDots').querySelectorAll('i').forEach((d) => { d.className = ''; });
    say(['Unfrozen with a passkey (simulated here). Tokens work again.']);
  });
  bar();
})();

// ------------------------------------------------------------------ the app icon badge
near($('app'), () => {
  const b = $('dockBadge');
  let n = 0;
  const tick = () => { n += 1; b.textContent = String(n); b.classList.add('on'); if (n < 3 && !RM) setTimeout(tick, 900); };
  if (RM) { b.textContent = '3'; b.classList.add('on'); } else setTimeout(tick, 600);
});
