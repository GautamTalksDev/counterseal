// Counterseal service worker. Three jobs:
//  1. Alerts: turns an empty Web Push "wake up" into a notification about a held request, a command line sign-in, a
//     passkey added or a change to the team. The push carries no data; the details come from the service over your own
//     session. A notification only ever opens the app at the exact hold: approving always needs your passkey in the app,
//     so no notification has an Approve button (the one action offered, Freeze, only stops things).
//  2. The app icon badge: the number of held requests waiting, where the Badging API exists (installed web apps in
//     Chromium browsers on Windows, macOS and ChromeOS; Safari web apps on macOS Sonoma 14+; Home Screen web apps on
//     iOS and iPadOS 16.4+, which also need notification permission). Feature-detected; nothing happens elsewhere.
//     https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/ (Badging API on iOS 16.4)
//     https://developer.mozilla.org/en-US/docs/Web/API/Badging_API (WorkerNavigator.setAppBadge)
//  3. An offline-safe shell: the app's own files (the page, its script, styles, fonts and icons) are kept so the app
//     opens without a network and says it is offline. Nothing private is ever cached: never /v1/ (the API), /p/ (the
//     proxy) or /.well-known/, never a request with credentials in it, never a response marked no-store, and only these
//     exact paths. Network first, so a new version is used as soon as it can be fetched.
const SHELL_CACHE = 'counterseal-shell-v2';
const SHELL = ['/app', '/app/app.js', '/app/evidence.js', '/app/warden.js', '/styles.css', '/skin.css', '/app-v3.css', '/img/warden/held-still.webp', '/brand.js', '/favicon.svg', '/receipts-sdk.js', '/manifest.webmanifest',
  '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png', '/apple-touch-icon.png', '/badge-96.png',
  '/fonts/geist.woff2', '/fonts/geist-mono.woff2', '/fonts/instrument-serif-italic.woff2'];
const SHELL_SET = new Set(SHELL);
const PRIVATE = /^\/(v1|p|\.well-known)(\/|$)/;

/** the one rule for what may be cached: a same-origin GET for one of the shell's own files, with no credentials in it */
function cacheable(request) {
  if (request.method !== 'GET') return false;
  let u;
  try { u = new URL(request.url); } catch { return false; }
  if (u.origin !== self.location.origin || PRIVATE.test(u.pathname) || u.search) return false;
  if (request.headers.get('authorization')) return false;
  return SHELL_SET.has(u.pathname);
}
/** a response may be kept only if it is a plain 200 from us that does not say no-store or private */
const keepable = (r) => !!r && r.ok && r.status === 200 && r.type === 'basic' && !/no-store|private/i.test(r.headers.get('cache-control') || '');

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(SHELL_CACHE);
    // one by one, so a missing file never stops the install; credentials are never sent for these
    await Promise.all(SHELL.map(async (p) => { try { const r = await fetch(p, { credentials: 'omit', cache: 'no-cache' }); if (keepable(r)) await c.put(p, r); } catch { /* offline install: later */ } }));
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== SHELL_CACHE) await caches.delete(k);
  await self.clients.claim();
})()));

self.addEventListener('fetch', (e) => {
  const req = e.request;
  // the app's page, opened from the icon, a shortcut or a notification (any #fragment): the same /app shell
  const nav = req.mode === 'navigate' && new URL(req.url).pathname === '/app' && new URL(req.url).origin === self.location.origin;
  if (!nav && !cacheable(req)) return; // the browser does what it always does; nothing is stored
  e.respondWith((async () => {
    const key = nav ? '/app' : new URL(req.url).pathname;
    try {
      const r = await fetch(req);
      if (keepable(r)) { const copy = r.clone(); e.waitUntil(caches.open(SHELL_CACHE).then((c) => c.put(key, copy))); }
      return r;
    } catch (err) {
      const hit = await caches.match(key, { cacheName: SHELL_CACHE });
      if (hit) return hit;
      throw err;
    }
  })());
});

/** the app icon badge: the number waiting, or cleared; silently nothing where the Badging API is missing */
async function badge(n) {
  try {
    if (!('setAppBadge' in self.navigator)) return;
    // Linux and Android have no app badges, and calling it from a worker there crashed headless Chromium in our browser
    // test (9 Oct 2026); ChromeOS (CrOS) has badges
    if (/Linux/.test(self.navigator.userAgent) && !/CrOS/.test(self.navigator.userAgent)) return;
    if (n > 0) await self.navigator.setAppBadge(n); else await self.navigator.clearAppBadge();
  } catch { /* not allowed here (no permission, not installed): the notification still shows */ }
}
// (the page sets the badge itself after it loads the list; nothing is posted to this worker)

// Freeze is on every alert that asks something of you: one tap stops every agent token (it only ever stops things;
// undoing it needs your passkey in the app). There is never an Approve action.
const FREEZE = [{ action: 'freeze', title: 'Freeze everything' }];

self.addEventListener('push', (e) => {
  e.waitUntil((async () => {
    let title = 'Counterseal: a request may be waiting';
    let body = 'Open Counterseal to check. (Could not load the details on this device.)';
    let tag = 'leash-hold', url = '/app', actions = FREEZE;
    try {
      // held requests, command line sign-ins and passkeys added in the last 15 minutes, and whether everything is frozen;
      // the newest event is shown (a freeze, which stops holds from mattering, outranks the holds)
      const r = await fetch('/v1/alerts', { credentials: 'same-origin', cache: 'no-store' });
      // signed out on this device: a session that ended, or a person removed from a team (their last alert)
      if (r.status === 401) { title = 'Counterseal: this device is signed out'; body = 'Sign in to see what happened. If you were removed from a team, your passkey no longer works for it.'; actions = undefined; }
      if (r.ok) {
        const { holds, signins, passkeys, frozen_at: frozenAt, team } = await r.json();
        if (Array.isArray(holds)) await badge(holds.length);
        const at = (x) => (x && Number.isFinite(x.created_at) ? x.created_at : 0);
        // a hold that someone just sealed (one of two) counts as new: that alert asks the next approver to look
        const heldAt = (h) => Math.max(at(h), ...(h && Array.isArray(h.votes) ? h.votes.map((v) => (Number.isFinite(v.at) ? v.at : 0)) : [0]));
        const byNewest = Array.isArray(holds) ? [...holds].sort((a, b) => heldAt(b) - heldAt(a)) : holds;
        const s = Array.isArray(signins) && signins[0], k = Array.isArray(passkeys) && passkeys[0], h0 = byNewest && byNewest[0];
        // team events (someone joined, a role changed, someone was removed, the protection will be lowered)
        const t = Array.isArray(team) && team[0], tAt = t && Number.isFinite(t.at) ? t.at : 0;
        if (Number.isFinite(frozenAt) && frozenAt >= at(s) && frozenAt >= at(k) && frozenAt >= tAt) {
          title = 'Counterseal is frozen';
          body = 'Every agent token is stopped. Unfreeze it with your passkey in the app.';
          tag = 'leash-frozen'; actions = undefined;
        } else if (t && tAt >= heldAt(h0) && tAt >= at(s) && tAt >= at(k)) {
          const n = typeof t.name === 'string' && t.name ? t.name : 'Someone';
          const role = (x) => (typeof x === 'string' ? x : 'a member');
          const seals = (q, sa) => `${q === 1 ? 'one seal' : `${q} seals from different people`}${sa === false ? ', never the person who asked' : ''}`;
          tag = 'leash-team-' + tAt; url = '/app#team';
          if (t.kind === 'member_joined') { title = `${n} joined your Counterseal team`; body = `As ${role(t.role)}. Not expected? Tap to review your team and remove them.`; }
          else if (t.kind === 'member_role_changed') { title = `${n} is now ${role(t.to)} on your Counterseal team`; body = `Was ${role(t.from)}. Not expected? Tap to review your team.`; actions = undefined; }
          else if (t.kind === 'member_removed') { title = `${n} was removed from your Counterseal team`; body = 'Their sessions, passkeys and keys were revoked.'; actions = undefined; }
          else if (t.kind === 'quorum_lowering' && t.to && Number.isFinite(t.effective_at)) {
            title = 'Counterseal: protection will be lowered';
            body = `From ${new Date(t.effective_at).toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' })}, held actions will need ${seals(t.to.quorum, t.to.selfApprove)}. Not expected? Tap to cancel it with your passkey.`;
          } else if (t.kind === 'breakglass_opened') {
            title = 'Counterseal: break glass is open';
            body = `Held actions are being let through${Number.isFinite(t.minutes) ? ` for up to ${t.minutes} minutes` : ''}, and every call it lets through is on the record. Not expected? Tap to close it.`;
            tag = 'leash-breakglass'; actions = undefined;
          } else if (t.kind === 'breakglass_closed') { title = 'Counterseal: break glass was closed'; body = 'Held actions wait for approval again.'; actions = undefined; }
          else if (t.kind === 'channel_added') { title = 'A channel now hears your Counterseal alerts'; body = `${t.channel === 'slack' ? 'Slack' : t.channel === 'discord' ? 'Discord' : t.channel === 'gchat' ? 'Google Chat' : 'A chat service'} was connected. It is only told: nobody can approve from it. Not expected? Tap to review.`; actions = undefined; }
          else { title = 'Counterseal: the lowering of protection was cancelled'; body = 'Nothing changes.'; actions = undefined; }
        } else if (s && /^[0-9a-f]{24}$/.test(String(s.id)) && at(s) >= heldAt(h0) && at(s) >= at(k)) {
          const where = [s.country, s.network].filter((x) => typeof x === 'string' && x).join(', ');
          title = 'A command line was signed in to your Counterseal account';
          body = `${where ? 'From ' + where + '. ' : ''}Not you? Tap to revoke it and everything it made.`;
          tag = 'leash-cli-' + s.id; url = '/app#cli=' + s.id;
        } else if (k && at(k) >= heldAt(h0)) {
          title = 'A passkey was added to your Counterseal account';
          body = `${typeof k.host === 'string' ? 'For ' + k.host + '. ' : ''}Not you? Tap to review your passkeys and remove it.`;
          tag = 'leash-pk-' + String(k.id).slice(0, 24); url = '/app#account';
        } else if (holds && !holds.length) { title = 'Counterseal alerts are working'; body = 'Nothing is waiting for you right now.'; actions = undefined; }
        else if (holds && holds.length) {
          const h = h0;
          // a coding agent's command or tool call (asked for by its guard), a deploy, the built-in demo, or an API call the
          // broker held
          const who = h.token_label || h.agent || (h.kind === 'demo' ? 'The demo agent' : 'Your agent');
          title = h.kind === 'demo' ? 'Demo: the practice agent wants to delete a repository' : h.kind === 'shell' ? `${who} wants to run a command` : h.kind === 'tool' ? `${who} wants to call a tool` : h.kind === 'deploy' ? `${who} wants to deploy` : `${who} wants to ${h.method} ${h.host}`;
          if (h.kind === 'demo') actions = undefined; // the demo never offers Freeze: nothing real is at stake
          // two seals: how many it has (the next approver is who this alert is for)
          const need = Number.isInteger(h.needs) ? h.needs : 1, got = Array.isArray(h.votes) ? h.votes.length : 0;
          const seals = need > 1 ? `\n${got} of ${need} seals${got ? ': needs another approver' : ''}` : '';
          // a held Stripe refund or payout leads with its amount (Counterseal wrote that line itself, from the request)
          body = `${typeof h.headline === 'string' && h.headline ? h.headline + '\n' : ''}${h.path}\n${h.why}${seals}${holds.length > 1 ? `\n+${holds.length - 1} more waiting` : ''}\nTap to review. Approving needs your passkey in the app.`;
          tag = 'leash-' + h.id; url = '/app#hold=' + h.id;
          if (typeof h.approve_url === 'string' && appUrl(h.approve_url)) url = h.approve_url;
        }
      }
    } catch { /* offline or signed out: the generic text still tells you to look */ }
    await self.registration.showNotification(title, { body, tag, renotify: true, requireInteraction: true, icon: '/icon-192.png', badge: '/badge-96.png', data: { url }, ...(actions ? { actions } : {}) });
  })());
});

/** an https link to a dashboard (/app), as the service sends it for a hold; anything else is ignored */
function appUrl(u) {
  try { const x = new URL(u, self.location.origin); return x.protocol === 'https:' || x.origin === self.location.origin ? (x.pathname === '/app' ? x : null) : null; } catch { return null; }
}

/** the Freeze button on an alert: freeze from here, over the browser's own session, and say what happened. If that does
 * not work (signed out, offline), open the app at its Freeze button instead; nothing claims a freeze that did not happen. */
async function freezeFromAlert() {
  try {
    const r = await fetch('/v1/me/freeze', { method: 'POST', credentials: 'same-origin', headers: { 'x-leash': '1', 'content-type': 'application/json' }, body: '{}' });
    if (r.ok) {
      await self.registration.showNotification('Counterseal froze every agent token', { body: 'Every request from your agents is refused. Unfreeze needs your passkey, in the app.', tag: 'leash-frozen', icon: '/icon-192.png', badge: '/badge-96.png', data: { url: '/app' } });
      return;
    }
  } catch { /* fall through */ }
  await self.clients.openWindow(self.location.origin + '/app#freeze');
}

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  if (e.action === 'freeze') { e.waitUntil(freezeFromAlert()); return; }
  // any other action or a tap on the notification itself only opens the app at that hold; it never approves anything
  const url = appUrl((e.notification.data && e.notification.data.url) || '/app');
  if (!url) return;
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) if (url.origin === self.location.origin && new URL(c.url).pathname.startsWith('/app')) { await c.navigate(url.href); return c.focus(); }
    return self.clients.openWindow(url.href);
  })());
});
