// Counterseal service worker: turns an empty Web Push "wake up" into a notification about a held request, a command
// line sign-in or a passkey added. The push carries no data; the details come from the service over your own session.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// Freeze is on every alert that asks something of you: one tap stops every agent token (it only ever stops things; undoing
// it needs your passkey in the app).
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
      if (r.ok) {
        const { holds, signins, passkeys, frozen_at: frozenAt } = await r.json();
        const at = (x) => (x && Number.isFinite(x.created_at) ? x.created_at : 0);
        const s = Array.isArray(signins) && signins[0], k = Array.isArray(passkeys) && passkeys[0], h0 = holds && holds[0];
        if (Number.isFinite(frozenAt) && frozenAt >= at(s) && frozenAt >= at(k)) {
          title = 'Counterseal is frozen';
          body = 'Every agent token is stopped. Unfreeze it with your passkey in the app.';
          tag = 'leash-frozen'; actions = undefined;
        } else if (s && /^[0-9a-f]{24}$/.test(String(s.id)) && at(s) >= at(h0) && at(s) >= at(k)) {
          const where = [s.country, s.network].filter((x) => typeof x === 'string' && x).join(', ');
          title = 'A command line was signed in to your Counterseal account';
          body = `${where ? 'From ' + where + '. ' : ''}Not you? Tap to revoke it and everything it made.`;
          tag = 'leash-cli-' + s.id; url = '/app#cli=' + s.id;
        } else if (k && at(k) >= at(h0)) {
          title = 'A passkey was added to your Counterseal account';
          body = `${typeof k.host === 'string' ? 'For ' + k.host + '. ' : ''}Not you? Tap to review your passkeys and remove it.`;
          tag = 'leash-pk-' + String(k.id).slice(0, 24); url = '/app#account';
        } else if (holds && !holds.length) { title = 'Counterseal alerts are working'; body = 'Nothing is waiting for you right now.'; actions = undefined; }
        else if (holds && holds.length) {
          const h = holds[0];
          // a coding agent's command or tool call (asked for by its guard), a deploy, or an API call the broker held
          const who = h.token_label || h.agent || 'Your agent';
          title = h.kind === 'shell' ? `${who} wants to run a command` : h.kind === 'tool' ? `${who} wants to call a tool` : h.kind === 'deploy' ? `${who} wants to deploy` : `${who} wants to ${h.method} ${h.host}`;
          // a held Stripe refund or payout leads with its amount (Counterseal wrote that line itself, from the request)
          body = `${typeof h.headline === 'string' && h.headline ? h.headline + '\n' : ''}${h.path}\n${h.why}${holds.length > 1 ? `\n+${holds.length - 1} more waiting` : ''}`;
          tag = 'leash-' + h.id; url = '/app#hold=' + h.id;
          // after the move, the approve link points at the host where this account has a passkey (the server says which)
          if (typeof h.approve_url === 'string' && appUrl(h.approve_url)) url = h.approve_url;
        }
      }
    } catch { /* offline or signed out: the generic text still tells you to look */ }
    await self.registration.showNotification(title, { body, tag, renotify: true, requireInteraction: true, icon: '/icon-192.png', badge: '/icon-192.png', data: { url }, ...(actions ? { actions } : {}) });
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
      await self.registration.showNotification('Counterseal froze every agent token', { body: 'Every request from your agents is refused. Unfreeze needs your passkey, in the app.', tag: 'leash-frozen', icon: '/icon-192.png', badge: '/icon-192.png', data: { url: '/app' } });
      return;
    }
  } catch { /* fall through */ }
  await self.clients.openWindow(self.location.origin + '/app#freeze');
}

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  if (e.action === 'freeze') { e.waitUntil(freezeFromAlert()); return; }
  const url = appUrl((e.notification.data && e.notification.data.url) || '/app');
  if (!url) return;
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) if (url.origin === self.location.origin && new URL(c.url).pathname.startsWith('/app')) { await c.navigate(url.href); return c.focus(); }
    return self.clients.openWindow(url.href);
  })());
});
