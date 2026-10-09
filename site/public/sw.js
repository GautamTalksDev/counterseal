// Counterseal service worker: turns an empty Web Push "wake up" into a notification about a held request, a command
// line sign-in or a passkey added. The push carries no data; the details come from the service over your own session.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  e.waitUntil((async () => {
    let title = 'Counterseal: a request may be waiting';
    let body = 'Open Counterseal to check. (Could not load the details on this device.)';
    let tag = 'leash-hold', url = '/app';
    try {
      // held requests, and command line sign-ins and passkeys added in the last 15 minutes; the newest event is shown
      const r = await fetch('/v1/alerts', { credentials: 'same-origin', cache: 'no-store' });
      if (r.ok) {
        const { holds, signins, passkeys } = await r.json();
        const at = (x) => (x && Number.isFinite(x.created_at) ? x.created_at : 0);
        const s = Array.isArray(signins) && signins[0], k = Array.isArray(passkeys) && passkeys[0], h0 = holds && holds[0];
        if (s && /^[0-9a-f]{24}$/.test(String(s.id)) && at(s) >= at(h0) && at(s) >= at(k)) {
          const where = [s.country, s.network].filter((x) => typeof x === 'string' && x).join(', ');
          title = 'A command line was signed in to your Counterseal account';
          body = `${where ? 'From ' + where + '. ' : ''}Not you? Tap to revoke it and everything it made.`;
          tag = 'leash-cli-' + s.id; url = '/app#cli=' + s.id;
        } else if (k && at(k) >= at(h0)) {
          title = 'A passkey was added to your Counterseal account';
          body = `${typeof k.host === 'string' ? 'For ' + k.host + '. ' : ''}Not you? Tap to review your passkeys and remove it.`;
          tag = 'leash-pk-' + String(k.id).slice(0, 24); url = '/app#account';
        } else if (holds && !holds.length) { title = 'Counterseal alerts are working'; body = 'Nothing is waiting for you right now.'; }
        else if (holds && holds.length) {
          const h = holds[0];
          // a coding agent's command or tool call (asked for by its guard), a deploy, or an API call the broker held
          const who = h.token_label || h.agent || 'Your agent';
          title = h.kind === 'shell' ? `${who} wants to run a command` : h.kind === 'tool' ? `${who} wants to call a tool` : h.kind === 'deploy' ? `${who} wants to deploy` : `${who} wants to ${h.method} ${h.host}`;
          body = `${h.path}\n${h.why}${holds.length > 1 ? `\n+${holds.length - 1} more waiting` : ''}`;
          tag = 'leash-' + h.id; url = '/app#hold=' + h.id;
          // after the move, the approve link points at the host where this account has a passkey (the server says which)
          if (typeof h.approve_url === 'string' && appUrl(h.approve_url)) url = h.approve_url;
        }
      }
    } catch { /* offline or signed out: the generic text still tells you to look */ }
    await self.registration.showNotification(title, { body, tag, renotify: true, requireInteraction: true, icon: '/icon-192.png', badge: '/icon-192.png', data: { url } });
  })());
});

/** an https link to a dashboard (/app), as the service sends it for a hold; anything else is ignored */
function appUrl(u) {
  try { const x = new URL(u, self.location.origin); return x.protocol === 'https:' || x.origin === self.location.origin ? (x.pathname === '/app' ? x : null) : null; } catch { return null; }
}

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = appUrl((e.notification.data && e.notification.data.url) || '/app');
  if (!url) return;
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) if (url.origin === self.location.origin && new URL(c.url).pathname.startsWith('/app')) { await c.navigate(url.href); return c.focus(); }
    return self.clients.openWindow(url.href);
  })());
});
