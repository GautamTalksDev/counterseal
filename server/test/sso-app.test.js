// The app's single sign-on screens (site/public/app): the links are read strictly, every element the code uses exists,
// and the screens keep to the page's CSP rules (no HTML sinks; the provider's address must be https).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../../site/public/${p}`, import.meta.url), 'utf8');

test('SSO in the app: strict #sso= links, every SSO element exists, https only, no HTML sinks', () => {
  const js = read('app/app.js'), html = read('app/index.html');
  assert.match(js, /\/\^#sso=\(\[0-9a-f\]\{24\}\)\$\//, 'a team link is exactly 24 hex characters');
  assert.match(js, /\/\^#sso-error=\(\[a-z_\]\{1,40\}\)\$\//, 'an error code is a short lower-case word');
  assert.match(js, /u\.protocol !== 'https:'/, 'the identity provider address must be https');
  assert.match(js, /history\.replaceState\(null, '', '\/app'\);\n  return true;/, 'the fragment is taken out of the address bar');
  const ids = new Set([...js.matchAll(/\$\('(sso[A-Za-z]+)'\)/g)].map((m) => m[1]));
  assert.ok(ids.size >= 15, `uses the SSO elements (${ids.size})`);
  for (const id of ids) assert.ok(html.includes(`id="${id}"`), `app/index.html has #${id}`);
  for (const p of ['/v1/sso/start', '/v1/sso/passkey/begin', '/v1/sso/passkey/finish', '/v1/team/sso', '/v1/team/sso/begin', '/v1/team/sso/finish', '/v1/team/sso/off/begin', '/v1/team/sso/off/finish']) assert.ok(js.includes(`'${p}'`), p);
  assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write/.test(js));
  assert.ok(!/<script>|\sstyle\s*=/.test(html));
});
