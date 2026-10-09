// The free Web Bot Auth checker. The signature is verified in this browser (websig.js, the same code as the SDK);
// the only server call is the optional directory fetch. What you paste is never sent anywhere.
import { verifyRequest, parseDictionary, generateIdentity, signRequest, directory as makeDirectory } from '/websig.js';
import { checkSignature } from './check.js';

const $ = (id) => document.getElementById(id);
const show = (text, ok) => { $('out').textContent = text; $('out').className = 'verdict ' + (ok ? 'ok' : 'bad'); $('out').hidden = false; };

/** the agent origin named in Signature-Agent (dictionary form or the older bare string) */
function agentOrigin() {
  const raw = $('sa').value.trim();
  if (!raw) return null;
  try {
    const d = /^"/.test(raw) ? new Map([['', { value: parseDictionary('x=' + raw).get('x').value }]]) : parseDictionary(raw);
    for (const m of d.values()) if (typeof m.value === 'string') return new URL(m.value).origin;
  } catch { /* not parseable: the check will say so */ }
  return null;
}

$('fetchDir').addEventListener('click', async () => {
  const origin = agentOrigin();
  if (!origin) return show('NOT VALID\nPaste a Signature-Agent header first, for example sig1="https://bots.example.com".', false);
  $('fetchDir').disabled = true;
  try {
    const r = await fetch('/v1/tools/directory?agent=' + encodeURIComponent(origin));
    const j = await r.json();
    if (!r.ok) return show('Could not fetch the directory.\n' + (j.message || j.error), false);
    $('dir').value = JSON.stringify({ keys: j.keys }, null, 2);
    $('dirFrom').textContent = `Fetched from ${j.url}`;
  } catch { show('Could not fetch the directory.', false); } finally { $('fetchDir').disabled = false; }
});

$('check').addEventListener('click', async () => {
  let dir = null;
  try { dir = JSON.parse($('dir').value || 'null'); } catch { return show('NOT VALID\nThe key directory is not valid JSON.', false); }
  const r = await checkSignature({
    method: $('method').value, url: $('url').value.trim(), directory: dir,
    headers: { 'signature-input': $('si').value, signature: $('sig').value, 'signature-agent': $('sa').value },
  }, { verifyRequest });
  show(r.text, r.ok);
});

// an example made in this browser: a fresh key, a signed request and its directory (nothing is sent anywhere)
$('example').addEventListener('click', async () => {
  const id = await generateIdentity();
  const url = 'https://shop.example/checkout';
  const h = await signRequest({ method: 'GET', url }, { key: id.privateKey, keyid: id.keyid, agent: 'https://bots.example.com' });
  $('method').value = 'GET'; $('url').value = url;
  $('si').value = h['signature-input']; $('sig').value = h.signature; $('sa').value = h['signature-agent'];
  $('dir').value = JSON.stringify(makeDirectory([id.publicJwk]), null, 2);
  $('dirFrom').textContent = 'Example key made in your browser just now.';
  $('out').hidden = true;
});
