// Verify a receipt in your browser. One API call (the log head, its signed checkpoint and the verifier key; cacheable
// for a few seconds). The bundle you paste or open never leaves this page.
import * as sdk from '/receipts-sdk.js';
import { checkPasted } from '/check.js';

const $ = (id) => document.getElementById(id);
let logKey = null;

fetch('/v1/stats').then((r) => r.json()).then(async (s) => {
  logKey = typeof s.verifier_key === 'string' ? s.verifier_key : null;
  $('vk').textContent = logKey || 'unavailable';
  $('origin').textContent = s.origin || '';
  if (!s.checkpoint) { $('head').textContent = 'The log has no entries yet.'; return; }
  try {
    const cp = await sdk.verifyCheckpoint(s.checkpoint, logKey);
    $('head').textContent = `${cp.size} entries. The latest checkpoint's signature checks out against the key above, here in your browser.`;
  } catch (e) {
    $('head').textContent = 'The latest checkpoint did not verify: ' + e.message;
  }
  $('cp').textContent = s.checkpoint;
}).catch(() => { $('head').textContent = 'Could not load the log head. Reload to try again.'; });

$('check').addEventListener('click', async () => {
  const r = await checkPasted($('bundle').value, { logKey }, sdk);
  $('out').textContent = r.text;
  $('out').className = 'verdict ' + (r.ok ? 'ok' : 'bad');
  $('out').hidden = false;
});
$('file').addEventListener('change', async (e) => {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  if (f.size > 1_000_000) { $('out').textContent = 'NOT VERIFIED\nThat file is too big to be a receipt bundle.'; $('out').hidden = false; return; }
  $('bundle').value = await f.text();
});
