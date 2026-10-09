// The free Web Bot Auth checker's verdict, kept apart from the page so it can be tested. Everything runs in your
// browser with the same code as the SDK (websig.js): the request you paste is never sent anywhere. The only server
// call the page makes is to fetch the agent's public key directory, if you ask it to.
const clean = (v) => String(v ?? '').replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16)}}`).slice(0, 300);
const iso = (s) => (Number.isFinite(s) ? new Date(s * 1000).toISOString() : 'unknown');

/** input: {method, url, headers: {signature, signature-input, signature-agent}, directory: {keys: [...]}}
 *  lib: {verifyRequest} from websig.js. Returns {ok, text, agent?}. Never throws. */
export async function checkSignature({ method = 'GET', url, headers = {}, directory }, lib, now) {
  try {
    if (typeof url !== 'string' || !/^https?:\/\//.test(url)) return { ok: false, text: 'NOT VALID\nPaste the full URL the agent requested, starting with https://.' };
    const h = new Headers();
    for (const [k, v] of Object.entries(headers || {})) if (typeof v === 'string' && v.trim()) h.set(k, v.trim());
    if (!directory || !Array.isArray(directory.keys)) return { ok: false, text: 'NOT VALID\nNo key directory to check against. Fetch it, or paste the JSON the agent publishes.' };
    let asked = null;
    const v = await lib.verifyRequest({ method: String(method).toUpperCase(), url, headers: h }, {
      fetchDirectory: async (origin) => { asked = origin; return directory; },
      now,
    });
    if (!v.ok) return { ok: false, agent: asked, text: `NOT VALID\n${clean(v.reason)}${asked ? `\nagent: ${clean(asked)}` : ''}` };
    return {
      ok: true, agent: v.agent,
      text: [
        'SIGNATURE VALID',
        `agent: ${clean(v.agent)}`,
        `keyid: ${clean(v.keyid)}`,
        `valid from ${iso(v.created)} to ${iso(v.expires)}`,
        v.nonce ? 'The nonce was not checked: this tool stores nothing, so it cannot tell a replayed request. Your server must keep nonces (see the docs).'
          : 'No nonce: a signature without one can be replayed until it expires (5 minutes at most).',
        '',
        'This checks the signature against the key directory shown above. It does not say who runs that origin.',
      ].join('\n'),
    };
  } catch (e) {
    return { ok: false, text: 'NOT VALID\n' + clean(e && e.message) };
  }
}
