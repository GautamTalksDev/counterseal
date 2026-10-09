// The in-browser verifier's verdict, kept apart from the page so it can be tested. A pasted bundle is checked against
// this log's own verifier key (served by this site), never against the key inside the bundle: anyone can make a key.
// The "Load a sample" bundle is signed with a throwaway key made in this browser, and its verdict says so.
const iso = (t) => (Number.isFinite(t) ? new Date(t).toISOString() : 'unknown');

/** text: the pasted JSON; logKey: this log's verifier key; demoKey: the sample's throwaway key; sdk: { verifyBundle, printable? } */
export async function checkPasted(text, { logKey, demoKey } = {}, sdk) {
  const p = sdk.printable || String;
  let b;
  try { b = JSON.parse(text); } catch { return { ok: false, text: 'NOT VERIFIED\nThat is not valid JSON.' }; }
  const demo = typeof demoKey === 'string' && !!b && b.log === demoKey;
  const key = demo ? demoKey : logKey;
  if (typeof key !== 'string') return { ok: false, text: "NOT VERIFIED\nThis log's verifier key could not be read, so there is nothing to check against. Reload and try again." };
  if (!demo && b && typeof b === 'object' && b.log !== undefined && b.log !== key) {
    return { ok: false, text: "NOT VERIFIED\nThis bundle names a different log key than this log's own key, so it was not issued by this log." };
  }
  try {
    const r = await sdk.verifyBundle(b, key);
    const rc = r.receipt || {};
    return {
      ok: true, demo,
      text: [
        demo ? 'VERIFIED (DEMO KEY)' : 'VERIFIED',
        `entry #${r.index} of ${r.treeSize} in ${p(r.origin)}`,
        `${p(rc.agent)}: ${p(rc.action)}${rc.decision ? ' (' + p(rc.decision) + ')' : ''}`,
        r.broker ? 'recorded by the broker itself, not reported by an agent' : 'reported by an agent with a receipts API key',
        `received ${iso(r.receivedAt)}`,
        '',
        demo ? 'This sample is signed with a throwaway key made in your browser. It is not this log and proves nothing about it.'
          : `Checked against this log's verifier key:\n${key}`,
      ].join('\n'),
    };
  } catch (e) {
    return { ok: false, text: 'NOT VERIFIED\n' + (e && e.message ? e.message : 'the bundle does not verify') };
  }
}
