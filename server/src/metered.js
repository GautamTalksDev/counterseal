// Budget seal, the pure half: the AI model APIs Counterseal meters, their price table, and how a call's cost is
// estimated before it goes and read from the provider's answer after it came back. src/budget.js keeps the state.
//
// These two providers are proxied like the ten in the irreversible map (src/providers.js): the agent holds a Counterseal
// token, the real key stays in the vault. They are not part of the public irreversible map (its version and its "10 APIs"
// claim are unchanged): what Counterseal adds for them is the meter and the caps. Their few irreversible rules (deletes,
// organisation admin calls) are held the same way as everywhere else.
//
// Prices: USD per million tokens, kept here in code, read by hand from the providers' own pages on PRICES_DATE. They
// go stale. A model that is not in the table is "unpriced": it is never guessed. Each token may make a small number of
// unpriced calls a day (UNPRICED_DEFAULT, or the account's own number); past that they wait for a passkey approval.
// Every estimate leans high on purpose (cache reads and writes are charged at the dearer rate, see costOf).

export const PRICES_DATE = '2026-10-10';
export const PRICE_SOURCES = {
  openai: 'https://developers.openai.com/api/docs/pricing',
  anthropic: 'https://platform.claude.com/docs/en/about-claude/pricing',
};
/** calls a token may make each UTC day to a model or a paid path with no price, before they wait for approval */
export const UNPRICED_DEFAULT = 10;
/** what an estimate assumes the answer will be when the request names no output limit */
export const DEFAULT_OUTPUT_TOKENS = 4096;
export const MAX_OUTPUT_TOKENS = 1_000_000;

// [input, output, cache read (null: charged as input)] in USD per million tokens, Standard tier.
// OpenAI, short context (up to 272K input tokens), read on 10 Oct 2026 from PRICE_SOURCES.openai.
const OPENAI = {
  'gpt-6-astra': [10, 50, 1], 'gpt-6.1-sol': [2, 10, 0.1], 'gpt-6-luna': [0.1, 0.5, 0.01], 'gpt-6-sol': [2, 10, 0.2],
  'gpt-5.6-sol': [4, 20, 0.4], 'gpt-5.6-terra': [2, 12, 0.2], 'gpt-5.6-luna': [0.2, 1.2, 0.02],
  'gpt-5.5': [5, 30, 0.5], 'gpt-5.5-pro': [30, 180, null], 'gpt-5.4': [2.5, 15, 0.25], 'gpt-5.4-mini': [0.75, 4.5, 0.075],
  'gpt-5.4-nano': [0.2, 1.25, 0.02], 'gpt-5.4-pro': [30, 180, null], 'gpt-5.2': [1.75, 14, 0.175], 'gpt-5.2-pro': [21, 168, null],
  'gpt-5.1': [1.25, 10, 0.125], 'gpt-5': [1.25, 10, 0.125], 'gpt-5-mini': [0.25, 2, 0.025], 'gpt-5-nano': [0.05, 0.4, 0.005],
  'gpt-5-pro': [15, 120, null], 'gpt-4.1': [2, 8, 0.5], 'gpt-4.1-mini': [0.4, 1.6, 0.1], 'gpt-4.1-nano': [0.1, 0.4, 0.025],
  'gpt-4o': [2.5, 10, 1.25], 'gpt-4o-2024-05-13': [5, 15, null], 'gpt-4o-mini': [0.15, 0.6, 0.075],
  o1: [15, 60, 7.5], 'o1-pro': [150, 600, null], 'o3-pro': [20, 80, null], o3: [2, 8, 0.5], 'o4-mini': [1.1, 4.4, 0.275], 'o3-mini': [1.1, 4.4, 0.55],
  'gpt-4-turbo-2024-04-09': [10, 30, null], 'gpt-4-0613': [30, 60, null], 'gpt-3.5-turbo': [0.5, 1.5, null], 'gpt-3.5-turbo-0125': [0.5, 1.5, null],
  'gpt-3.5-turbo-1106': [1, 2, null], 'gpt-3.5-turbo-instruct': [1.5, 2, null],
};
// Anthropic, base input, output and cache hits, read on 10 Oct 2026 from PRICE_SOURCES.anthropic; model ids from
// https://platform.claude.com/docs/en/about-claude/models/overview. Haiku 5.5 has two tiers; the dearer one (prompts over
// 100,000 tokens) is used for every call. Cache writes are charged at the 1 hour rate, twice the input price.
const ANTHROPIC = {
  'claude-fable-5-1': [10, 50, 0.25], 'claude-opus-5-5': [4, 20, 0.2], 'claude-sonnet-5-5': [2, 10, 0.1], 'claude-haiku-5-5': [0.5, 2.5, 0.05],
  'claude-opus-4-6': [5, 25, 0.5], 'claude-sonnet-4-6': [3, 15, 0.3], 'claude-opus-4-5': [5, 25, 0.5], 'claude-sonnet-4-5': [3, 15, 0.3],
  'claude-haiku-4-5': [1, 5, 0.1],
};
export const PRICES = { openai: OPENAI, anthropic: ANTHROPIC };

/** the price of a model, or null when it is unpriced. Exact names only; on Anthropic a dated snapshot of a listed model
 * ("claude-sonnet-4-5-20250929") is that model. Nothing else is matched, so a new model is unpriced, never guessed. */
export function priceOf(provider, model) {
  const t = PRICES[provider];
  if (!t || typeof model !== 'string' || model.length > 100) return null;
  if (Object.hasOwn(t, model)) return t[model];
  if (provider === 'anthropic') {
    const m = /^(claude-[a-z0-9-]+?)-20\d{6}$/.exec(model);
    if (m && Object.hasOwn(t, m[1])) return t[m[1]];
  }
  return null;
}

const MICRO = 1_000_000;
/** micro dollars for this many tokens at this price per million (rounded up) */
const at = (tokens, perM) => Math.ceil((tokens * Math.round(perM * MICRO)) / MICRO);
/** the cost of a call in micro dollars from its usage: {input, output, cacheRead, cacheWrite}. Input that was a cache hit
 * is charged at the cache price where the table has one; cache writes at twice the input price (the dearer, 1 hour rate). */
export function costOf(price, u) {
  const [inP, outP, crP] = price;
  return at(u.input, inP) + at(u.output, outP) + at(u.cacheRead, crP ?? inP) + at(u.cacheWrite, inP * 2);
}

// ---------------------------------------------------------------- which calls are metered
// metered: the call returns token usage that is priced. free: costs nothing at the provider. Every other write on these
// two hosts may cost money in a way the meter cannot read (images, audio, batches, fine tuning, vector stores), so it is
// "unpriced" and counts against the daily allowance of unpriced calls.
const PATHS = {
  openai: { metered: /^\/v1\/(chat\/completions|responses|completions)$/, free: /^\/v1\/(files|uploads(\/[A-Za-z0-9_-]+(\/(parts|complete|cancel))?)?|responses\/input_tokens)$/ },
  anthropic: { metered: /^\/v1\/messages$/, free: /^\/v1\/messages\/count_tokens$/ },
};
/** 'metered', 'free' or 'unpriced' for a write to one of the metered providers; null for anything else (no meter) */
export function meterKind(provider, method, canon) {
  const p = PATHS[provider];
  if (!p || method === 'GET' || method === 'HEAD') return null;
  if (method === 'POST' && p.metered.test(canon)) return 'metered';
  if (method === 'POST' && p.free.test(canon)) return 'free';
  if (method === 'DELETE') return 'free';
  return 'unpriced';
}

const posInt = (v, max) => (Number.isSafeInteger(v) && v >= 1 && v <= max ? v : null);
/** What a metered request says before it goes: {model, stream, estimate in micro dollars} or {model: null} when the body
 * does not name a model Counterseal can read (unpriced). The estimate is the dear side: every input byte counted as a
 * third of a token (English text is about four characters a token) and the full output limit the request allows. */
export function readRequest(provider, bodyText, view) {
  const j = view(bodyText);
  if (!j || typeof j !== 'object' || Array.isArray(j)) return { model: null };
  const model = typeof j.model === 'string' ? j.model : null;
  const price = priceOf(provider, model);
  if (!price) return { model, price: null };
  const out = posInt(j.max_tokens, MAX_OUTPUT_TOKENS) ?? posInt(j.max_completion_tokens, MAX_OUTPUT_TOKENS) ?? posInt(j.max_output_tokens, MAX_OUTPUT_TOKENS) ?? DEFAULT_OUTPUT_TOKENS;
  const input = Math.ceil(new TextEncoder().encode(bodyText).length / 3);
  return { model, price, stream: j.stream === true, estimate: costOf(price, { input, output: out, cacheRead: 0, cacheWrite: 0 }) };
}

// ---------------------------------------------------------------- reading the answer
const tok = (v) => (Number.isSafeInteger(v) && v >= 0 && v <= 1e9 ? v : 0);
/** OpenAI chat and completions (prompt_tokens, completion_tokens) and the Responses API (input_tokens, output_tokens).
 * prompt_tokens includes cached tokens; they are all charged at the input price (the dear side). */
function openaiUsage(u) {
  if (!u || typeof u !== 'object') return null;
  if ('prompt_tokens' in u || 'completion_tokens' in u) return { input: tok(u.prompt_tokens), output: tok(u.completion_tokens), cacheRead: 0, cacheWrite: 0 };
  if ('input_tokens' in u || 'output_tokens' in u) return { input: tok(u.input_tokens), output: tok(u.output_tokens), cacheRead: 0, cacheWrite: 0 };
  return null;
}
/** Anthropic: input_tokens excludes the cache; cache_read_input_tokens and cache_creation_input_tokens are separate */
function anthropicUsage(u) {
  if (!u || typeof u !== 'object' || !('input_tokens' in u || 'output_tokens' in u)) return null;
  return { input: tok(u.input_tokens), output: tok(u.output_tokens), cacheRead: tok(u.cache_read_input_tokens), cacheWrite: tok(u.cache_creation_input_tokens) };
}

/** The usage in a provider's answer (JSON, or a server-sent event stream), or null when it cannot be read with
 * certainty. A stream: OpenAI sends usage in its last chunk only when the request asked for it (stream_options), the
 * Responses API in response.completed; Anthropic sends input in message_start and the running output total in each
 * message_delta (the largest is kept). The model the provider says it used is returned too. */
export function readUsage(provider, contentType, text) {
  const pick = provider === 'anthropic' ? anthropicUsage : openaiUsage;
  if (/^text\/event-stream/i.test(contentType)) {
    let best = null, model = null;
    for (const line of text.split('\n')) {
      if (!line.startsWith('data:') || !line.includes('"usage"')) continue;
      let o; try { o = JSON.parse(line.slice(5)); } catch { continue; }
      const holder = o?.message?.usage ? o.message : o?.response?.usage ? o.response : o;
      const u = pick(holder.usage);
      if (!u) continue;
      if (typeof holder.model === 'string') model = holder.model;
      best = best ? { input: Math.max(best.input, u.input), output: Math.max(best.output, u.output), cacheRead: Math.max(best.cacheRead, u.cacheRead), cacheWrite: Math.max(best.cacheWrite, u.cacheWrite) } : u;
    }
    return best && { usage: best, model };
  }
  let o; try { o = JSON.parse(text); } catch { return null; }
  const u = o && typeof o === 'object' ? pick(o.usage) : null;
  return u && { usage: u, model: typeof o.model === 'string' ? o.model : null };
}

// ---------------------------------------------------------------- the two providers
export const METERED = {
  openai: {
    name: 'OpenAI',
    host: 'api.openai.com',
    base: '',
    metered: true,
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^sk-/,
    paths: /^\/v1\/[A-Za-z0-9_./-]{1,200}$/,
    note: 'The OpenAI API under /v1. Chat Completions, Responses and Completions are metered against your budgets.',
    irreversible: [
      { id: 'oa.delete', m: 'DELETE', p: '/**', why: 'Deletes a file, vector store, assistant, fine tuned model, container or conversation. The API has no undelete.' },
      { id: 'oa.admin', m: 'POST,PUT,PATCH', p: '/v1/organization/**', why: 'Changes the OpenAI organisation itself: API keys, projects, members, invites, rate limits or spend settings.' },
    ],
  },
  anthropic: {
    name: 'Anthropic',
    host: 'api.anthropic.com',
    base: '',
    metered: true,
    // the version header is fixed here, after the agent's own headers, so the usage fields read are the documented ones
    auth: (k) => ({ 'x-api-key': k, 'anthropic-version': '2023-06-01' }),
    keyHint: /^sk-ant-/,
    paths: /^\/v1\/[A-Za-z0-9_./-]{1,200}$/,
    note: 'The Claude API under /v1. Messages is metered against your budgets.',
    irreversible: [
      { id: 'an.delete', m: 'DELETE', p: '/**', why: 'Deletes a file, batch, skill or other stored object. The API has no undelete.' },
      { id: 'an.admin', m: 'POST,PUT,PATCH', p: '/v1/organizations/**', why: 'Changes the Anthropic organisation itself: API keys, workspaces, members or invites.' },
    ],
  },
};
