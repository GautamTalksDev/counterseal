// Token policy. A token can only narrow what its credential can do; it never widens it.
// Order: deny > irreversible map (held unless pre-approved by a passkey holder) > hold > allow > default.
// Brakes (src/brakes.js) sit around this: a frozen account and a tripped token are checked first, and money caps may
// let a Stripe refund or payout through the map, but only if everything after the map (hold, allow, default) agrees.
import { HttpError } from './util.js';
import { globMatch, globToRe, irreversibleRule, matchPath, PROVIDERS } from './providers.js';
import { normaliseBrakes } from './money.js';

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

/** a glob whose regular expression cannot backtrack badly: "**" at most twice, and in each segment (between "/" and
 *  inside each {a,b} alternative) at most one wildcard, "*" or "**" */
export function safeGlob(g) {
  if ((g.match(/\*\*/g) || []).length > 2) return false;
  return g.split(/[/{},]/).every((seg) => (seg.replace(/\*\*/g, '*').match(/\*/g) || []).length <= 1);
}

function rules(list, name) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > 50) throw new HttpError(400, 'bad_policy', `${name} must be a list (max 50)`);
  return list.map((r) => {
    if (!r || typeof r !== 'object') throw new HttpError(400, 'bad_policy');
    const m = r.method === undefined ? '*' : String(r.method).toUpperCase();
    if (m !== '*' && !METHODS.includes(m)) throw new HttpError(400, 'bad_policy', `unknown method ${m}`);
    if (typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.length > 300 || /[\s\\]/.test(r.path) || r.path.includes('//')) throw new HttpError(400, 'bad_policy', 'path must be a glob starting with /');
    // an unbalanced or nested brace would otherwise fail on every request this token makes
    try { globToRe(r.path); } catch { throw new HttpError(400, 'bad_policy', 'path has an unbalanced or nested {}'); }
    // Globs compile to regular expressions, which backtrack: three "**" against a 2,000 character path took seconds of
    // CPU (catastrophic backtracking). So "**" at most twice per path, and at most one wildcard in a path segment.
    if (!safeGlob(r.path)) throw new HttpError(400, 'bad_policy', 'path may use ** at most twice, and one wildcard (* or **) per segment');
    // same canonical form as request paths: one trailing slash dropped
    return { method: m, path: r.path.length > 1 && r.path.endsWith('/') ? r.path.slice(0, -1) : r.path };
  });
}

/** validate + normalise a user policy. `byPasskey` decides whether irreversible pre-approval may be granted. */
export function normalisePolicy(p, byPasskey) {
  if (p === undefined || p === null) p = {};
  if (typeof p !== 'object' || Array.isArray(p)) throw new HttpError(400, 'bad_policy');
  const out = {
    allow: rules(p.allow, 'allow'),
    deny: rules(p.deny, 'deny'),
    hold: rules(p.hold, 'hold'),
    default: p.default === 'deny' ? 'deny' : p.default === 'hold' ? 'hold' : 'allow',
    readOnly: p.readOnly === true,
    perMinute: Number.isInteger(p.perMinute) && p.perMinute > 0 && p.perMinute <= 600 ? p.perMinute : 120,
    // Letting an agent run irreversible operations unattended is the one dangerous switch. Only a fresh passkey
    // ceremony can set it; a CLI session (which an agent on the same machine can read) cannot.
    unattendedIrreversible: rules(p.unattendedIrreversible, 'unattendedIrreversible'),
  };
  if (out.unattendedIrreversible.length && !byPasskey) throw new HttpError(403, 'passkey_required', 'Only a passkey holder can let irreversible operations through without approval.');
  // Brakes. `limits` (the breaker) only narrows, so any session may set it. `money` loosens (below its caps, Stripe
  // refunds and payouts pass unattended), so like unattendedIrreversible only a passkey ceremony can set it.
  const { limits, money } = normaliseBrakes(p, byPasskey);
  out.limits = limits;
  out.money = money;
  return out;
}

// on case-insensitive providers both the path and the rule are lowercased, so /repos/Acme/App cannot dodge /repos/acme/*
const hitRaw = (list, methods, path, ci) => list.some((r) => (r.method === '*' || methods.includes(r.method)) && globMatch(ci ? r.path.toLowerCase() : r.path, path));

/** -> {decision: 'allow'|'deny'|'hold', rule, why}. `path` must be canonical (see broker.js canonPath). */
export function decide(policy, provider, method, canon, body, search = '') {
  const ci = !!PROVIDERS[provider]?.ci, path = matchPath(provider, canon);
  const hit = (list, m, p) => hitRaw(list, m, p, ci);
  // a deny or hold rule written for GET also covers HEAD (many servers run the GET handler for a HEAD)
  const strict = method === 'HEAD' ? ['HEAD', 'GET'] : [method];
  if (hit(policy.deny, strict, path)) return { decision: 'deny', rule: 'policy.deny', why: 'This token is not allowed to call this endpoint.' };
  if (policy.readOnly && !['GET', 'HEAD'].includes(method)) return { decision: 'deny', rule: 'policy.readOnly', why: 'This token is read-only.' };
  const irr = irreversibleRule(provider, method, canon, body, search);
  if (irr) {
    // `always` rules (method overrides) cannot be pre-approved: a pre-approval names a method, and these hide theirs
    if (!irr.always && hit(policy.unattendedIrreversible, [method], path)) return { decision: 'allow', rule: irr.id + ':preapproved', why: irr.why };
    return { decision: 'hold', rule: irr.id, why: irr.why };
  }
  return afterMap(policy, provider, method, canon);
}

/** The part of decide() after the irreversible map: hold rules, the allow list and the default. Money caps use it to ask
 * "would this token's own policy let this call through?" before turning a map hold into an allow. */
export function afterMap(policy, provider, method, canon) {
  const ci = !!PROVIDERS[provider]?.ci, path = matchPath(provider, canon);
  const hit = (list, m, p) => hitRaw(list, m, p, ci);
  const strict = method === 'HEAD' ? ['HEAD', 'GET'] : [method];
  if (hit(policy.hold, strict, path)) return { decision: 'hold', rule: 'policy.hold', why: 'Your policy asks for approval on this endpoint.' };
  if (policy.allow.length) {
    if (hit(policy.allow, [method], path)) return { decision: 'allow', rule: 'policy.allow', why: '' };
    return policy.default === 'allow'
      ? { decision: 'deny', rule: 'policy.allowlist', why: 'Not on this token\'s allow list.' }
      : { decision: policy.default, rule: 'policy.default', why: 'Not on this token\'s allow list.' };
  }
  if (policy.default === 'allow') return { decision: 'allow', rule: 'default', why: '' };
  return { decision: policy.default, rule: 'policy.default', why: 'Default for this token.' };
}
