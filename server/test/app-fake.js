// A small fake DOM that runs the dashboard's own code (site/public/app/app.js) against the answers of the real Worker.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

class Txt { constructor(t) { this.text = String(t); } get textContent() { return this.text; } }
class El {
  constructor(tag, id) { this.tag = tag; this.id = id; this.children = []; this.options = [{ value: '' }]; this.dataset = {}; this.attrs = {}; this._text = ''; this.hidden = false; this.value = ''; this.checked = false; this.disabled = false; this.title = ''; this.listeners = {}; const on = new Set(); this.classList = { toggle: (c, f) => ((f ?? !on.has(c)) ? on.add(c) : on.delete(c)), add: (c) => on.add(c), contains: (c) => on.has(c) }; }
  append(...kids) { for (const k of kids) this.children.push(typeof k === 'string' ? new Txt(k) : k); }
  replaceChildren(...kids) { this.children = []; this.append(...kids); }
  get childNodes() { return this.children; }
  closest() { return new El('label'); }
  get childElementCount() { return this.children.filter((c) => c instanceof El).length; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  setAttribute(n, v) { this.attrs[n] = String(v); }
  focus() {} scrollIntoView() {} setSelectionRange() {} remove() {} click() { return this.onclick && this.onclick({ preventDefault() {} }); }
  all(test, out = []) { for (const c of this.children) if (c instanceof El) { if (test(c)) out.push(c); c.all(test, out); } return out; }
  querySelectorAll(sel) { return sel === 'input' ? this.all((c) => c.tag === 'input') : []; }
  querySelector() { return null; }
}

/** run app.js: routes maps "METHOD /path" to a function (body, init) returning [status, json] */
export async function page(routes, { hash = '' } = {}) {
  const els = new Map(), created = [], calls = [], toasts = [], intervals = [], docListeners = {};
  const NAV = ['holds', 'vault', 'tokens', 'gates', 'team', 'agentkeys', 'receipts', 'audit', 'account'].map((v) => { const a = new El('a'); a.dataset.view = v; return a; });
  const VIEWS = NAV.map((a) => { const s = new El('section'); s.dataset.view = a.dataset.view; return s; });
  const byId = (id) => { if (!els.has(id)) els.set(id, new El(id === 'toast' ? 'div' : 'div', id)); return els.get(id); };
  const document = {
    hidden: false, addEventListener: (type, fn) => { (docListeners[type] ||= []).push(fn); },
    getElementById: byId, createElement: (t) => { created.push(t); return new El(t); }, createTextNode: (t) => new Txt(t), activeElement: null, body: new El('body'),
    querySelectorAll: (sel) => (sel === '#snav a' ? NAV : sel === '.view' ? VIEWS : []),
  };
  const fetch = async (path, init = {}) => {
    const method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body });
    const r = routes[`${method} ${path}`] || routes[`${method} *`];
    if (!r) return { ok: false, status: 404, json: async () => ({ error: 'not_found' }) };
    const [status, json] = await r(body, init);
    return { ok: status < 400, status, json: async () => json };
  };
  const ctx = vm.createContext({
    document, fetch, window: { addEventListener() {}, scrollTo() {}, trustedTypes: undefined }, location: { hash, origin: 'https://leash.test', assign() {}, replace() {}, reload() {} }, history: { replaceState() {} },
    navigator: { credentials: { get: async () => ({ id: 'cred', response: { authenticatorData: new ArrayBuffer(4), clientDataJSON: new ArrayBuffer(4), signature: new ArrayBuffer(4) } }) }, clipboard: { writeText: async (t) => { ctx.copied = t; } } },
    confirm: () => true, setTimeout: () => 0, clearTimeout() {}, setInterval: (fn) => intervals.push(fn), clearInterval() {}, Intl, URL, Blob, btoa, atob, Uint8Array, ArrayBuffer, Promise, JSON, Object, Array, String, Number, Date, Math, Set, Map, console, Error, SyntaxError, encodeURIComponent,
  });
  const src = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8').replace(/^import .*$/m, 'const BRAND = { name: "Counterseal" };')
    .replace(/^import \{[^}]*\} from '\.\/warden\.js';$/m, () => readFileSync(new URL('../../site/public/app/warden.js', import.meta.url), 'utf8').replace(/^export /gm, ''));
  vm.runInContext(src, ctx, { filename: 'app.js' });
  const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
  await settle();
  const toast = () => byId('toast').textContent;
  return { byId, calls, created, NAV, VIEWS, settle, toast, ctx, intervals, document, docListeners, go: async (view) => { NAV.find((a) => a.dataset.view === view).click(); await settle(); } };
}

