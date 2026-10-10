// Cloudflare entry for the public log's Durable Object. RPC calls (env.LOG.get(id).head()) only work on a class that
// extends DurableObject from cloudflare:workers. Node tests use the plain ReceiptLog in log.js, which has the same methods.
import { DurableObject } from 'cloudflare:workers';
import { LogCore } from './log.js';

export class ReceiptLog extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = new LogCore(ctx.storage.sql, env, (fn) => ctx.storage.transactionSync(fn));
  }
  append(items, now) { return this.ctx.blockConcurrencyWhile(() => this.core.append(items, now)); }
  head() { return this.core.head(); }
  inclusion(i, n) { return this.core.inclusion(i, n); }
  consistency(m, n) { return this.core.consistency(m, n); }
  entry(i) { return this.core.entry(i); }
  entries(s, c) { return this.core.entries(s, c); }
  tenantEntries(t, b, c) { return this.core.tenantEntries(t, b, c); }
  forgetTenant(t) { return this.core.forgetTenant(t); }
}
