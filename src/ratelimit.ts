// A fixed-window counter per key, in memory.
//
// Used for `initialize` only: opening a session is the expensive step here (a
// transport plus a whole McpServer), and tool calls are already limited per
// user by the gateway. One process, one container, so in-memory is enough.

import net from "node:net";

export interface RateResult {
  ok: boolean;
  /** Whole seconds until the window resets, for a Retry-After header. */
  retryAfterSec: number;
}

export class FixedWindowLimiter {
  private readonly hits = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
    /** The map is pruned when it grows past this, so a flood of distinct keys
     *  cannot become its own memory problem. */
    private readonly maxKeys = 50_000,
  ) {}

  /** Would `hit(key)` pass right now? Counts nothing. Two limiters that
   *  guard one action are both peeked first and only then both hit, so a
   *  request refused by one of them does not use up the other's allowance. */
  peek(key: string): RateResult {
    const t = this.now();
    const w = this.hits.get(key);
    if (!w || t - w.start >= this.windowMs) {
      return { ok: this.max > 0, retryAfterSec: Math.max(1, Math.ceil(this.windowMs / 1000)) };
    }
    const retryAfterSec = Math.max(1, Math.ceil((w.start + this.windowMs - t) / 1000));
    return { ok: w.count < this.max, retryAfterSec };
  }

  hit(key: string): RateResult {
    const t = this.now();
    let w = this.hits.get(key);
    if (!w || t - w.start >= this.windowMs) {
      if (!w && this.hits.size >= this.maxKeys) this.prune();
      w = { start: t, count: 0 };
      this.hits.set(key, w);
    }
    const retryAfterSec = Math.max(1, Math.ceil((w.start + this.windowMs - t) / 1000));
    if (w.count >= this.max) return { ok: false, retryAfterSec };
    w.count++;
    return { ok: true, retryAfterSec };
  }

  /** Drop windows that have ended. If every window is still open, drop the
   *  oldest half: a limiter that forgets is better than one that runs out. */
  prune(): void {
    const t = this.now();
    for (const [k, w] of this.hits) if (t - w.start >= this.windowMs) this.hits.delete(k);
    if (this.hits.size >= this.maxKeys) {
      const drop = Math.ceil(this.hits.size / 2);
      let i = 0;
      for (const k of this.hits.keys()) {
        if (i++ >= drop) break;
        this.hits.delete(k);
      }
    }
  }

  get keys(): number {
    return this.hits.size;
  }
}

/**
 * A matcher for a list of addresses and CIDR ranges ("160.79.104.0/21",
 * "2001:db8::/32", "203.0.113.7"). Throws on an entry it cannot read, so a
 * typo in the env stops the server at boot instead of quietly matching
 * nothing. An IPv4 address written IPv6-style ("::ffff:160.79.104.9") is
 * matched as the IPv4 address it is.
 */
export function ipMatcher(entries: readonly string[]): (ip: string) => boolean {
  const list = new net.BlockList();
  for (const raw of entries) {
    const entry = raw.trim();
    const slash = entry.indexOf("/");
    const addr = slash === -1 ? entry : entry.slice(0, slash);
    const family = net.isIP(addr);
    if (family === 0) throw new Error(`not an IP address or CIDR range: ${JSON.stringify(entry.slice(0, 64))}`);
    const type = family === 4 ? "ipv4" : "ipv6";
    if (slash === -1) {
      list.addAddress(addr, type);
      continue;
    }
    const bitsRaw = entry.slice(slash + 1);
    const bits = Number(bitsRaw);
    const max = family === 4 ? 32 : 128;
    if (!/^\d+$/.test(bitsRaw) || bits > max) {
      throw new Error(`bad prefix length in ${JSON.stringify(entry.slice(0, 64))}`);
    }
    list.addSubnet(addr, bits, type);
  }
  return (ip: string) => {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    const addr = mapped ? mapped[1] : ip;
    const family = net.isIP(addr);
    if (family === 0) return false;
    return list.check(addr, family === 4 ? "ipv4" : "ipv6");
  };
}
