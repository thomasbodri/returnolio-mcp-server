// The live MCP sessions, with a ceiling.
//
// Before 2026-09-28 every `initialize` created a session and nothing counted
// them. A session held a transport and a whole McpServer in memory for up to
// 24 hours, and any account on any plan can get a token, so one free sign-up
// with a loop could fill the container's memory and take the connector down
// for everybody. Three limits now apply:
//
// - per user: opening one more than `perUser` closes that user's least
//   recently used session. The client whose session went away gets a 404 on
//   its next call and re-initializes, which MCP clients already do after a
//   restart. Nobody else is affected.
// - global: when `global` sessions are live (idle ones swept first), a new
//   session is refused with 503 rather than evicting someone else's.
// - idle: a session untouched for `idleMs` is closed, checked both on access
//   and by a periodic sweep.
//
// Rate limiting of `initialize` itself lives in ratelimit.ts.

export interface Closable {
  close(): Promise<void> | void;
}

export interface SessionEntry<T extends Closable, R> {
  transport: T;
  tokenRef: R;
  /** Whose session this is. A session id presented with a valid token for a
   *  DIFFERENT account is not that account's session, and must not become one:
   *  the token is refreshed into the session on every request, so without this
   *  check a guessed id would let one user's token drive another's transport. */
  userId: string;
  createdAt: number;
  lastSeenAt: number;
}

export interface SessionLimits {
  perUser: number;
  global: number;
  idleMs: number;
}

export type CloseReason = "idle" | "evicted_per_user_cap" | "closed";

export class SessionStore<T extends Closable, R> {
  private readonly byId = new Map<string, SessionEntry<T, R>>();
  /** Sessions whose `initialize` is being handled right now. They count
   *  against the global cap, so a burst of parallel initializes cannot all
   *  pass the check before any of them is stored. */
  private pending = 0;

  constructor(
    private readonly limits: SessionLimits,
    private readonly now: () => number = Date.now,
    private readonly onClose: (id: string, entry: SessionEntry<T, R>, reason: CloseReason) => void = () => {},
  ) {}

  get size(): number {
    return this.byId.size;
  }

  countFor(userId: string): number {
    let n = 0;
    for (const s of this.byId.values()) if (s.userId === userId) n++;
    return n;
  }

  /**
   * Look a session up for `userId` and refresh its idle clock.
   *
   * Returns undefined for an id that does not exist, one that has gone idle,
   * AND one that belongs to somebody else, so the caller answers all three
   * with the same 404. Telling them apart would confirm a guessed id exists.
   */
  get(id: string | undefined, userId: string | undefined): SessionEntry<T, R> | undefined {
    if (!id) return undefined;
    const s = this.byId.get(id);
    if (!s) return undefined;
    if (this.isIdle(s)) {
      this.drop(id, s, "idle");
      return undefined;
    }
    if (!userId || s.userId !== userId) return undefined;
    s.lastSeenAt = this.now();
    return s;
  }

  /**
   * Ask for room for one more session for `userId`. Returns false when the
   * server is full.
   * On true, the caller MUST call `release()` once its initialize has finished,
   * whether or not the session was stored.
   */
  reserve(userId?: string): boolean {
    const full = () => this.byId.size + this.pending >= this.limits.global;
    if (full()) this.sweep();
    // A user already at their own cap replaces their oldest session rather
    // than adding one, so a full server still lets them reconnect.
    if (full() && !(userId !== undefined && this.countFor(userId) >= this.limits.perUser)) return false;
    this.pending++;
    return true;
  }

  release(): void {
    if (this.pending > 0) this.pending--;
  }

  /** Store a freshly initialized session, closing the user's least recently
   *  used ones if this takes them over their cap. */
  add(id: string, transport: T, tokenRef: R, userId: string): void {
    const t = this.now();
    this.byId.set(id, { transport, tokenRef, userId, createdAt: t, lastSeenAt: t });
    const mine = [...this.byId.entries()]
      .filter(([, s]) => s.userId === userId)
      .sort((a, b) => a[1].lastSeenAt - b[1].lastSeenAt || a[1].createdAt - b[1].createdAt);
    let excess = mine.length - this.limits.perUser;
    for (const [oldId, old] of mine) {
      if (excess <= 0) break;
      if (oldId === id) continue;
      this.drop(oldId, old, "evicted_per_user_cap");
      excess--;
    }
  }

  /** Forget the session that owns `transport` (called from its onclose). */
  forgetTransport(transport: T): string | undefined {
    for (const [id, s] of this.byId) {
      if (s.transport === transport) {
        this.byId.delete(id);
        this.onClose(id, s, "closed");
        return id;
      }
    }
    return undefined;
  }

  /** Close every session that has gone idle. Returns how many were closed. */
  sweep(): number {
    let n = 0;
    for (const [id, s] of this.byId) {
      if (this.isIdle(s)) {
        this.drop(id, s, "idle");
        n++;
      }
    }
    return n;
  }

  private isIdle(s: SessionEntry<T, R>): boolean {
    return this.now() - s.lastSeenAt >= this.limits.idleMs;
  }

  private drop(id: string, s: SessionEntry<T, R>, reason: CloseReason): void {
    // Delete first: closing the transport fires its onclose, which calls
    // forgetTransport, which must then find nothing and log nothing twice.
    this.byId.delete(id);
    this.onClose(id, s, reason);
    try {
      void Promise.resolve(s.transport.close()).catch(() => {});
    } catch {
      // Already closed. The point was to drop the reference.
    }
  }
}
