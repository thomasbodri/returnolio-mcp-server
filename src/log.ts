// One JSON object per line, always with a time, so `docker logs` can be read
// by a person and parsed by a script.
//
// The caller is named by ids only: `userId` (the token subject) and `clientId`
// (the connection id, `cid`, the frontend put in the token). Never a token,
// never an email address. Callers are expected not to pass either, and
// `scrub` is the second line of defence for when one slips through inside an
// error message: fields named like a credential are dropped, and anything in a
// string that looks like a JWT or an email address is masked.

type Level = "info" | "warn" | "error";

const DROP_KEYS = /^(authorization|token|access_token|refresh_token|bearer|secret|password|email|cookie)$/i;
const JWT_LIKE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const EMAIL_LIKE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function scrubString(s: string): string {
  return s.replace(JWT_LIKE, "[token]").replace(EMAIL_LIKE, "[email]");
}

export function scrub(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    if (DROP_KEYS.test(k)) continue;
    out[k] = typeof v === "string" ? scrubString(v) : v;
  }
  return out;
}

/** Where lines go. Swappable so tests can read what would have been logged. */
export let sink: (line: string, level: Level) => void = (line, level) => {
  if (level === "error") console.error(line);
  else console.log(line);
};

export function setLogSink(fn: typeof sink): void {
  sink = fn;
}

export function log(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ time: new Date().toISOString(), level, event, ...scrub(fields) });
  sink(line, level);
}

/** The first 8 characters of a session id: enough to follow one session
 *  through the log, not enough to present as one. */
export function shortId(id: string | undefined): string | undefined {
  return id ? id.slice(0, 8) : undefined;
}
