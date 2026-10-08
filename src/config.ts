// Everything the server reads from its environment, read once, checked once.
//
// Required: MCP_JWT_PUBLIC_KEY, the Ed25519 public key the web app's access
// tokens are verified with (since 2026-09-28; this server can verify tokens
// but not mint them), and MCP_SERVICE_SECRET. MCP_JWT_SECRET, the old HS256
// secret, is read only while MCP_LEGACY_AUTH_UNTIL is set.
//
// The server used to start without its secrets:
// `MCP_JWT_SECRET` fell through as `undefined` (every token then failed to
// verify, which is loud), and a missing `MCP_SERVICE_SECRET` quietly dropped the
// service-signature header from every gateway call (which is silent, and only
// safe for as long as the gateway also insists on it). A server that cannot
// prove who it is should not be serving, so a missing or short secret now stops
// the process at boot with the NAME of the missing variable. Values are never
// printed.

import crypto, { type KeyObject } from "node:crypto";
import { ipMatcher } from "./ratelimit.js";

export interface Limits {
  /** Live sessions one user may hold. Opening one more closes their oldest. */
  sessionsPerUser: number;
  /** Live sessions across all users. When full, new sessions are refused. */
  sessionsGlobal: number;
  /** A session untouched for this long is closed. */
  sessionIdleMs: number;
  /** New sessions one user may open per window. */
  initPerUserPerWindow: number;
  /** New sessions one client IP may open per window. Claude's own servers
   *  connect on behalf of many users from few addresses, so this is the loose
   *  outer fence and the per-user limit is the real one. */
  initPerIpPerWindow: number;
  initWindowMs: number;
  /** Client addresses the per-IP limit does not apply to (addresses and CIDR
   *  ranges). By default Anthropic's published outbound range, because every
   *  Claude.ai user arrives from it: counted per IP, one busy afternoon of
   *  Claude.ai users would share a single bucket and lock each other out.
   *  The per-user limit and the session caps still apply to them. */
  initIpExempt: string[];
}

/**
 * The old HS256 shared secret and the end of the window in which tokens
 * signed with it are still accepted. See `legacyWindowOpen` in auth.ts.
 */
export interface LegacyHs256 {
  secret: string;
  /** ms since epoch */
  until: number;
}

export interface Config {
  port: number;
  /** Ed25519 public key the web app's access tokens are verified with. */
  jwtPublicKey: KeyObject;
  /** Only during the switch off HS256; null once MCP_LEGACY_AUTH_UNTIL is unset. */
  legacyHs256: LegacyHs256 | null;
  serviceSecret: string;
  serverUrl: string;
  issuer: string;
  audience: string;
  frontendUrl: string;
  limits: Limits;
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`invalid configuration: ${problems.join("; ")}`);
    this.name = "ConfigError";
  }
}

/** 32 characters is the floor; the real values are 64 hex characters. */
const MIN_SECRET_LENGTH = 32;

/**
 * `MCP_JWT_PUBLIC_KEY`: the base64 of the SPKI DER (one line, 60 characters
 * for Ed25519) or an SPKI PEM with `\n` for newlines. Must be Ed25519.
 * Problems are reported by the variable's NAME, never its value.
 */
export function parsePublicKey(raw: string, name = "MCP_JWT_PUBLIC_KEY"): KeyObject | string {
  const text = raw.trim();
  // Node would happily derive a public key from a private one. The point of
  // the switch is that this server never holds the signing key, so refuse it.
  if (/PRIVATE KEY/.test(text)) return `${name} holds a private key; this server must get only the public key`;
  let key: KeyObject;
  try {
    key = text.includes("-----BEGIN")
      ? crypto.createPublicKey(text.replace(/\\n/g, "\n"))
      : crypto.createPublicKey({ key: Buffer.from(text, "base64"), format: "der", type: "spki" });
  } catch {
    return `${name} is not a readable public key`;
  }
  if (key.type !== "public") return `${name} is not a public key`;
  if (key.asymmetricKeyType !== "ed25519") return `${name} is not an Ed25519 key`;
  return key;
}

export const DEFAULT_LIMITS: Limits = {
  sessionsPerUser: 10,
  sessionsGlobal: 1000,
  sessionIdleMs: 60 * 60 * 1000,
  initPerUserPerWindow: 30,
  initPerIpPerWindow: 120,
  initWindowMs: 10 * 60 * 1000,
  // Anthropic's outbound range for MCP calls, read 2026-09-28 from
  // https://platform.claude.com/docs/en/api/ip-addresses ("Outbound IP
  // addresses", IPv4). The page says it will not change without notice.
  initIpExempt: ["160.79.104.0/21"],
};

/** `MCP_INIT_IP_EXEMPT`: comma-separated addresses and CIDR ranges, or `none`
 *  for no exemption. Unset or empty keeps the default. */
function ipListFrom(env: NodeJS.ProcessEnv, name: string, fallback: string[], problems: string[]): string[] {
  const raw = env[name];
  if (raw == null || raw.trim() === "") return fallback;
  if (raw.trim().toLowerCase() === "none") return [];
  const list = raw.split(",").map((s) => s.trim()).filter((s) => s !== "");
  try {
    ipMatcher(list);
  } catch (err) {
    problems.push(`${name}: ${(err as Error).message}`);
    return fallback;
  }
  return list;
}

function intFrom(env: NodeJS.ProcessEnv, name: string, fallback: number, problems: string[]): number {
  const raw = env[name];
  if (raw == null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    problems.push(`${name} must be a positive integer`);
    return fallback;
  }
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];

  const secret = (name: string): string => {
    const v = env[name] ?? "";
    if (v === "") problems.push(`${name} is not set`);
    else if (v.length < MIN_SECRET_LENGTH) problems.push(`${name} is shorter than ${MIN_SECRET_LENGTH} characters`);
    return v;
  };

  const serviceSecret = secret("MCP_SERVICE_SECRET");
  const serverUrl = env.MCP_SERVER_URL || "https://mcp.returnolio.com";

  // The token key. Required: without it no token can be verified.
  let jwtPublicKey: KeyObject | null = null;
  const rawKey = env.MCP_JWT_PUBLIC_KEY ?? "";
  if (rawKey.trim() === "") problems.push("MCP_JWT_PUBLIC_KEY is not set");
  else {
    const parsed = parsePublicKey(rawKey);
    if (typeof parsed === "string") problems.push(parsed);
    else jwtPublicKey = parsed;
  }

  // The HS256 transition window (2026-09-28, OWASP audit M27). Set
  // MCP_LEGACY_AUTH_UNTIL, an ISO time, only while the web app may still hold
  // HS256 tokens it issued before it switched to EdDSA; MCP_JWT_SECRET is then
  // required. Unset: HS256 is refused and MCP_JWT_SECRET is ignored.
  let legacyHs256: LegacyHs256 | null = null;
  const rawUntil = (env.MCP_LEGACY_AUTH_UNTIL ?? "").trim();
  if (rawUntil !== "") {
    const until = Date.parse(rawUntil);
    if (!Number.isFinite(until)) problems.push("MCP_LEGACY_AUTH_UNTIL is not an ISO time");
    const legacySecret = secret("MCP_JWT_SECRET");
    if (Number.isFinite(until) && legacySecret.length >= MIN_SECRET_LENGTH) {
      legacyHs256 = { secret: legacySecret, until };
    }
  }

  const config: Config = {
    port: intFrom(env, "MCP_PORT", 3459, problems),
    jwtPublicKey: jwtPublicKey as KeyObject,
    legacyHs256,
    serviceSecret,
    serverUrl,
    issuer: env.MCP_OAUTH_ISSUER || "https://app.returnolio.com",
    audience: env.MCP_OAUTH_AUDIENCE || serverUrl,
    frontendUrl: env.FRONTEND_INTERNAL_URL || "http://127.0.0.1:3000",
    limits: {
      sessionsPerUser: intFrom(env, "MCP_SESSIONS_PER_USER", DEFAULT_LIMITS.sessionsPerUser, problems),
      sessionsGlobal: intFrom(env, "MCP_SESSIONS_GLOBAL", DEFAULT_LIMITS.sessionsGlobal, problems),
      sessionIdleMs: intFrom(env, "MCP_SESSION_IDLE_MS", DEFAULT_LIMITS.sessionIdleMs, problems),
      initPerUserPerWindow: intFrom(env, "MCP_INIT_PER_USER", DEFAULT_LIMITS.initPerUserPerWindow, problems),
      initPerIpPerWindow: intFrom(env, "MCP_INIT_PER_IP", DEFAULT_LIMITS.initPerIpPerWindow, problems),
      initWindowMs: intFrom(env, "MCP_INIT_WINDOW_MS", DEFAULT_LIMITS.initWindowMs, problems),
      initIpExempt: ipListFrom(env, "MCP_INIT_IP_EXEMPT", DEFAULT_LIMITS.initIpExempt, problems),
    },
  };

  if (problems.length > 0) throw new ConfigError(problems);
  return config;
}
