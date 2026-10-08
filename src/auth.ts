import { Router, type Request, type Response, type NextFunction } from "express";
import { decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import type { Config, LegacyHs256 } from "./config.js";
import { log } from "./log.js";

// This server is an OAuth *resource server* only. The authorization server (the
// /authorize, /token, /register endpoints) lives in the Returnolio web app. Here
// we just advertise where the AS is and validate the bearer token on /mcp.

export interface AuthedRequest extends Request {
  mcpToken?: string;
  mcpUserId?: string;
  /** The connection id (`cid`) the frontend put in the token, when it did. */
  mcpClientId?: string;
  /** How the token was signed; "HS256" only inside the transition window. */
  mcpTokenAlg?: "EdDSA" | "HS256";
}

/** A window further out than this is treated as a mistake and ignored. */
export const MAX_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Are HS256 tokens still accepted at `now`? Only while MCP_LEGACY_AUTH_UNTIL
 * is ahead, and never for more than MAX_WINDOW_MS ahead, so a far-future
 * value left in the env cannot keep the shared secret alive.
 */
export function legacyWindowOpen(legacy: LegacyHs256 | null, now: number): boolean {
  if (!legacy) return false;
  return now < legacy.until && legacy.until - now <= MAX_WINDOW_MS;
}

class RefusedAlg extends Error {
  constructor(public readonly alg: string) {
    super("alg_not_accepted");
    this.name = "RefusedAlg";
  }
}

export function createAuth(
  config: Pick<Config, "jwtPublicKey" | "legacyHs256" | "serverUrl" | "issuer" | "audience">,
  now: () => number = Date.now,
) {
  const legacyKey = config.legacyHs256 ? new TextEncoder().encode(config.legacyHs256.secret) : null;

  /**
   * Verify alg, iss, aud and expiry. EdDSA against the web app's public key:
   * this server can check a token but cannot make one (OWASP audit
   * 2026-09-28, M27). HS256 against the old shared secret only inside the
   * transition window, for the one-hour tokens the web app issued before it
   * switched. Every other alg, "none" included, is refused.
   */
  async function verify(token: string): Promise<{ claims: JWTPayload; alg: "EdDSA" | "HS256" }> {
    const { alg } = decodeProtectedHeader(token);
    const t = now();
    const pinned = { issuer: config.issuer, audience: config.audience, currentDate: new Date(t) };
    if (alg === "EdDSA") {
      const { payload } = await jwtVerify(token, config.jwtPublicKey, { ...pinned, algorithms: ["EdDSA"] });
      return { claims: payload, alg };
    }
    if (alg === "HS256" && legacyKey && legacyWindowOpen(config.legacyHs256, t)) {
      const { payload } = await jwtVerify(token, legacyKey, { ...pinned, algorithms: ["HS256"] });
      return { claims: payload, alg };
    }
    throw new RefusedAlg(String(alg ?? "none").slice(0, 16));
  }

  const authRouter = Router();
  const wwwAuth = `Bearer resource_metadata="${config.serverUrl}/.well-known/oauth-protected-resource"`;

  // RFC 9728 Protected Resource Metadata: points clients at the frontend AS.
  authRouter.get("/.well-known/oauth-protected-resource", (_req: Request, res: Response) => {
    res.json({
      resource: config.serverUrl,
      authorization_servers: [config.issuer],
      bearer_methods_supported: ["header"],
    });
  });

  // Validate the bearer JWT (alg/iss/aud pinned, see verify above). This
  // rejects garbage early; the gateway still does the authoritative live plan
  // re-check on every tool call. A token with no subject or the wrong scope is
  // refused here too, the same two checks the gateway makes: a session must
  // belong to somebody, or the per-user session cap has nobody to count.
  function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.setHeader("WWW-Authenticate", wwwAuth);
      res.status(401).json({ error: "missing_token" });
      return;
    }
    const token = authHeader.slice(7);
    verify(token).then(
      ({ claims, alg }) => accept(req, res, next, token, claims, alg),
      (err: unknown) => {
        // The reason (expired, bad signature, wrong audience, refused alg) is
        // logged, never the token. The caller gets the same answer for all.
        const reason = err instanceof RefusedAlg ? `alg_${err.alg}` : err instanceof Error ? (err as { code?: string }).code ?? err.name : "unknown";
        log("warn", "auth_rejected", { reason, path: req.path });
        res.setHeader("WWW-Authenticate", wwwAuth);
        res.status(401).json({ error: "invalid_token" });
      },
    ).catch(next);
  }

  function accept(
    req: AuthedRequest,
    res: Response,
    next: NextFunction,
    token: string,
    claims: JWTPayload,
    alg: "EdDSA" | "HS256",
  ): void {
    const sub = claims.sub != null ? String(claims.sub) : "";
    if (sub === "" || claims.scope !== "mcp:read") {
      log("warn", "auth_rejected", { reason: sub === "" ? "no_subject" : "wrong_scope", path: req.path });
      res.setHeader("WWW-Authenticate", wwwAuth);
      res.status(401).json({ error: "invalid_token" });
      return;
    }
    req.mcpToken = token;
    req.mcpUserId = sub;
    req.mcpClientId = claims.cid != null ? String(claims.cid) : undefined;
    req.mcpTokenAlg = alg;
    next();
  }

  return { authRouter, requireAuth };
}
