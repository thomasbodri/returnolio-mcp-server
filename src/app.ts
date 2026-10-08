import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import cors from "cors";
import crypto from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createMcpServer, type TokenRef } from "./server.js";
import { createAuth, type AuthedRequest } from "./auth.js";
import { createGateway, type GatewayCall } from "./gateway.js";
import type { Config } from "./config.js";
import { log, shortId } from "./log.js";
import { SessionStore } from "./sessions.js";
import { FixedWindowLimiter, ipMatcher } from "./ratelimit.js";

export interface AppDeps {
  /** Replaces the real gateway (tests). */
  gateway?: GatewayCall;
  /** Replaces Date.now for sessions and rate limits (tests). */
  now?: () => number;
  /** Replaces Date.now for token expiry and the HS256 window (tests). */
  authNow?: () => number;
}

/**
 * Express 4 does not catch a rejected promise from an async handler: the
 * request hangs and the rejection escapes to the process. Every async route
 * goes through this so the error reaches the error handler below instead.
 */
export function wrap(fn: (req: AuthedRequest, res: Response, next: NextFunction) => Promise<void>): RequestHandler {
  return (req, res, next) => {
    fn(req as AuthedRequest, res, next).catch(next);
  };
}

/**
 * The address a request came from. Public traffic arrives through the
 * Cloudflare tunnel, so the socket address is cloudflared's container and the
 * visitor is in `cf-connecting-ip`. The port is published on the host's
 * loopback only, so the header can be set by hand only from the box itself or
 * from a container on the same network, which is also the only place the
 * limit could be dodged from.
 */
function clientIp(req: Request): string {
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf.length > 0 && cf.length <= 64) return cf;
  return req.socket.remoteAddress ?? "unknown";
}

/** The JSON-RPC method and, for tools/call, the tool name. Nothing else from
 *  the body is logged: arguments can carry whatever the user typed. */
function rpcSummary(body: unknown): { method?: string; tool?: string } {
  const one = Array.isArray(body) ? body[0] : body;
  if (!one || typeof one !== "object") return {};
  const m = (one as { method?: unknown }).method;
  const method = typeof m === "string" ? m.slice(0, 64) : undefined;
  let tool: string | undefined;
  if (method === "tools/call") {
    const n = (one as { params?: { name?: unknown } }).params?.name;
    if (typeof n === "string") tool = n.slice(0, 64);
  }
  return { method, tool };
}

/**
 * The last word on every error. The caller gets a fixed JSON code and never
 * a stack trace, a message or a library path; Express's default handler used
 * to print the whole trace (with /app/node_modules paths) to anyone who sent
 * a broken body. The detail goes to our log instead. A body-parser message
 * can quote the body, so for a client error only its type is logged.
 */
export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  const e = err as { status?: unknown; statusCode?: unknown; type?: unknown; name?: unknown; message?: unknown; stack?: unknown };
  const raw = typeof e?.status === "number" ? e.status : typeof e?.statusCode === "number" ? e.statusCode : 500;
  const status = raw >= 400 && raw < 600 ? raw : 500;
  const areq = req as AuthedRequest;
  if (status < 500) {
    log("warn", "request_error", {
      status,
      type: typeof e?.type === "string" ? e.type : undefined,
      path: req.path,
      userId: areq.mcpUserId,
      clientId: areq.mcpClientId,
    });
  } else {
    log("error", "request_error", {
      status,
      path: req.path,
      userId: areq.mcpUserId,
      clientId: areq.mcpClientId,
      name: typeof e?.name === "string" ? e.name : undefined,
      message: typeof e?.message === "string" ? e.message : String(err),
      stack: typeof e?.stack === "string" ? e.stack : undefined,
    });
  }
  if (res.headersSent) {
    res.end();
    return;
  }
  res.status(status).json({ error: status < 500 ? "bad_request" : "internal_error" });
}

export function createApp(config: Config, deps: AppDeps = {}) {
  const now = deps.now ?? Date.now;
  const gateway = deps.gateway ?? createGateway(config);
  const { authRouter, requireAuth } = createAuth(config, deps.authNow ?? Date.now);
  const L = config.limits;

  /**
   * Live MCP sessions, keyed by the id the client echoes back in
   * `mcp-session-id`.
   *
   * Each entry carries its own TokenRef. The bearer token is refreshed into it
   * on every authenticated request, so a tool call always forwards the
   * credential the client presented on THAT request rather than the one it
   * happened to hold when the session opened an hour ago. See TokenRef in
   * server.ts for what that used to cost.
   *
   * The map is in-process and unshared, which is fine for one container but
   * means a restart invalidates every session id in the wild. Clients recover:
   * an unknown id gets a 404 and they re-initialize. The same recovery is what
   * makes the caps in sessions.ts safe to enforce.
   */
  const sessions = new SessionStore<StreamableHTTPServerTransport, TokenRef>(
    { perUser: L.sessionsPerUser, global: L.sessionsGlobal, idleMs: L.sessionIdleMs },
    now,
    (id, s, reason) => log("info", "session_closed", { session: shortId(id), userId: s.userId, clientId: s.tokenRef.clientId, reason }),
  );
  const initPerIp = new FixedWindowLimiter(L.initPerIpPerWindow, L.initWindowMs, now);
  const initPerUser = new FixedWindowLimiter(L.initPerUserPerWindow, L.initWindowMs, now);
  const ipExempt = ipMatcher(L.initIpExempt);

  /** Refresh a live session's token and caller ids from this request. */
  function touch(req: AuthedRequest): ReturnType<typeof sessions.get> {
    const s = sessions.get(req.headers["mcp-session-id"] as string | undefined, req.mcpUserId);
    if (s) {
      if (req.mcpToken) s.tokenRef.current = req.mcpToken;
      s.tokenRef.clientId = req.mcpClientId;
    }
    return s;
  }

  const app = express();
  app.disable("x-powered-by");

  app.use(cors({ origin: "*", exposedHeaders: ["Mcp-Session-Id", "Mcp-Protocol-Version"] }));

  // One line per request, written when the connection is done with it (a
  // long-lived GET stream logs when it ends, an aborted request still logs), with the
  // caller's ids once requireAuth has set them and the JSON-RPC method and
  // tool name the /mcp handler found. Replaces the old free-text request line,
  // which had no time and no caller.
  app.use((req, res, next) => {
    const started = now();
    res.once("close", () => {
      const areq = req as AuthedRequest;
      const rpc = (res.locals.rpc ?? {}) as { method?: string; tool?: string };
      log("info", "http", {
        method: req.method,
        path: req.path.slice(0, 128),
        status: res.statusCode,
        ms: now() - started,
        userId: areq.mcpUserId,
        clientId: areq.mcpClientId,
        // Only the old kind is named, so the end of HS256 traffic is one grep.
        alg: areq.mcpTokenAlg === "HS256" ? "HS256" : undefined,
        rpc: rpc.method,
        tool: rpc.tool,
        session: shortId(req.headers["mcp-session-id"] as string | undefined),
        ua: (req.headers["user-agent"] ?? "").slice(0, 40) || undefined,
      });
    });
    next();
  });

  // Resource metadata (no auth).
  app.use(authRouter);

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", server: "returnolio-mcp" });
  });

  // The body is parsed only after the token checks out, so an anonymous caller
  // cannot make the server parse anything.
  const json = express.json({ limit: "256kb" });

  app.post(
    "/mcp",
    requireAuth,
    json,
    wrap(async (req, res) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      const rpc = rpcSummary(req.body);
      res.locals.rpc = rpc;
      const who = { userId: req.mcpUserId, clientId: req.mcpClientId, ...rpc };

      const existing = touch(req);
      if (existing) {
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }
      if (sessionId) {
        res.status(404).json({ error: "session_not_found" });
        return;
      }
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({ error: "first_request_must_be_initialize" });
        return;
      }

      const userId = req.mcpUserId!;
      const ip = clientIp(req);
      // Both limits are checked before either is counted, so a request the IP
      // limit refuses does not use up the user's allowance (or the reverse).
      // Claude.ai's own outbound range is exempt from the IP limit: every
      // Claude.ai user arrives from it, so there it would be one bucket for
      // all of them (see initIpExempt in config.ts).
      const exempt = ipExempt(ip);
      const byUser = initPerUser.peek(userId);
      const byIp = exempt ? byUser : initPerIp.peek(ip);
      if (!byUser.ok || !byIp.ok) {
        const refused = byUser.ok ? byIp : byUser;
        log("warn", "initialize_rate_limited", { ...who, by: byUser.ok ? "ip" : "user" });
        res.setHeader("Retry-After", String(refused.retryAfterSec));
        res.status(429).json({ error: "rate_limited" });
        return;
      }
      initPerUser.hit(userId);
      if (!exempt) initPerIp.hit(ip);
      if (!sessions.reserve(userId)) {
        log("error", "session_capacity_full", { ...who, live: sessions.size });
        res.setHeader("Retry-After", "60");
        res.status(503).json({ error: "server_busy" });
        return;
      }

      try {
        const tokenRef: TokenRef = { current: req.mcpToken!, userId, clientId: req.mcpClientId };
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (id) => {
            sessions.add(id, transport, tokenRef, userId);
            log("info", "session_created", { userId, clientId: req.mcpClientId, session: shortId(id), live: sessions.size });
          },
        });
        transport.onclose = () => {
          sessions.forgetTransport(transport);
        };

        const server = createMcpServer(tokenRef, gateway);
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      } finally {
        sessions.release();
      }
    }),
  );

  app.get(
    "/mcp",
    requireAuth,
    wrap(async (req, res) => {
      const session = touch(req);
      if (!session) {
        res.status(404).json({ error: "session_not_found" });
        return;
      }
      await session.transport.handleRequest(req, res);
    }),
  );

  app.delete(
    "/mcp",
    requireAuth,
    wrap(async (req, res) => {
      const session = touch(req);
      if (!session) {
        res.status(404).json({ error: "session_not_found" });
        return;
      }
      await session.transport.handleRequest(req, res);
    }),
  );

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  app.use(errorHandler);

  const sweepTimer = setInterval(() => sessions.sweep(), 5 * 60 * 1000);
  sweepTimer.unref();

  return { app, sessions, close: () => clearInterval(sweepTimer) };
}
