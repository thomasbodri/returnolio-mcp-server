// The 2026-09-28 hardening: fail-closed config, session caps, idle expiry,
// initialize rate limits, errors without stack traces, and log lines that name
// the caller by id and never carry a token or an email. Runs against the build
// (`npm test` builds first) on a loopback port with a stub gateway, so nothing
// leaves the process and no real secret is involved.
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { loadConfig, ConfigError, DEFAULT_LIMITS } from "../dist/config.js";
import { createGateway } from "../dist/gateway.js";
import { createApp, wrap, errorHandler } from "../dist/app.js";
import { SessionStore } from "../dist/sessions.js";
import { FixedWindowLimiter, ipMatcher } from "../dist/ratelimit.js";
import { setLogSink, scrub } from "../dist/log.js";

import { APP_KEYS, AUDIENCE, ISSUER, claims, publicKeyEnv, signEdDSA } from "./keys.mjs";

const SERVICE_SECRET = "s".repeat(64);
const PUBLIC_KEY = publicKeyEnv();

function testConfig(limits = {}) {
  return {
    port: 0,
    jwtPublicKey: APP_KEYS.publicKey,
    legacyHs256: null,
    serviceSecret: SERVICE_SECRET,
    serverUrl: AUDIENCE,
    issuer: ISSUER,
    audience: AUDIENCE,
    frontendUrl: "http://127.0.0.1:9",
    limits: { ...DEFAULT_LIMITS, ...limits },
  };
}

function token(sub, extra = {}) {
  return signEdDSA(claims(sub, extra));
}

// Log capture shared by every test in this file.
const lines = [];
setLogSink((line) => lines.push(line));

async function start(limits = {}, gateway) {
  let t = 1_000_000;
  const clock = { now: () => t, advance: (ms) => (t += ms) };
  const { app, sessions, close } = createApp(testConfig(limits), {
    now: clock.now,
    gateway: gateway ?? (async () => JSON.stringify({ ok: true })),
  });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    base,
    sessions,
    clock,
    async stop() {
      close();
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    },
  };
}

const HEADERS = { "content-type": "application/json", accept: "application/json, text/event-stream" };

function initBody(id = 1) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
  });
}

async function initialize(base, tok, extraHeaders = {}) {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { ...HEADERS, authorization: `Bearer ${tok}`, ...extraHeaders },
    body: initBody(),
  });
  await res.text();
  return { status: res.status, id: res.headers.get("mcp-session-id"), res };
}

async function rpc(base, tok, sessionId, body) {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { ...HEADERS, authorization: `Bearer ${tok}`, "mcp-session-id": sessionId },
    body: JSON.stringify(body),
  });
  return { status: res.status, text: await res.text() };
}

const listTools = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };

// ---------------------------------------------------------------- config

test("config refuses to load without the token key or the service secret, naming them and never a value", () => {
  assert.throws(() => loadConfig({}), (err) => {
    assert.ok(err instanceof ConfigError);
    assert.ok(err.problems.includes("MCP_JWT_PUBLIC_KEY is not set"));
    assert.ok(err.problems.includes("MCP_SERVICE_SECRET is not set"));
    return true;
  });
  assert.throws(
    () => loadConfig({ MCP_JWT_PUBLIC_KEY: PUBLIC_KEY, MCP_SERVICE_SECRET: "short-secret-value" }),
    (err) => {
      assert.deepEqual(err.problems, ["MCP_SERVICE_SECRET is shorter than 32 characters"]);
      assert.doesNotMatch(err.message, /short-secret-value/);
      return true;
    },
  );
  assert.throws(
    () => loadConfig({ MCP_JWT_PUBLIC_KEY: PUBLIC_KEY, MCP_SERVICE_SECRET: SERVICE_SECRET, MCP_SESSIONS_PER_USER: "0" }),
    /MCP_SESSIONS_PER_USER must be a positive integer/,
  );
});

test("MCP_INIT_IP_EXEMPT: default is Anthropic's outbound range, 'none' clears it, a typo stops the boot", () => {
  const base = { MCP_JWT_PUBLIC_KEY: PUBLIC_KEY, MCP_SERVICE_SECRET: SERVICE_SECRET };
  assert.deepEqual(loadConfig(base).limits.initIpExempt, ["160.79.104.0/21"]);
  assert.deepEqual(loadConfig({ ...base, MCP_INIT_IP_EXEMPT: "none" }).limits.initIpExempt, []);
  assert.deepEqual(
    loadConfig({ ...base, MCP_INIT_IP_EXEMPT: " 203.0.113.0/24 , 2001:db8::/32" }).limits.initIpExempt,
    ["203.0.113.0/24", "2001:db8::/32"],
  );
  assert.throws(() => loadConfig({ ...base, MCP_INIT_IP_EXEMPT: "160.79.104.0/21,anthropic" }), (err) => {
    assert.ok(err instanceof ConfigError);
    assert.match(err.problems[0], /^MCP_INIT_IP_EXEMPT: not an IP address/);
    return true;
  });
});

test("config loads with the key and the secret and the documented defaults", () => {
  const c = loadConfig({ MCP_JWT_PUBLIC_KEY: PUBLIC_KEY, MCP_SERVICE_SECRET: SERVICE_SECRET });
  assert.equal(c.legacyHs256, null);
  assert.equal(c.port, 3459);
  assert.equal(c.limits.sessionIdleMs, 60 * 60 * 1000);
  assert.equal(c.limits.sessionsPerUser, 10);
  assert.equal(c.limits.sessionsGlobal, 1000);
  assert.equal(c.audience, "https://mcp.returnolio.com");
});

test("the gateway client will not exist without the service secret", () => {
  assert.throws(() => createGateway({ frontendUrl: "http://x", serviceSecret: "" }), /MCP_SERVICE_SECRET is required/);
});

test("every gateway call is signed", async () => {
  let seen;
  const call = createGateway({ frontendUrl: "http://gw", serviceSecret: SERVICE_SECRET }, async (url, init) => {
    seen = { url, headers: init.headers };
    return new Response('{"ok":true}', { status: 200 });
  });
  await call("score", { current: "tok", userId: "7" }, { ticker: "NVDA" }, "get_stock_score");
  assert.equal(seen.url, "http://gw/api/mcp/data/score?ticker=NVDA");
  assert.match(seen.headers["x-mcp-service"], /^\d+\.[0-9a-f]{64}$/);
  assert.match(seen.headers["x-mcp-service-v2"], /^\d+\.[0-9a-f]{64}$/);
  assert.equal(seen.headers.authorization, "Bearer tok");
});

test("an unreachable gateway gives the caller no internal address", async () => {
  const call = createGateway({ frontendUrl: "http://172.18.0.1:3000", serviceSecret: SERVICE_SECRET }, async () => {
    throw new TypeError("fetch failed", { cause: new Error("connect ECONNREFUSED 172.18.0.1:3000") });
  });
  const out = await call("top10", { current: "tok" }, {}, "get_top10");
  assert.doesNotMatch(out, /172\.18|ECONNREFUSED|fetch failed/);
});

// ---------------------------------------------------------------- units

function fakeTransport() {
  return { closed: false, close() { this.closed = true; } };
}

test("per-user cap closes that user's least recently used session, and nobody else's", () => {
  let t = 0;
  const store = new SessionStore({ perUser: 2, global: 100, idleMs: 1000 }, () => t);
  const a = fakeTransport(), b = fakeTransport(), c = fakeTransport(), other = fakeTransport();
  store.add("a", a, {}, "u1"); t++;
  store.add("o", other, {}, "u2"); t++;
  store.add("b", b, {}, "u1"); t++;
  assert.ok(store.get("a", "u1")); t++; // a is now more recent than b
  store.add("c", c, {}, "u1");
  assert.equal(store.countFor("u1"), 2);
  assert.equal(b.closed, true);
  assert.equal(a.closed, false);
  assert.equal(other.closed, false);
  assert.equal(store.get("b", "u1"), undefined);
});

test("global cap refuses a new session instead of evicting someone else's", () => {
  const store = new SessionStore({ perUser: 5, global: 2, idleMs: 1000 }, () => 0);
  assert.equal(store.reserve(), true);
  store.add("a", fakeTransport(), {}, "u1");
  store.release();
  assert.equal(store.reserve(), true);
  // A reservation in flight counts, so a parallel initialize cannot slip past.
  assert.equal(store.reserve(), false);
  store.add("b", fakeTransport(), {}, "u2");
  store.release();
  assert.equal(store.reserve(), false);
  assert.equal(store.size, 2);
});

test("a full server still lets a user at their own cap swap their oldest session", () => {
  const store = new SessionStore({ perUser: 1, global: 2, idleMs: 1000 }, () => 0);
  store.add("a", fakeTransport(), {}, "u1");
  store.add("b", fakeTransport(), {}, "u2");
  assert.equal(store.reserve("u3"), false);
  assert.equal(store.reserve("u1"), true);
  store.add("c", fakeTransport(), {}, "u1");
  store.release();
  assert.equal(store.size, 2);
  assert.equal(store.get("a", "u1"), undefined);
  assert.ok(store.get("c", "u1"));
});

test("idle sessions expire on access and on the sweep, and free their room", () => {
  let t = 0;
  const store = new SessionStore({ perUser: 5, global: 2, idleMs: 1000 }, () => t);
  const a = fakeTransport(), b = fakeTransport();
  store.add("a", a, {}, "u1");
  store.add("b", b, {}, "u2");
  t = 999;
  assert.ok(store.get("a", "u1"));
  t = 1500;
  assert.equal(store.sweep(), 1); // b, last seen at 0
  assert.equal(b.closed, true);
  t = 2000;
  assert.equal(store.get("a", "u1"), undefined); // last seen at 999
  assert.equal(a.closed, true);
  assert.equal(store.size, 0);
});

test("a session id is not found for a different user", () => {
  const store = new SessionStore({ perUser: 5, global: 5, idleMs: 1000 }, () => 0);
  store.add("a", fakeTransport(), {}, "u1");
  assert.equal(store.get("a", "u2"), undefined);
  assert.equal(store.get("a", undefined), undefined);
  assert.ok(store.get("a", "u1"));
});

test("fixed-window limiter allows the max, refuses the next, and resets", () => {
  let t = 0;
  const lim = new FixedWindowLimiter(2, 1000, () => t);
  assert.equal(lim.hit("k").ok, true);
  assert.equal(lim.hit("k").ok, true);
  const r = lim.hit("k");
  assert.equal(r.ok, false);
  assert.equal(r.retryAfterSec, 1);
  assert.equal(lim.hit("other").ok, true);
  t = 1000;
  assert.equal(lim.hit("k").ok, true);
});

test("peek says what hit would say and counts nothing", () => {
  let t = 0;
  const lim = new FixedWindowLimiter(1, 1000, () => t);
  for (let i = 0; i < 5; i++) assert.equal(lim.peek("k").ok, true);
  assert.equal(lim.hit("k").ok, true);
  const r = lim.peek("k");
  assert.equal(r.ok, false);
  assert.equal(r.retryAfterSec, 1);
  t = 1000;
  assert.equal(lim.peek("k").ok, true);
});

test("ipMatcher reads addresses and CIDR ranges and refuses garbage", () => {
  const m = ipMatcher(["160.79.104.0/21", "2001:db8::/32", "203.0.113.7"]);
  assert.equal(m("160.79.104.0"), true);
  assert.equal(m("160.79.111.255"), true);
  assert.equal(m("160.79.112.0"), false);
  assert.equal(m("160.79.103.255"), false);
  assert.equal(m("::ffff:160.79.105.1"), true);
  assert.equal(m("2001:db8::1"), true);
  assert.equal(m("203.0.113.7"), true);
  assert.equal(m("203.0.113.8"), false);
  assert.equal(m("unknown"), false);
  assert.equal(ipMatcher([])("160.79.104.1"), false);
  assert.throws(() => ipMatcher(["160.79.104.0/33"]), /prefix/);
  assert.throws(() => ipMatcher(["160.79.104.0/"]), /prefix/);
  assert.throws(() => ipMatcher(["claude.ai"]), /not an IP/);
});

test("the limiter's memory is bounded", () => {
  const lim = new FixedWindowLimiter(1, 60_000, () => 0, 10);
  for (let i = 0; i < 100; i++) lim.hit(`ip${i}`);
  assert.ok(lim.keys <= 10, String(lim.keys));
});

// ---------------------------------------------------------------- HTTP

test("broken JSON gets a JSON 400 with no stack trace and no framework banner", async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/mcp`, {
      method: "POST",
      headers: { ...HEADERS, authorization: `Bearer ${token(1)}` },
      body: "{bad json",
    });
    const text = await res.text();
    assert.equal(res.status, 400);
    assert.deepEqual(JSON.parse(text), { error: "bad_request" });
    assert.doesNotMatch(text, /node_modules|SyntaxError|\bat\s|<pre>/);
    assert.equal(res.headers.get("x-powered-by"), null);
  } finally {
    await s.stop();
  }
});

test("without a token the body is never parsed: 401, not a parse error", async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/mcp`, { method: "POST", headers: HEADERS, body: "{bad" });
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: "missing_token" });
  } finally {
    await s.stop();
  }
});

test("unknown paths get JSON 404, not Express's HTML page", async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/nope`);
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { error: "not_found" });
  } finally {
    await s.stop();
  }
});

test("a token with no subject or the wrong scope is refused", async () => {
  const s = await start();
  try {
    assert.equal((await initialize(s.base, token(null))).status, 401);
    assert.equal((await initialize(s.base, token(1, { scope: "admin" }))).status, 401);
    assert.equal((await initialize(s.base, token(1))).status, 200);
  } finally {
    await s.stop();
  }
});

test("a thrown async handler becomes a JSON 500 without the stack", async () => {
  const app = express();
  app.get("/boom", wrap(async () => { throw new Error("secret internal detail at /app/src/x.ts:1"); }));
  app.use(errorHandler);
  const server = await new Promise((r) => { const x = app.listen(0, "127.0.0.1", () => r(x)); });
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/boom`);
    const text = await res.text();
    assert.equal(res.status, 500);
    assert.deepEqual(JSON.parse(text), { error: "internal_error" });
    assert.doesNotMatch(text, /secret internal detail|\/app\/src/);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("the user's fourth session closes their oldest; the old id then answers 404", async () => {
  const s = await start({ sessionsPerUser: 3 });
  try {
    const tok = token(42);
    const ids = [];
    for (let i = 0; i < 4; i++) {
      const r = await initialize(s.base, tok);
      assert.equal(r.status, 200);
      ids.push(r.id);
      s.clock.advance(10);
    }
    assert.equal(s.sessions.countFor("42"), 3);
    assert.equal((await rpc(s.base, tok, ids[0], listTools)).status, 404);
    assert.equal((await rpc(s.base, tok, ids[3], listTools)).status, 200);
    // Another user is untouched by user 42's churn.
    assert.equal((await initialize(s.base, token(43))).status, 200);
  } finally {
    await s.stop();
  }
});

test("when the server is full a new session gets 503, and idle ones make room", async () => {
  const s = await start({ sessionsGlobal: 2, sessionIdleMs: 60_000 });
  try {
    assert.equal((await initialize(s.base, token(1))).status, 200);
    assert.equal((await initialize(s.base, token(2))).status, 200);
    const full = await initialize(s.base, token(3));
    assert.equal(full.status, 503);
    assert.equal(full.res.headers.get("retry-after"), "60");
    s.clock.advance(60_000);
    assert.equal((await initialize(s.base, token(3))).status, 200);
  } finally {
    await s.stop();
  }
});

test("an idle session expires and its id answers 404", async () => {
  const s = await start({ sessionIdleMs: 1000 });
  try {
    const tok = token(5);
    const { id } = await initialize(s.base, tok);
    s.clock.advance(999);
    assert.equal((await rpc(s.base, tok, id, listTools)).status, 200);
    s.clock.advance(999);
    assert.equal((await rpc(s.base, tok, id, listTools)).status, 200); // the call above reset the clock
    s.clock.advance(1000);
    assert.equal((await rpc(s.base, tok, id, listTools)).status, 404);
  } finally {
    await s.stop();
  }
});

test("initialize is rate limited per user, and per IP across users", async () => {
  const s = await start({ initPerUserPerWindow: 2, initPerIpPerWindow: 3, initWindowMs: 60_000 });
  try {
    const tok = token(9);
    assert.equal((await initialize(s.base, tok)).status, 200);
    assert.equal((await initialize(s.base, tok)).status, 200);
    const limited = await initialize(s.base, tok);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.res.headers.get("retry-after")) > 0);

    // User 9's refusals did not use up the IP's allowance: one more user fits, then the IP is full.
    const ip = { "cf-connecting-ip": "203.0.113.7" };
    assert.equal((await initialize(s.base, token(10), ip)).status, 200);
    assert.equal((await initialize(s.base, token(11), ip)).status, 200);
    assert.equal((await initialize(s.base, token(12), ip)).status, 200);
    assert.equal((await initialize(s.base, token(13), ip)).status, 429);
    // A different visitor address is not affected.
    assert.equal((await initialize(s.base, token(14), { "cf-connecting-ip": "198.51.100.1" })).status, 200);

    s.clock.advance(60_000);
    assert.equal((await initialize(s.base, tok)).status, 200);
  } finally {
    await s.stop();
  }
});

test("a request refused by the IP limit does not use up that user's allowance", async () => {
  const s = await start({ initPerUserPerWindow: 2, initPerIpPerWindow: 1, initWindowMs: 60_000, initIpExempt: [] });
  try {
    const busy = { "cf-connecting-ip": "203.0.113.20" };
    assert.equal((await initialize(s.base, token(30), busy)).status, 200);
    // User 31 is refused three times by the IP limit...
    for (let i = 0; i < 3; i++) assert.equal((await initialize(s.base, token(31), busy)).status, 429);
    // ...and still has both of their own opens left from other addresses.
    assert.equal((await initialize(s.base, token(31), { "cf-connecting-ip": "198.51.100.31" })).status, 200);
    assert.equal((await initialize(s.base, token(31), { "cf-connecting-ip": "198.51.100.32" })).status, 200);
    assert.equal((await initialize(s.base, token(31), { "cf-connecting-ip": "198.51.100.33" })).status, 429);
  } finally {
    await s.stop();
  }
});

test("Claude.ai's outbound range is not limited per IP, but each user there still is", async () => {
  const s = await start({ initPerUserPerWindow: 2, initPerIpPerWindow: 1, initWindowMs: 60_000 });
  try {
    const claude = { "cf-connecting-ip": "160.79.104.10" };
    for (let u = 40; u < 46; u++) assert.equal((await initialize(s.base, token(u), claude)).status, 200);
    assert.equal((await initialize(s.base, token(40), claude)).status, 200);
    const limited = await initialize(s.base, token(40), claude);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.res.headers.get("retry-after")) > 0);
    // Just outside the /21 the IP limit applies as before.
    const outside = { "cf-connecting-ip": "160.79.112.10" };
    assert.equal((await initialize(s.base, token(50), outside)).status, 200);
    assert.equal((await initialize(s.base, token(51), outside)).status, 429);
  } finally {
    await s.stop();
  }
});

test("a session belongs to its user: another user's valid token gets 404", async () => {
  const s = await start();
  try {
    const { id } = await initialize(s.base, token(1));
    assert.equal((await rpc(s.base, token(2), id, listTools)).status, 404);
  } finally {
    await s.stop();
  }
});

test("a tool call forwards the token of THAT request and logs time, user, client and tool, never the token", async () => {
  const seen = [];
  const s = await start({}, async (endpoint, caller, params, tool) => {
    seen.push({ endpoint, token: caller.current, userId: caller.userId, clientId: caller.clientId, tool });
    return JSON.stringify({ ok: true });
  });
  try {
    const first = token(77, { cid: 5 });
    const { id } = await initialize(s.base, first);
    const fresh = token(77, { cid: 5, jti: "second" });
    lines.length = 0;
    const r = await rpc(s.base, fresh, id, {
      jsonrpc: "2.0", id: 3, method: "tools/call",
      params: { name: "get_stock_score", arguments: { ticker: "someone@example.com" } },
    });
    assert.equal(r.status, 200);
    assert.deepEqual(seen, [{ endpoint: "score", token: fresh, userId: "77", clientId: "5", tool: "get_stock_score" }]);

    const http = lines.map((l) => JSON.parse(l)).find((l) => l.event === "http" && l.rpc === "tools/call");
    assert.ok(http, lines.join("\n"));
    assert.match(http.time, /^\d{4}-\d\d-\d\dT/);
    assert.equal(http.userId, "77");
    assert.equal(http.clientId, "5");
    assert.equal(http.tool, "get_stock_score");
    const all = lines.join("\n");
    assert.ok(!all.includes(fresh) && !all.includes(first), "a token reached the log");
    assert.doesNotMatch(all, /someone@example\.com/);
  } finally {
    await s.stop();
  }
});

test("the log scrubber drops credential fields and masks tokens and emails in text", () => {
  const out = scrub({
    token: "abc",
    authorization: "Bearer x",
    email: "a@b.co",
    message: `failed for jane.doe@example.com with ${token(1)}`,
    userId: "7",
  });
  assert.deepEqual(Object.keys(out).sort(), ["message", "userId"]);
  assert.equal(out.message, "failed for [email] with [token]");
});
