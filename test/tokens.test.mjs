// The switch from HS256 (a secret shared with the web app, so whoever read
// this container's env could mint a token for any user) to EdDSA (the web app
// signs with a private key; this server holds only the public key). OWASP
// audit 2026-09-28, M27. Runs against the build on a loopback port with a stub
// gateway; keys are generated per run.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { loadConfig, ConfigError, DEFAULT_LIMITS } from "../dist/config.js";
import { createApp } from "../dist/app.js";
import { legacyWindowOpen, MAX_WINDOW_MS } from "../dist/auth.js";
import { setLogSink } from "../dist/log.js";
import { APP_KEYS, AUDIENCE, ISSUER, claims, keyPair, publicKeyEnv, signEdDSA, signHS256, unsigned } from "./keys.mjs";

const SERVICE_SECRET = "s".repeat(64);
const LEGACY_SECRET = "t".repeat(64);
const HOUR = 60 * 60 * 1000;

const lines = [];
setLogSink((line) => lines.push(line));

async function start({ legacyUntil = null, authNow } = {}) {
  const config = {
    port: 0,
    jwtPublicKey: APP_KEYS.publicKey,
    legacyHs256: legacyUntil == null ? null : { secret: LEGACY_SECRET, until: legacyUntil },
    serviceSecret: SERVICE_SECRET,
    serverUrl: AUDIENCE,
    issuer: ISSUER,
    audience: AUDIENCE,
    frontendUrl: "http://127.0.0.1:9",
    limits: { ...DEFAULT_LIMITS },
  };
  const { app, close } = createApp(config, { gateway: async () => "{}", ...(authNow ? { authNow } : {}) });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    async stop() {
      close();
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    },
  };
}

async function status(base, token) {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    }),
  });
  await res.text();
  return res.status;
}

// ---------------------------------------------------------------- EdDSA

test("an EdDSA token signed with the web app's key is accepted", async () => {
  const s = await start();
  try {
    assert.equal(await status(s.base, signEdDSA(claims(1))), 200);
    assert.equal(await status(s.base, signEdDSA(claims(2), APP_KEYS.privateKey, { kid: "abc" })), 200);
  } finally {
    await s.stop();
  }
});

test("EdDSA tokens are refused when signed by another key, tampered, expired, or for another issuer or audience", async () => {
  const s = await start();
  try {
    assert.equal(await status(s.base, signEdDSA(claims(1), keyPair().privateKey)), 401);
    const [h, , sig] = signEdDSA(claims(1)).split(".");
    const forged = Buffer.from(JSON.stringify(claims(2))).toString("base64url");
    assert.equal(await status(s.base, `${h}.${forged}.${sig}`), 401);
    const past = Math.floor(Date.now() / 1000) - 60;
    assert.equal(await status(s.base, signEdDSA(claims(1, { exp: past }))), 401);
    assert.equal(await status(s.base, signEdDSA(claims(1, { iss: "https://evil.test" }))), 401);
    assert.equal(await status(s.base, signEdDSA(claims(1, { aud: "https://other.test" }))), 401);
  } finally {
    await s.stop();
  }
});

test("alg none and HS256 keyed with the public key are refused", async () => {
  const s = await start({ legacyUntil: Date.now() + HOUR });
  try {
    assert.equal(await status(s.base, unsigned(claims(1))), 401);
    const pem = APP_KEYS.publicKey.export({ format: "pem", type: "spki" }).toString();
    assert.equal(await status(s.base, signHS256(claims(1), pem)), 401);
    assert.equal(await status(s.base, signHS256(claims(1), publicKeyEnv())), 401);
  } finally {
    await s.stop();
  }
});

// ---------------------------------------------------------------- HS256 window

test("HS256 tokens the web app issued before the switch pass inside the window", async () => {
  const s = await start({ legacyUntil: Date.now() + HOUR });
  try {
    lines.length = 0;
    assert.equal(await status(s.base, signHS256(claims(7), LEGACY_SECRET)), 200);
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(lines.some((l) => l.includes('"alg":"HS256"')), "the access line names the old kind, so its end is one grep");
    assert.equal(await status(s.base, signHS256(claims(7), "another-secret-" + "x".repeat(40))), 401);
  } finally {
    await s.stop();
  }
});

test("HS256 is refused once the window has ended, with no window, and with a window set too far ahead", async () => {
  const until = Date.now() + HOUR;
  const after = await start({ legacyUntil: until, authNow: () => until });
  const none = await start();
  const far = await start({ legacyUntil: Date.now() + MAX_WINDOW_MS + HOUR });
  try {
    const t = signHS256(claims(7, { exp: Math.floor(until / 1000) + 600 }), LEGACY_SECRET);
    assert.equal(await status(after.base, t), 401);
    assert.equal(await status(none.base, t), 401);
    assert.equal(await status(far.base, t), 401);
    // EdDSA is unaffected by the window.
    assert.equal(await status(after.base, signEdDSA(claims(7, { exp: Math.floor(until / 1000) + 600 }))), 200);
  } finally {
    await Promise.all([after.stop(), none.stop(), far.stop()]);
  }
});

test("legacyWindowOpen: open strictly before `until`, never more than 7 days out", () => {
  const legacy = { secret: LEGACY_SECRET, until: 10 * HOUR };
  assert.equal(legacyWindowOpen(legacy, 10 * HOUR - 1), true);
  assert.equal(legacyWindowOpen(legacy, 10 * HOUR), false);
  assert.equal(legacyWindowOpen(null, 0), false);
  assert.equal(legacyWindowOpen({ secret: LEGACY_SECRET, until: MAX_WINDOW_MS + 1 }, 0), false);
});

// ---------------------------------------------------------------- config

const base = { MCP_JWT_PUBLIC_KEY: publicKeyEnv(), MCP_SERVICE_SECRET: SERVICE_SECRET };

function problems(env) {
  try {
    loadConfig(env);
  } catch (err) {
    assert.ok(err instanceof ConfigError);
    return err.problems;
  }
  return [];
}

test("the public key is read from base64 SPKI DER and from a one-line PEM with \\n escapes", () => {
  const pem = APP_KEYS.publicKey.export({ format: "pem", type: "spki" }).toString().replace(/\n/g, "\\n");
  const a = loadConfig(base).jwtPublicKey;
  const b = loadConfig({ ...base, MCP_JWT_PUBLIC_KEY: pem }).jwtPublicKey;
  assert.ok(a.equals(b));
  assert.equal(a.asymmetricKeyType, "ed25519");
});

test("a private key, a non-Ed25519 key or garbage stops the boot, by name only", () => {
  const priv = APP_KEYS.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  assert.deepEqual(problems({ ...base, MCP_JWT_PUBLIC_KEY: priv }), [
    "MCP_JWT_PUBLIC_KEY holds a private key; this server must get only the public key",
  ]);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey
    .export({ format: "der", type: "spki" }).toString("base64");
  assert.deepEqual(problems({ ...base, MCP_JWT_PUBLIC_KEY: rsa }), ["MCP_JWT_PUBLIC_KEY is not an Ed25519 key"]);
  const bad = problems({ ...base, MCP_JWT_PUBLIC_KEY: "not-a-key-VALUE" });
  assert.deepEqual(bad, ["MCP_JWT_PUBLIC_KEY is not a readable public key"]);
  assert.doesNotMatch(bad.join(" "), /VALUE/);
});

test("the HS256 window needs a parseable end time and the old secret; unset, the secret is ignored", () => {
  assert.equal(loadConfig({ ...base, MCP_JWT_SECRET: LEGACY_SECRET }).legacyHs256, null);
  const c = loadConfig({ ...base, MCP_JWT_SECRET: LEGACY_SECRET, MCP_LEGACY_AUTH_UNTIL: "2026-09-30T12:00:00Z" });
  assert.deepEqual(c.legacyHs256, { secret: LEGACY_SECRET, until: Date.parse("2026-09-30T12:00:00Z") });
  assert.deepEqual(problems({ ...base, MCP_LEGACY_AUTH_UNTIL: "2026-09-30T12:00:00Z" }), ["MCP_JWT_SECRET is not set"]);
  assert.deepEqual(problems({ ...base, MCP_JWT_SECRET: LEGACY_SECRET, MCP_LEGACY_AUTH_UNTIL: "friday" }), [
    "MCP_LEGACY_AUTH_UNTIL is not an ISO time",
  ]);
});
