// Service signature v2: the query string and the token are signed too
// (OWASP audit 2026-09-28, M27). The web app verifies it in
// src/lib/mcp/service-hmac.ts; the vector below is in that repo's
// service-hmac.test.ts as well, so the two implementations cannot drift.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { canonicalQuery, createGateway, signServiceHeaderV2 } from "../dist/gateway.js";
import { setLogSink } from "../dist/log.js";

setLogSink(() => {});
const SECRET = "s".repeat(64);
const TOKEN = "header.payload.signature";

test("the shared vector", () => {
  const params = new URLSearchParams({ sector: "Tech & Media", min_score: "70" });
  assert.equal(canonicalQuery(params), "min_score=70&sector=Tech+%26+Media");
  assert.equal(
    signServiceHeaderV2(SECRET, "/api/mcp/data/screen", params, TOKEN, "1759000000000"),
    "1759000000000.6499e447a6bcf8b2a5210794831096c93afd0f86c13673e17a6b328eb3b122d5",
  );
});

/** What the web app computes for a request it received. */
function expected(url, token, ts) {
  const u = new URL(url);
  return signServiceHeaderV2(SECRET, u.pathname, u.searchParams, token, ts);
}

test("every gateway call carries a v2 signature over exactly what it sent", async () => {
  let seen;
  const call = createGateway({ frontendUrl: "http://gw", serviceSecret: SECRET }, async (url, init) => {
    seen = { url, headers: init.headers };
    return new Response("{}", { status: 200 });
  });
  await call("screen", { current: TOKEN, userId: "7" }, { sector: "Tech & Media", min_score: "70", empty: "" }, "screen_stocks");
  const v2 = seen.headers["x-mcp-service-v2"];
  const ts = v2.split(".")[0];
  assert.equal(v2, expected(seen.url, TOKEN, ts));
  assert.equal(seen.headers["x-mcp-service"].split(".")[0], ts, "v1 and v2 share one timestamp");
});

test("the v2 signature does not survive a tampered query, another token or another path", async () => {
  let seen;
  const call = createGateway({ frontendUrl: "http://gw", serviceSecret: SECRET }, async (url, init) => {
    seen = { url, headers: init.headers };
    return new Response("{}", { status: 200 });
  });
  await call("score", { current: TOKEN }, { ticker: "NVDA" }, "get_stock_score");
  const v2 = seen.headers["x-mcp-service-v2"];
  const ts = v2.split(".")[0];
  assert.notEqual(v2, expected("http://gw/api/mcp/data/score?ticker=AAPL", TOKEN, ts));
  assert.notEqual(v2, expected("http://gw/api/mcp/data/score?ticker=NVDA&x=1", TOKEN, ts));
  assert.notEqual(v2, expected("http://gw/api/mcp/data/score", TOKEN, ts));
  assert.notEqual(v2, expected("http://gw/api/mcp/data/score?ticker=NVDA", "other.token.x", ts));
  assert.notEqual(v2, expected("http://gw/api/mcp/data/compare?ticker=NVDA", TOKEN, ts));
  // Order and encoding of the same parameters do not matter.
  assert.equal(
    expected("http://gw/p?b=2&a=1", TOKEN, ts),
    signServiceHeaderV2(SECRET, "/p", new URLSearchParams("a=1&b=2"), TOKEN, ts),
  );
  // A plain HMAC of the v1 string is not a v2 signature.
  const v1 = crypto.createHmac("sha256", SECRET).update(`${ts}:/api/mcp/data/score`).digest("hex");
  assert.notEqual(v2, `${ts}.${v1}`);
});
