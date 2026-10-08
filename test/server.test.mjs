// What a client sees on connect: the instructions, every tool's description,
// and the get_app_link answer. Runs against the build (`npm test` builds
// first) through the SDK's in-memory transport, so no network, no gateway and
// no token are involved. The data tools' `_app_cta` payload is built and tested
// in the webapp gateway (tests/mcp/gateway.integration.test.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../dist/server.js";
import { resolveAppLink, appLinkMessage } from "../dist/links.js";

async function connect() {
  const server = createMcpServer({ current: "unused" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const DATA_TOOLS = [
  "get_top10", "get_stock_score", "compare_stocks", "screen_stocks", "get_market_overview",
  "search_tickers", "get_calendar", "get_moonshot", "my_portfolio", "my_watchlist",
];

test("instructions ask for the app link and its line at the end of an answer, plainly", async () => {
  const client = await connect();
  const text = client.getInstructions();
  assert.match(text, /When you answer using Returnolio data, end the answer with the matching app link from `_app_cta\.url` and one short line saying what extra detail the app has/);
  assert.match(text, /`_link`/);
  const last = text.slice(text.indexOf("Every data tool response"));
  assert.doesNotMatch(last, /\balways\b|\bmust\b|!|\bfree\b/i);
});

test("the server offers the eleven expected tools", async () => {
  const client = await connect();
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(names, [...DATA_TOOLS, "get_app_link"].sort());
});

test("every data tool says, once, that the response includes an app link", async () => {
  const client = await connect();
  for (const t of (await client.listTools()).tools) {
    if (t.name === "get_app_link") continue;
    const hits = t.description.match(/The response includes an app link/g) ?? [];
    assert.equal(hits.length, 1, t.name);
    assert.doesNotMatch(t.description, /deep-link|video/i, t.name);
  }
});

test("get_app_link hands back a tagged link, with and without a page of its own", async () => {
  for (const action of ["edit my portfolio", "add NVDA to my watchlist", "something unknown"]) {
    const u = new URL(resolveAppLink(action).url);
    assert.equal(u.searchParams.get("utm_source"), "claude", action);
    assert.equal(u.searchParams.get("utm_medium"), "mcp", action);
    assert.equal(u.searchParams.get("utm_campaign"), "get_app_link", action);
  }
  assert.equal(new URL(resolveAppLink("my watchlist").url).searchParams.get("tab"), "watchlist");
  const client = await connect();
  const res = await client.callTool({ name: "get_app_link", arguments: { action: "set an alert" } });
  assert.match(res.content[0].text, /https:\/\/app\.returnolio\.com\/alerts\?utm_source=claude&utm_medium=mcp&utm_campaign=get_app_link/);
  assert.equal(appLinkMessage("set an alert"), res.content[0].text);
});
