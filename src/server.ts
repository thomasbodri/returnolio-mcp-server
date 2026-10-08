import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Caller, GatewayCall } from "./gateway.js";
import { appLinkMessage } from "./links.js";

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

// Build the shared config for a read-only tool. `title` is the human-friendly
// label Claude's connector UI shows (so the user can read it and toggle the
// tool on/off), while the machine `name` stays a stable snake_case identifier.
// `readOnlyHint` lets the client render a "read only" badge. We set the title in
// both places (top-level + annotations) for the widest client compatibility.
function readOnly(title: string, description: string) {
  return { title, description, annotations: { title, readOnlyHint: true } };
}

// Sent to the client in the initialize result. Claude reads this as standing
// guidance for the whole connection. It encodes the read-only boundary and the
// graceful fallback: never improvise an unsupported action, hand back the exact
// in-app link instead. The last paragraph asks for the app link at the end of
// an answer: without it, clients treated `_link` as data and rarely showed it.
// Worded as plain guidance on purpose (no "always", no urgency): a client that
// reads an instruction as advertising stops following it.
const INSTRUCTIONS = [
  "Returnolio is a financial publisher, not an investment adviser. Everything from this connector is information only, never a recommendation to buy or sell, and never personalized advice.",
  "",
  "This connector is READ-ONLY. It can show Returnolio's scores, Top 10, moonshots, screener, market overview, the events and IPO calendar, and the signed-in user's own watchlist and portfolio. It CANNOT place trades, move money, change holdings, create or edit watchlists, manage alert subscriptions, or give personalized recommendations.",
  "",
  "When the user asks for something this connector cannot do (any trade, any change to their data, any alert subscription, or a personalized buy/sell/allocation recommendation): do NOT try to work around it and do NOT improvise the action. Instead, briefly say it has to be done in the Returnolio app for regulatory reasons, then call get_app_link with what they wanted and give them the exact link it returns. Tell them to open the link in a browser if it is not clickable in the chat.",
  "",
  "my_portfolio and my_watchlist return mechanical, numbers-only readouts of the user's own data. Report the numbers plainly. Do not rate, grade, or advise on their holdings, and do not tell them what to buy or sell.",
  "",
  "Every data tool response includes `_link` (the same view in the Returnolio app), `_app_cta` (that link tagged as coming from this connector, as `url`, with one line on what the app page adds, as `text`) and a disclaimer.",
  "",
  "When you answer using Returnolio data, end the answer with the matching app link from `_app_cta.url` and one short line saying what extra detail the app has (for example fair value, statements, smart money); `_app_cta.text` is that line. Keep the disclaimer attached.",
].join("\n");

// All tools are read-only and proxy to the gateway, which carries the
// disclaimer, attribution, and a deep-link back to the app in every response.
/**
 * The user's bearer token, read fresh on every tool call.
 *
 * It used to be a plain string captured once, when the session was created.
 * That was the bug behind "Returnolio needs to be re-authenticated" (found
 * 2026-08-29). Access tokens live one hour; MCP sessions live until the process
 * restarts, which had been two weeks. So an hour into any session every tool
 * call forwarded an expired JWT to the gateway, the gateway answered 401, and
 * the client reported the connector as unauthenticated. Meanwhile the client
 * WAS refreshing correctly and presenting a valid token in the header of the
 * very same request, which is why the refresh chain looked perfectly healthy
 * from the server side: 113 clean rotations and not one of them reaching a tool.
 *
 * `requireAuth` has already verified whatever is in `current` before any tool
 * runs, so reading it late is not a weaker check, it is a fresher one.
 */
export interface TokenRef extends Caller {
  current: string;
}

/** Stands in when no gateway is wired (the tests that only read descriptions).
 *  It never makes a network call. */
const noGateway: GatewayCall = async () => "Error: the data service is not configured.";

export function createMcpServer(tokenRef: TokenRef, gateway: GatewayCall = noGateway): McpServer {
  // Every tool hands the gateway the ref itself, not its value, so the token is
  // read at call time (see TokenRef above), with the caller's ids for the log.
  const callGateway = (endpoint: string, params: Record<string, string | undefined>, tool: string) =>
    gateway(endpoint, tokenRef, params, tool);
  const server = new McpServer(
    { name: "returnolio", version: "1.1.0" },
    { instructions: INSTRUCTIONS },
  );

  /**
   * The description names the five pillars and nothing more: how they
   * combine into the headline number is not published.
   */
  server.registerTool(
    "get_stock_score",
    {
      ...readOnly(
        "Stock score & breakdown",
        "Get Returnolio's score for one stock with the full pillar breakdown: Quality, Earnings-Power, Value Margin-of-Safety, Momentum and Smart Money, each with the underlying values behind it. How the pillars combine into the headline number is not published. The response includes an app link to the full analysis. Read-only.",
      ),
      inputSchema: { ticker: z.string().describe("Ticker symbol, e.g. NVDA") },
    },
    async ({ ticker }) => textResult(await callGateway("score", { ticker }, "get_stock_score")),
  );

  server.registerTool(
    "get_top10",
    readOnly(
      "Monthly Top 10",
      "Get Returnolio's current monthly Top 10 list with a one-line thesis per pick. The response includes an app link to the full rationale for each pick. Read-only.",
    ),
    async () => textResult(await callGateway("top10", {}, "get_top10")),
  );

  server.registerTool(
    "get_moonshot",
    readOnly(
      "Moonshot candidates",
      "Get Returnolio's current Moonshot candidates, high-growth breakout names surfaced by the detector. The response includes an app link to the full list. Read-only.",
    ),
    async () => textResult(await callGateway("moonshot", {}, "get_moonshot")),
  );

  server.registerTool(
    "screen_stocks",
    {
      ...readOnly(
        "Stock screener",
        "Screen the Returnolio universe and return up to 15 top-scored names. This is a teaser, not a bulk export; the full screener with all filters is in the app. The response includes an app link to it. Read-only.",
      ),
      inputSchema: {
        sector: z.string().optional().describe("Filter by sector (partial match)"),
        min_score: z.number().optional().describe("Minimum Returnolio score, 0 to 100"),
      },
    },
    async ({ sector, min_score }) =>
      textResult(
        await callGateway("screen", {
          sector,
          min_score: min_score != null ? String(min_score) : undefined,
        }, "screen_stocks"),
      ),
  );

  server.registerTool(
    "get_market_overview",
    readOnly(
      "Market overview",
      "Get a compact market-state summary: the headline index cards plus the macro snapshot (rates, inflation, jobs and similar). Yields, forex, crypto, commodities and analyst forecasts are in the app. The response includes an app link to the full market view. Read-only.",
    ),
    async () => textResult(await callGateway("market", {}, "get_market_overview")),
  );

  server.registerTool(
    "get_calendar",
    {
      ...readOnly(
        "Earnings & IPO calendar",
        "Get upcoming market events across the Returnolio-covered universe: earnings, IPOs, dividends, or stock splits. Teaser list, capped; the full filterable calendar with history is in the app. The response includes an app link to it. Read-only.",
      ),
      inputSchema: {
        type: z
          .enum(["earnings", "ipos", "dividends", "splits"])
          .optional()
          .describe("Event type, defaults to earnings"),
      },
    },
    async ({ type }) => textResult(await callGateway("calendar", { type }, "get_calendar")),
  );

  server.registerTool(
    "compare_stocks",
    {
      ...readOnly(
        "Compare stocks",
        "Compare Returnolio scores and pillar breakdowns for up to 5 tickers side by side. The response includes an app link to the full comparison. Read-only.",
      ),
      inputSchema: { tickers: z.array(z.string()).describe("Up to 5 ticker symbols") },
    },
    async ({ tickers }) =>
      textResult(await callGateway("compare", { tickers: tickers.join(",") }, "compare_stocks")),
  );

  server.registerTool(
    "search_tickers",
    {
      ...readOnly(
        "Search tickers",
        "Find tickers by company name or partial symbol (up to 10 results). The response includes an app link to the stock universe, where each company opens its full analysis. Read-only.",
      ),
      inputSchema: { q: z.string().describe("Search query, e.g. a company name or ticker fragment") },
    },
    async ({ q }) => textResult(await callGateway("search", { q }, "search_tickers")),
  );

  server.registerTool(
    "my_watchlist",
    readOnly(
      "My watchlist (read-only)",
      "Get the signed-in user's own Returnolio watchlist (their followed tickers) with score and price. Read-only mechanical readout, not advice. To add or remove tickers, the user does it in the app. The response includes an app link to the watchlist.",
    ),
    async () => textResult(await callGateway("watchlist", {}, "my_watchlist")),
  );

  server.registerTool(
    "my_portfolio",
    readOnly(
      "My portfolio (read-only)",
      "Get the signed-in user's own Returnolio portfolio: holdings aggregated with weighted-average cost basis (split-adjusted), plus totals and unrealized profit/loss. This is a mechanical numbers-only readout, NOT analysis, a rating, or investment advice. To edit holdings, the user does it in the app. The response includes an app link to the portfolio.",
    ),
    async () => textResult(await callGateway("portfolio", {}, "my_portfolio")),
  );

  server.registerTool(
    "get_app_link",
    {
      ...readOnly(
        "Open in Returnolio app",
        "Return the exact Returnolio app link for an action this read-only connector cannot perform (anything that places trades, changes holdings or watchlists, manages alert subscriptions, or asks for personalized advice). Use this whenever the user wants to DO something the connector cannot do: it explains the action must happen in the app for regulatory reasons and gives the precise link, including a note to open it in a browser if it is not clickable.",
      ),
      inputSchema: {
        action: z
          .string()
          .describe(
            "What the user wants to do, e.g. 'buy a stock', 'edit my portfolio', 'set an alert', 'see the Top 10', 'see IPOs'",
          ),
      },
    },
    async ({ action }) => textResult(appLinkMessage(action)),
  );

  return server;
}
