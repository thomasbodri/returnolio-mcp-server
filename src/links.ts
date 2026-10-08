// Static deep-link fallback for the read-only connector.
//
// The MCP cannot place trades, change a user's holdings or watchlist, manage
// alert subscriptions, or give personalized advice. When the user asks for any
// of those, the model is told (via the server instructions) NOT to improvise,
// but to call get_app_link and hand back the exact in-app page. This module is
// pure data + one resolver so the behavior is deterministic and testable.

const APP_BASE = process.env.MCP_APP_BASE || "https://app.returnolio.com";

/**
 * Every link this tool hands back carries the connector's campaign tag, the
 * same keys the gateway puts on `_app_cta.url` (webapp src/lib/mcp/app-cta.ts),
 * so a visit that starts here is counted as one in site_hits.
 */
export function withMcpUtm(url: string, campaign = "get_app_link"): string {
  const u = new URL(url);
  u.searchParams.set("utm_source", "claude");
  u.searchParams.set("utm_medium", "mcp");
  u.searchParams.set("utm_campaign", campaign);
  return u.toString();
}

interface LinkRule {
  keywords: string[];
  path: string;
  label: string;
}

// Order matters: earlier rules win. The trade/broker rule is first so "buy a
// stock" routes to the explicit "we don't place trades" message rather than the
// generic portfolio page.
const RULES: LinkRule[] = [
  {
    keywords: ["buy", "sell", "trade", "order", "purchase", "execute", "broker", "brokerage"],
    path: "/my-portfolio",
    label:
      "Returnolio does not place trades or move money. Track the position in your portfolio here and trade with your own broker",
  },
  {
    keywords: ["watchlist", "watch list", "follow ", "unfollow", "watch "],
    path: "/my-portfolio?tab=watchlist",
    label: "Add or remove tickers on your watchlist, under My Portfolio",
  },
  {
    keywords: ["portfolio", "holding", "position", "cost basis", "cash", "add ticker", "transaction"],
    path: "/my-portfolio",
    label: "View and edit your portfolio",
  },
  {
    keywords: ["alert", "notify", "notification", "subscribe", "unsubscribe"],
    path: "/alerts",
    label: "Manage your alerts and subscriptions",
  },
  {
    keywords: ["ipo", "calendar", "earnings", "dividend", "split", "event"],
    path: "/events",
    label: "See the events and IPO calendar",
  },
  {
    keywords: ["top 10", "top10", "top ten"],
    path: "/top10",
    label: "See the current Top 10",
  },
  { keywords: ["moonshot"], path: "/top10", label: "See the Moonshot candidates, alongside the Top 10" },
  {
    keywords: ["screen", "universe", "filter", "scan"],
    path: "/universe",
    label: "Use the full screener in the Universe view",
  },
  {
    keywords: ["smart money", "institution", "13f", "hedge fund", "guru"],
    path: "/smart-money",
    label: "See Smart Money positioning",
  },
  { keywords: ["compare"], path: "/compare", label: "Compare stocks side by side" },
  {
    keywords: ["market", "macro", "yield", "forex", "commodity", "crypto"],
    path: "/market",
    label: "See the market overview",
  },
  {
    keywords: ["method", "scoring", "how is the score", "weight", "pillar"],
    path: "/methodology",
    label: "Read the scoring methodology",
  },
  {
    keywords: ["setting", "account", "plan", "subscription", "billing", "upgrade"],
    path: "/settings",
    label: "Manage your account in settings",
  },
  { keywords: ["predict", "forecast"], path: "/predictions", label: "See the predictions" },
];

export interface AppLink {
  url: string;
  label: string;
  matched: boolean;
}

/** Resolve a free-text action to the best in-app page. Falls back to the app home. */
export function resolveAppLink(action: string): AppLink {
  const a = (action || "").toLowerCase();
  const rule = RULES.find((r) => r.keywords.some((k) => a.includes(k)));
  if (rule) {
    return { url: withMcpUtm(`${APP_BASE}${rule.path}`), label: rule.label, matched: true };
  }
  return { url: withMcpUtm(APP_BASE), label: "Open Returnolio", matched: false };
}

/** The exact text the get_app_link tool returns to the model. */
export function appLinkMessage(action: string): string {
  const { url, label } = resolveAppLink(action);
  return [
    `This connector is read-only and cannot do that here, for regulatory reasons (Returnolio is a financial publisher, not an investment adviser).`,
    ``,
    `${label}:`,
    url,
    ``,
    `If the link is not clickable in this chat, copy it into your web browser.`,
    ``,
    `Information only, not investment advice.`,
  ].join("\n");
}
