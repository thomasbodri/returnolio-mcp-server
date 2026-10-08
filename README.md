# Returnolio MCP server

This is the MCP server behind `https://mcp.returnolio.com/mcp`. It lets Claude, ChatGPT and
other MCP clients read Returnolio's stock research for a signed-in user: company scores,
the monthly Top 10, the screener, the market overview, the events calendar, and the user's
own watchlist and portfolio.

It is listed in the official MCP Registry as `com.returnolio/returnolio`.

## Connect

In Claude: Settings › Connectors › Add custom connector, then paste
`https://mcp.returnolio.com/mcp`. You sign in with your Returnolio account. A Returnolio plan
decides which tools answer. Setup for other clients is at
https://returnolio.com/docs/features/mcp

## Tools

All tools are read-only. None of them can trade, move money or change your data.

| Tool | What it returns |
| --- | --- |
| `get_stock_score` | The score for one stock, with its five pillars: Quality, Earnings-Power, Value Margin-of-Safety, Momentum and Smart Money |
| `compare_stocks` | Several stocks side by side |
| `screen_stocks` | Companies that pass your filters |
| `search_tickers` | Find a ticker by name |
| `get_top10` | The monthly Top 10 |
| `get_moonshot` | The Moonshot Detected picks |
| `get_market_overview` | The headline indexes and a macro snapshot: rates, inflation, jobs |
| `get_calendar` | Earnings, events and IPOs |
| `my_watchlist` | Your own watchlist |
| `my_portfolio` | Your own portfolio, as numbers only |
| `get_app_link` | A link to the matching page in the Returnolio app |

Every answer carries a link to the same view in the app. Returnolio is a financial publisher,
not an investment adviser: nothing here is a recommendation to buy or sell.

## How it is built

The server is thin on purpose. It holds no database credentials and makes no product
decisions. Each tool call goes to the Returnolio web app's gateway, which checks the user's
plan again, applies rate limits, caps result sizes and attaches the disclaimer.

- **Sign-in:** OAuth. Access tokens are signed by the web app with an Ed25519 private key.
  This server holds only the public key, so it can check a token but cannot make one.
- **Calls to the gateway** carry a signature over the path, the query string and the token,
  so a token copied by hand cannot be replayed against the gateway.
- **Limits:** live sessions per user and per server, an idle timeout, and rate limits on
  opening sessions. All are set by environment variables (`src/config.ts`).
- **Fails closed:** the server will not start without a valid public key and service secret.
  It logs the variable's name, never its value.
- **Logs:** one JSON line per event. Tokens and email addresses are dropped or masked
  (`src/log.ts`).

## Run it yourself

```bash
cp .env.example .env   # fill in MCP_JWT_PUBLIC_KEY and MCP_SERVICE_SECRET
npm ci
npm test               # typecheck, build and every test
npm start
```

Without a Returnolio gateway behind it the server starts, but every tool call is refused.
The code is here so you can read how it handles your sign-in and your data.

## Security

Please report a vulnerability as described at https://returnolio.com/.well-known/security.txt
