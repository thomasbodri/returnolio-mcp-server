import crypto from "node:crypto";
import type { Config } from "./config.js";
import { log } from "./log.js";

// The MCP server is thin: every tool call proxies to the Returnolio frontend
// gateway, forwarding the user's bearer token and a service-HMAC header. The
// gateway is authoritative (live plan re-check, rate limits, result caps,
// disclaimer). We just pass its JSON straight through to the model.

/** Who is calling, as far as the log needs to know. Ids only. */
export interface Caller {
  current: string;
  userId?: string;
  clientId?: string;
}

export type GatewayCall = (
  endpoint: string,
  caller: Caller,
  params: Record<string, string | undefined>,
  tool: string,
) => Promise<string>;

export function createGateway(
  config: Pick<Config, "frontendUrl" | "serviceSecret">,
  fetchImpl: typeof fetch = fetch,
): GatewayCall {
  // loadConfig refuses to start without the secret. This repeats the check
  // for any other caller: an unsigned gateway call is never sent.
  if (!config.serviceSecret) throw new Error("gateway: MCP_SERVICE_SECRET is required");

  /** v1: path only. Kept for a web app that has not been updated yet;
   *  the updated web app accepts it only inside the transition window. */
  function signServiceHeader(path: string, ts: string): string {
    const sig = crypto.createHmac("sha256", config.serviceSecret).update(`${ts}:${path}`).digest("hex");
    return `${ts}.${sig}`;
  }

  return async function callGateway(endpoint, caller, params, tool) {
    const path = `/api/mcp/data/${endpoint}`;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== "") qs.set(k, v);
    }
    const url = `${config.frontendUrl}${path}${qs.toString() ? `?${qs.toString()}` : ""}`;
    const who = { userId: caller.userId, clientId: caller.clientId, tool };
    const started = Date.now();

    try {
      const ts = String(Date.now());
      const res = await fetchImpl(url, {
        headers: {
          authorization: `Bearer ${caller.current}`,
          "x-mcp-service": signServiceHeader(path, ts),
          "x-mcp-service-v2": signServiceHeaderV2(config.serviceSecret, path, qs, caller.current, ts),
        },
      });
      const text = await res.text();
      const ms = Date.now() - started;
      if (!res.ok) {
        // Log every refusal. The gateway does not write token-level 401s to
        // mcp_calls (it has no trustworthy user id at that point), so before
        // this line an expired forwarded token produced no record anywhere:
        // the admin dashboard showed no denials, the call log showed no calls,
        // and the only symptom was the user being asked to re-authenticate.
        // Silence was the reason that bug survived a week. Only the gateway's
        // error code is logged, not its body.
        log("warn", "tool_call", { ...who, status: res.status, error: errorCode(text), ms });
        return `Error ${res.status}: ${text}`;
      }
      log("info", "tool_call", { ...who, status: res.status, ms });
      return text;
    } catch (err) {
      // The detail (address, errno) goes to the log; the caller learns only
      // that the data service could not be reached.
      log("error", "tool_call", {
        ...who,
        status: 0,
        error: err instanceof Error ? `${err.name}: ${err.message}` : "unknown",
        cause: err instanceof Error && err.cause instanceof Error ? err.cause.message : undefined,
        ms: Date.now() - started,
      });
      return "Error: could not reach Returnolio. Please try again in a moment.";
    }
  };
}

/** The `error` field of a gateway JSON answer, or a fixed word if there is none. */
function errorCode(text: string): string {
  try {
    const j = JSON.parse(text) as { error?: unknown };
    if (typeof j.error === "string" && /^[a-z0-9_]{1,64}$/i.test(j.error)) return j.error;
  } catch {
    // not JSON
  }
  return "unparsed";
}

/**
 * Service signature v2 (2026-09-28, OWASP audit M27). v1 signed only the
 * timestamp and the path, so a captured header could be replayed for five
 * minutes with another query string or another user's token. v2 signs
 *   "v2\n<ts>\n<path>\n<canonical query>\n<sha256 hex of the bearer token>"
 * The canonical query is the parameters sorted by name, then value, and
 * re-encoded with URLSearchParams. The web app's src/lib/mcp/service-hmac.ts
 * builds the identical string; the shared test vector in
 * test/gateway-v2.test.mjs is in that repo's tests too. Change both together.
 */
export function canonicalQuery(params: URLSearchParams): string {
  const pairs = [...params.entries()].sort(([ak, av], [bk, bv]) =>
    ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0,
  );
  return new URLSearchParams(pairs).toString();
}

export function signServiceHeaderV2(
  secret: string,
  path: string,
  params: URLSearchParams,
  bearer: string,
  ts: string,
): string {
  const tokenHash = crypto.createHash("sha256").update(bearer).digest("hex");
  const payload = ["v2", ts, path, canonicalQuery(params), tokenHash].join("\n");
  return `${ts}.${crypto.createHmac("sha256", secret).update(payload).digest("hex")}`;
}
