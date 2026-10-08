import { createApp } from "./app.js";
import { ConfigError, loadConfig, type Config } from "./config.js";
import { log } from "./log.js";
import { MAX_WINDOW_MS } from "./auth.js";

// A rejection nobody awaited is logged, and the process carries on: the
// request it belonged to already got its answer (or its error handler). An
// exception nobody caught leaves the process in an unknown state, so it is
// logged and the process exits; `restart: unless-stopped` brings it back
// clean, and clients re-initialize.
process.on("unhandledRejection", (reason) => {
  log("error", "unhandled_rejection", {
    message: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});
process.on("uncaughtException", (err) => {
  log("error", "uncaught_exception", { message: err.message, stack: err.stack });
  process.exit(1);
});

let config: Config;
try {
  config = loadConfig();
} catch (err) {
  // Names of the missing or bad variables only, never a value.
  log("error", "config_invalid", { problems: err instanceof ConfigError ? err.problems : [String(err)] });
  process.exit(1);
}

const { app } = createApp(config);

// Bind 0.0.0.0 INSIDE the container so Docker port-forwarding and the
// cloudflared tunnel (which reach it via the container network interface) can
// connect. Host exposure stays loopback-only via the compose port mapping
// "127.0.0.1:3459:3459".
app.listen(config.port, "0.0.0.0", () => {
  const legacy = config.legacyHs256;
  log("info", "listening", {
    port: config.port,
    nodeEnv: process.env.NODE_ENV ?? "unset",
    limits: config.limits,
    // When old HS256 tokens stop being accepted; null = they are not.
    hs256Until: legacy ? new Date(legacy.until).toISOString() : null,
  });
  if (legacy && legacy.until - Date.now() > MAX_WINDOW_MS) {
    log("warn", "hs256_window_ignored", { reason: "MCP_LEGACY_AUTH_UNTIL is more than 7 days ahead" });
  }
});
