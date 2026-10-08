// Token helpers for the tests. Tokens are built by hand with node:crypto,
// synchronously, so the tests do not verify jose with jose: an independent
// encoder has to agree with the server's decoder. Keys are generated per run;
// no key is committed.
import crypto from "node:crypto";

export const ISSUER = "https://app.test";
export const AUDIENCE = "https://mcp.test";

export function keyPair() {
  return crypto.generateKeyPairSync("ed25519");
}

/** The one key pair most tests use: the web app's, as far as they know. */
export const APP_KEYS = keyPair();

/** MCP_JWT_PUBLIC_KEY as S would write it: base64 of the SPKI DER. */
export function publicKeyEnv(publicKey = APP_KEYS.publicKey) {
  return publicKey.export({ format: "der", type: "spki" }).toString("base64");
}

const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

/** Claims the web app puts in every access token, with `over` on top. `sub`
 *  null leaves the subject out. */
export function claims(sub, over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    scope: "mcp:read",
    plan: "free",
    ...(sub == null ? {} : { sub: String(sub) }),
    iss: ISSUER,
    aud: AUDIENCE,
    iat: now,
    exp: now + 600,
    ...over,
  };
}

export function signEdDSA(payload, privateKey = APP_KEYS.privateKey, header = {}) {
  const input = `${b64u({ alg: "EdDSA", typ: "JWT", ...header })}.${b64u(payload)}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), privateKey).toString("base64url")}`;
}

export function signHS256(payload, secret) {
  const input = `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u(payload)}`;
  return `${input}.${crypto.createHmac("sha256", secret).update(input).digest("base64url")}`;
}

export function unsigned(payload) {
  return `${b64u({ alg: "none", typ: "JWT" })}.${b64u(payload)}.`;
}
