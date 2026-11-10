// Shared helpers for the WebFilter Proxy extension (SPEC_EXT_OPS O9).
// Loaded by the background worker (importScripts / manifest `scripts`) and by the popup and options pages.
// Talks only to the loopback admin API, with GET requests and a read-only token.
"use strict";

const api = globalThis.browser ?? globalThis.chrome;

/** The only hosts the extension will ever talk to or proxy through. */
const LOOPBACK_HOSTS = Object.freeze(["127.0.0.1", "localhost", "[::1]"]);
const DEFAULT_PROXY = "127.0.0.1:8080";
const API_TIMEOUT_MS = 5000;
const MAX_INPUT = 200;
const MAX_TOKEN = 512;

class ApiError extends Error {
  /** kind: "not_configured" | "unreachable" | "auth" | "http" | "bad_response" */
  constructor(kind, message) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
  }
}

function parsePort(s) {
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n >= 1 && n <= 65535 ? n : null;
}

/**
 * Validate the admin URL: http only, loopback host from the allowlist, explicit port 1-65535,
 * no credentials, no path beyond "/", no query or fragment. Returns the normalized origin or throws.
 */
function validateAdminUrl(s) {
  const raw = String(s ?? "").trim();
  if (raw.length === 0 || raw.length > MAX_INPUT) throw new Error("Admin URL is required (max 200 characters).");
  // Structure first: scheme, host, explicit port, optional trailing "/". Nothing else.
  const m = /^http:\/\/([^/?#@\s]+):(\d{1,5})\/?$/i.exec(raw);
  if (!m) throw new Error("Admin URL must look like http://127.0.0.1:9090 (http, loopback host, explicit port, no path).");
  const port = parsePort(m[2]);
  if (port === null) throw new Error("Admin URL port must be between 1 and 65535.");
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Admin URL is not a valid URL.");
  }
  if (u.protocol !== "http:") throw new Error("Admin URL scheme must be http.");
  if (!LOOPBACK_HOSTS.includes(u.hostname)) throw new Error("Admin URL host must be 127.0.0.1, localhost or [::1].");
  if (u.username !== "" || u.password !== "") throw new Error("Admin URL must not contain credentials.");
  if (u.pathname !== "/" || u.search !== "" || u.hash !== "") throw new Error("Admin URL must not have a path, query or fragment.");
  // URL.origin drops the default port 80; keep the port explicit.
  return u.port === "" ? `${u.origin}:${port}` : u.origin;
}

/** Validate a proxy "host:port" (loopback host only). Empty means the default. Returns {host, port, text} or throws. */
function validateProxy(s) {
  const raw = String(s ?? "").trim() || DEFAULT_PROXY;
  if (raw.length > MAX_INPUT) throw new Error("Proxy must be host:port.");
  const m = /^(\[::1\]|[A-Za-z0-9.]+):(\d{1,5})$/.exec(raw);
  if (!m) throw new Error("Proxy must be host:port, for example 127.0.0.1:8080.");
  const host = m[1].toLowerCase();
  if (!LOOPBACK_HOSTS.includes(host)) throw new Error("Proxy host must be 127.0.0.1, localhost or [::1].");
  const port = parsePort(m[2]);
  if (port === null) throw new Error("Proxy port must be between 1 and 65535.");
  return { host, port, text: `${host}:${port}` };
}

/** Validate the token shape (never logged, never shown). */
function validateToken(s) {
  const t = String(s ?? "").trim();
  if (t.length === 0 || t.length > MAX_TOKEN || /[\s\u0000-\u001f\u007f]/.test(t)) {
    throw new Error("Token must be 1-512 printable characters without spaces.");
  }
  return t;
}

/** Return the URL string only if it parses with an http or https scheme, else null. */
function safeHttpUrl(s) {
  if (typeof s !== "string" || s.length === 0 || s.length > 8192) return null;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

async function storageGet(keys) {
  return (await api.storage.local.get(keys)) ?? {};
}

async function storageSet(items) {
  await api.storage.local.set(items);
}

/** Session storage when available (survives worker restarts, cleared with the browser), else null. */
function sessionArea() {
  return api.storage && api.storage.session ? api.storage.session : null;
}

/**
 * GET `${origin}/api/v1/${path}` with the read-only Bearer token. This is the only network call the
 * extension makes, and it is GET only.
 */
async function apiGet(path) {
  if (typeof path !== "string" || !/^[a-z0-9/_-]+(\?[A-Za-z0-9_=&-]*)?$/.test(path)) {
    throw new ApiError("bad_response", "invalid API path");
  }
  const cfg = await storageGet(["adminUrl", "token"]);
  if (!cfg.adminUrl || !cfg.token) throw new ApiError("not_configured", "Extension is not configured.");
  let origin;
  try {
    origin = validateAdminUrl(cfg.adminUrl);
  } catch {
    throw new ApiError("not_configured", "Stored admin URL is invalid.");
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), API_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(`${origin}/api/v1/${path}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${cfg.token}`, Accept: "application/json" },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: ctl.signal,
    });
  } catch {
    throw new ApiError("unreachable", "Admin API unreachable.");
  } finally {
    clearTimeout(timer);
  }
  if (resp.status === 401 || resp.status === 403) throw new ApiError("auth", "Token refused by the admin API.");
  if (!resp.ok) throw new ApiError("http", `Admin API answered HTTP ${resp.status}.`);
  try {
    return await resp.json();
  } catch {
    throw new ApiError("bad_response", "Admin API sent invalid JSON.");
  }
}

/** Non-negative integer from untrusted JSON, else 0. */
function toCount(v) {
  return Number.isSafeInteger(v) && v >= 0 ? v : 0;
}
