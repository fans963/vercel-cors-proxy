import express from "express";
import * as http from "node:http";
import * as https from "node:https";

const app = express();
app.use(express.raw({ type: "*/*", limit: "10mb" }));

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, x-requested-with, accept, cache-control, pragma",
  "access-control-max-age": "86400",
  "access-control-expose-headers": "*",
};

const HOP_BY_HOP_REQ_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "content-length",
]);

const HOP_BY_HOP_RES_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

const PROXY_COOKIE_8080 = "upstream_jsessionid_8080";
const PROXY_COOKIE_9080 = "upstream_jsessionid_9080";

app.all("/", (req, res) => {
  if (req.method === "OPTIONS") {
    setCorsHeaders(res);
    res.status(204).end();
    return;
  }

  let targetUrl;
  try {
    targetUrl = parseTargetUrl(req);
    validateTarget(targetUrl);
  } catch {
    setCorsHeaders(res);
    res.status(400).send("Invalid or missing ?url= parameter");
    return;
  }

  const isCaptcha = targetUrl.pathname
    .toLowerCase()
    .includes("verifycode.servlet");

  const reqHeaders = buildForwardHeaders(req, targetUrl, isCaptcha);

  const proxyReq = requestByProtocol(
    targetUrl,
    { method: req.method, headers: reqHeaders },
    (proxyRes) => {
      res.status(proxyRes.statusCode || 502);

      for (const [name, value] of Object.entries(proxyRes.headers)) {
        if (value === undefined) continue;

        const lower = name.toLowerCase();
        if (HOP_BY_HOP_RES_HEADERS.has(lower)) continue;
        if (
          lower === "set-cookie" ||
          lower === "content-security-policy" ||
          lower === "content-security-policy-report-only" ||
          lower === "cross-origin-resource-policy" ||
          lower === "reporting-endpoints" ||
          lower === "report-to"
        ) {
          continue;
        }

        res.setHeader(name, value);
      }

      setCorsHeaders(res);
      maybePersistUpstreamSession(proxyRes, targetUrl, res);

      if (isCaptcha) {
        res.setHeader(
          "cache-control",
          "no-store, no-cache, must-revalidate, proxy-revalidate",
        );
        res.setHeader("pragma", "no-cache");
        res.setHeader("expires", "0");
      }

      proxyRes.on("error", (err) => res.destroy(err));
      proxyRes.pipe(res);
    },
  );

  proxyReq.on("error", (err) => {
    if (!res.headersSent) {
      setCorsHeaders(res);
      res.status(502).json({ error: "Proxy error", details: err.message });
      return;
    }
    res.destroy(err);
  });

  if (
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body &&
    req.body.length > 0
  ) {
    proxyReq.write(req.body);
  }

  proxyReq.end();
});

function setCorsHeaders(res) {
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    res.setHeader(k, v);
  }
}

function requestByProtocol(urlObj, options, callback) {
  const mod = urlObj.protocol === "https:" ? https : http;
  return mod.request(urlObj, options, callback);
}

function parseTargetUrl(req) {
  const u = new URL(req.originalUrl || req.url, "http://localhost");
  const raw = u.searchParams.get("url");
  if (!raw) throw new Error("missing");

  try {
    return new URL(raw);
  } catch {
    return new URL(decodeURIComponent(raw));
  }
}

function validateTarget(targetUrl) {
  if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
    throw new Error("only http/https");
  }

  // Lock down to school system endpoints for safety and session stability.
  if (targetUrl.hostname !== "202.119.81.112") {
    throw new Error("host not allowed");
  }
  if (targetUrl.port !== "8080" && targetUrl.port !== "9080") {
    throw new Error("port not allowed");
  }
}

function buildForwardHeaders(req, targetUrl, isCaptcha) {
  const out = {};

  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;

    const lower = name.toLowerCase();
    if (lower.startsWith("x-vercel-")) continue;
    if (HOP_BY_HOP_REQ_HEADERS.has(lower)) continue;
    if (lower === "origin" || lower === "referer" || lower === "cookie") {
      continue;
    }

    out[name] = value;
  }

  out.host = targetUrl.host;
  out["accept-encoding"] = "identity";

  const cookie = pickProxySessionCookie(req, targetUrl);
  if (cookie) {
    out.cookie = `JSESSIONID=${cookie}`;
  }

  if (isCaptcha) {
    out.accept = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8";
    out["cache-control"] = "no-cache";
    out.pragma = "no-cache";
    out.referer = "http://202.119.81.112:8080/";
  } else if (targetUrl.port === "9080") {
    out.referer = "http://202.119.81.112:9080/njlgdx/xk/LoginToXk?method=jwxt";
  }

  if (!out["user-agent"] && !out["User-Agent"]) {
    out["user-agent"] =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";
  }

  return out;
}

function pickProxySessionCookie(req, targetUrl) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  if (targetUrl.port === "8080") {
    return cookies[PROXY_COOKIE_8080] || "";
  }
  if (targetUrl.port === "9080") {
    return cookies[PROXY_COOKIE_9080] || "";
  }
  return "";
}

function parseCookieHeader(raw) {
  const out = {};
  if (!raw) return out;

  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) out[key] = val;
  }

  return out;
}

function maybePersistUpstreamSession(proxyRes, targetUrl, res) {
  const rawSetCookie = proxyRes.headers["set-cookie"];
  if (!rawSetCookie) return;

  const setCookieList = Array.isArray(rawSetCookie)
    ? rawSetCookie
    : [String(rawSetCookie)];

  const jsession = extractJsessionId(setCookieList);
  if (!jsession) return;

  const proxyCookieName =
    targetUrl.port === "8080" ? PROXY_COOKIE_8080 : PROXY_COOKIE_9080;

  // Store upstream session on proxy domain only; never expose raw upstream cookie.
  const cookieValue = `${proxyCookieName}=${jsession}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

  const existing = res.getHeader("set-cookie");
  if (!existing) {
    res.setHeader("set-cookie", [cookieValue]);
    return;
  }

  if (Array.isArray(existing)) {
    res.setHeader("set-cookie", [...existing, cookieValue]);
  } else {
    res.setHeader("set-cookie", [String(existing), cookieValue]);
  }
}

function extractJsessionId(setCookieList) {
  for (const item of setCookieList) {
    const m = item.match(/(?:^|\s|;)JSESSIONID=([^;]+)/i);
    if (m && m[1]) {
      return m[1].trim();
    }
  }
  return "";
}

export default app;
