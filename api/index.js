import express from "express";
import * as http from "node:http";
import * as https from "node:https";

const app = express();

// 让 body 保持原始二进制
app.use(express.raw({ type: "*/*", limit: "10mb" }));

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "access-control-allow-headers": "content-type, authorization, x-requested-with, accept, cache-control, pragma",
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

app.all("/", (req, res) => {
  // 预检请求
  if (req.method === "OPTIONS") {
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);
    res.status(204).end();
    return;
  }

  let targetUrl;
  try {
    targetUrl = parseTargetUrl(req);
  } catch (e) {
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);
    res.status(400).send("Invalid or missing ?url= parameter");
    return;
  }

  const isCaptcha =
    targetUrl.pathname.toLowerCase().includes("verifycode.servlet");

  const headers = buildForwardHeaders(req, targetUrl, isCaptcha);
  const options = {
    method: req.method,
    headers,
  };

  const proxyReq = requestByProtocol(targetUrl, options, (proxyRes) => {
    // 状态码
    res.status(proxyRes.statusCode || 502);

    // 回传上游头（过滤掉不该回传的）
    for (const [name, value] of Object.entries(proxyRes.headers)) {
      const lower = name.toLowerCase();

      if (HOP_BY_HOP_RES_HEADERS.has(lower)) continue;
      if (
        lower === "content-security-policy" ||
        lower === "content-security-policy-report-only" ||
        lower === "cross-origin-resource-policy" ||
        lower === "reporting-endpoints" ||
        lower === "report-to"
      ) {
        continue;
      }

      if (value !== undefined) {
        res.setHeader(name, value);
      }
    }

    // CORS 头覆盖
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);

    // 验证码禁止缓存，避免拿到旧图
    if (isCaptcha) {
      res.setHeader("cache-control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("pragma", "no-cache");
      res.setHeader("expires", "0");
    }

    proxyRes.on("error", (err) => res.destroy(err));
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    if (!res.headersSent) {
      for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);
      res.status(502).json({ error: "Proxy error", details: err.message });
    } else {
      res.destroy(err);
    }
  });

  // 仅非 GET/HEAD 透传 body
  const hasBody =
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body &&
    req.body.length > 0;

  if (hasBody) {
    proxyReq.write(req.body);
  }

  proxyReq.end();
});

function requestByProtocol(urlObj, options, callback) {
  const mod = urlObj.protocol === "https:" ? https : http;
  return mod.request(urlObj, options, callback);
}

function parseTargetUrl(req) {
  // Vercel/Express 下，req.originalUrl 通常包含完整查询串
  const u = new URL(req.originalUrl || req.url, "http://localhost");
  const raw = u.searchParams.get("url");
  if (!raw) throw new Error("missing url");

  const decoded = decodeURIComponent(raw);
  const target = new URL(decoded);

  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new Error("only http/https allowed");
  }

  return target;
}

function buildForwardHeaders(req, targetUrl, isCaptcha) {
  const out = {};

  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;

    const lower = name.toLowerCase();

    // Vercel 注入头和 hop-by-hop 头不要转发
    if (lower.startsWith("x-vercel-")) continue;
    if (HOP_BY_HOP_REQ_HEADERS.has(lower)) continue;

    // 这两个最容易触发上游拦截
    if (lower === "origin") continue;

    // 如果你确认上游需要 referer，可保留；不需要可删除
    out[name] = value;
  }

  // Host 必须是目标站点
  out.host = targetUrl.host;

  // 避免压缩编码导致某些代理链路出现异常
  out["accept-encoding"] = "identity";

  // 验证码请求强化“拿新图”
  if (isCaptcha) {
    out.accept = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8";
    out["cache-control"] = "no-cache";
    out.pragma = "no-cache";
  }

  // UA 太空时补一个
  if (!out["user-agent"] && !out["User-Agent"]) {
    out["user-agent"] =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
  }

  return out;
}

export default app;
