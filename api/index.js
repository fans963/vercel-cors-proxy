import express from "express";
import * as http from "node:http";
import * as https from "node:https";

const app = express();
app.use(express.json({ limit: "1mb" }));

const DEFAULT_CORS_ALLOW_HEADERS = "content-type, authorization, accept";
const CORS_ALLOW_ORIGINS = (process.env.CORS_ALLOW_ORIGINS || "*")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const DEFAULT_LOGIN_BASE_URL = "http://202.119.81.112:8080";
const DEFAULT_TARGET_URL =
  "http://202.119.81.112:9080/njlgdx/xskb/xskb_list.do?Ves632DSdyV=NEW_XSD_PYGL";

const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 12000);

function getAllowedOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) {
    return "*";
  }
  if (CORS_ALLOW_ORIGINS.includes("*")) {
    return "*";
  }
  return CORS_ALLOW_ORIGINS.includes(origin) ? origin : "null";
}

function setCorsHeaders(res, req = null) {
  const allowOrigin = req ? getAllowedOrigin(req) : "*";
  const requestHeaders = req?.headers["access-control-request-headers"];

  res.setHeader("Access-Control-Allow-Origin", allowOrigin);
  res.setHeader("Vary", "Origin, Access-Control-Request-Headers");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    requestHeaders || DEFAULT_CORS_ALLOW_HEADERS,
  );
  res.setHeader("Access-Control-Max-Age", "86400");
}

function sendJson(res, req, status, payload) {
  setCorsHeaders(res, req);
  res.status(status).json(payload);
}

app.use((req, res, next) => {
  setCorsHeaders(res, req);
  if (req.method === "OPTIONS") {
    res.setHeader("Content-Length", "0");
    res.status(204).end();
    return;
  }
  next();
});

app.get("/", (req, res) => {
  res.json({ ok: true, service: "schedule-fetcher", endpoints: ["/api/session/start", "/api/session/submit"] });
});

app.post("/api/session/start", async (req, res) => {
  const loginBaseUrl = req.body?.loginBaseUrl || DEFAULT_LOGIN_BASE_URL;
  let loginBase;
  try {
    loginBase = new URL(loginBaseUrl);
    validateTarget(loginBase);
  } catch (e) {
    sendJson(res, req, 400, { error: "invalid loginBaseUrl", details: String(e) });
    return;
  }

  const session = { jsession8080: "", jsession9080: "" };
  const logs = [];

  try {
    const homeUrl = new URL("/", loginBase);
    const homeRes = await upstreamRequest(homeUrl, {
      method: "GET",
      session,
      referer: `${loginBase.origin}/`,
    });
    updateSessionFromSetCookie(session, homeUrl, homeRes.headers["set-cookie"]);
    logs.push(
      `[START] GET / status=${homeRes.statusCode} url=${homeUrl.toString()} contentType=${
        homeRes.headers["content-type"] || ""
      }`,
    );

    const captchaUrl = new URL(
      `/verifycode.servlet?t=${Date.now()}`,
      loginBase,
    );
    const captchaRes = await upstreamRequest(captchaUrl, {
      method: "GET",
      session,
      referer: `${loginBase.origin}/`,
      isCaptcha: true,
    });
    updateSessionFromSetCookie(
      session,
      captchaUrl,
      captchaRes.headers["set-cookie"],
    );

    logs.push(
      `[START] GET verifycode status=${captchaRes.statusCode} bytes=${captchaRes.body.length} url=${captchaUrl.toString()} contentType=${
        captchaRes.headers["content-type"] || ""
      } session8080=${mask(session.jsession8080)}`,
    );

    sendJson(res, req, 200, {
      session,
      captchaBase64: captchaRes.body.toString("base64"),
      captchaContentType: captchaRes.headers["content-type"] || "",
      networkLogs: logs,
    });
  } catch (e) {
    sendJson(res, req, 502, {
      error: "start_failed",
      details: String(e),
      networkLogs: logs,
    });
  }
});

app.post("/api/session/submit", async (req, res) => {
  const loginBaseUrl = req.body?.loginBaseUrl || DEFAULT_LOGIN_BASE_URL;
  const targetUrl = req.body?.targetUrl || DEFAULT_TARGET_URL;
  const username = req.body?.username || "";
  const password = req.body?.password || "";
  const verifyCode = req.body?.verifyCode || "";

  if (!username || !password || !verifyCode) {
    sendJson(res, req, 400, { error: "username/password/verifyCode required" });
    return;
  }

  const session = normalizeSession(req.body?.session);
  const logs = [];

  let loginBase;
  let target;
  try {
    loginBase = new URL(loginBaseUrl);
    target = new URL(targetUrl);
    validateTarget(loginBase);
    validateTarget(target);
  } catch (e) {
    sendJson(res, req, 400, { error: "invalid url", details: String(e) });
    return;
  }

  try {
    const logonUrl = new URL("/Logon.do?method=logon", loginBase);
    const form = new URLSearchParams({
      USERNAME: username,
      PASSWORD: password,
      useDogCode: "",
      RANDOMCODE: verifyCode,
    }).toString();

    let postRes = await upstreamRequest(logonUrl, {
      method: "POST",
      session,
      referer: `${loginBase.origin}/`,
      contentType: "application/x-www-form-urlencoded",
      body: Buffer.from(form, "utf8"),
    });
    updateSessionFromSetCookie(session, logonUrl, postRes.headers["set-cookie"]);

    logs.push(
      `[SUBMIT] POST logon status=${postRes.statusCode} url=${logonUrl.toString()} session8080=${mask(
        session.jsession8080,
      )} session9080=${mask(session.jsession9080)}`,
    );

    let currentUrl = logonUrl;
    let redirects = 0;
    while (isRedirectStatus(postRes.statusCode) && redirects < 5) {
      const location = postRes.headers.location;
      if (!location) {
        break;
      }

      const nextUrl = new URL(location, currentUrl);
      validateTarget(nextUrl);
      logs.push(
        `[SUBMIT] redirect status=${postRes.statusCode} from=${currentUrl.toString()} to=${nextUrl.toString()}`,
      );

      postRes = await upstreamRequest(nextUrl, {
        method: "GET",
        session,
        referer: `${loginBase.origin}/`,
      });
      updateSessionFromSetCookie(session, nextUrl, postRes.headers["set-cookie"]);
      currentUrl = nextUrl;
      redirects += 1;
    }

    const targetRes = await upstreamRequest(target, {
      method: "GET",
      session,
      referer: "http://202.119.81.112:9080/njlgdx/xk/LoginToXk?method=jwxt",
    });

    logs.push(
      `[SUBMIT] GET target status=${targetRes.statusCode} url=${target.toString()} cookie=${buildSessionCookieHeader(
        session,
        target,
      )}`,
    );

    sendJson(res, req, 200, {
      html: decodeBody(targetRes.body, targetRes.headers["content-type"]),
      networkLogs: logs,
      session,
      statusCode: targetRes.statusCode,
      targetContentType: targetRes.headers["content-type"] || "",
    });
  } catch (e) {
    sendJson(res, req, 502, {
      error: "submit_failed",
      details: String(e),
      networkLogs: logs,
      session,
    });
  }
});

function normalizeSession(raw) {
  return {
    jsession8080: String(raw?.jsession8080 || ""),
    jsession9080: String(raw?.jsession9080 || ""),
  };
}

function validateTarget(targetUrl) {
  if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
    throw new Error("only http/https allowed");
  }
  if (targetUrl.hostname !== "202.119.81.112") {
    throw new Error("host not allowed");
  }
  if (targetUrl.port !== "8080" && targetUrl.port !== "9080") {
    throw new Error("port not allowed");
  }
}

function requestByProtocol(urlObj, options, callback) {
  const mod = urlObj.protocol === "https:" ? https : http;
  return mod.request(urlObj, options, callback);
}

function buildSessionCookieHeader(session, targetUrl) {
  const cookie = targetUrl.port === "8080"
    ? session.jsession8080
    : targetUrl.port === "9080"
      ? session.jsession9080
      : "";
  return cookie ? `JSESSIONID=${cookie}` : "";
}

function buildForwardHeaders({ targetUrl, session, referer, isCaptcha, contentType }) {
  const headers = {
    Accept: "*/*",
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    Host: targetUrl.host,
    "Accept-Encoding": "identity",
  };

  const cookie = buildSessionCookieHeader(session, targetUrl);
  if (cookie) {
    headers.Cookie = cookie;
  }

  if (referer) {
    headers.Referer = referer;
  }

  if (contentType) {
    headers["Content-Type"] = contentType;
  }

  if (isCaptcha) {
    headers.Accept = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8";
    headers["Cache-Control"] = "no-cache";
    headers.Pragma = "no-cache";
  }

  return headers;
}

function upstreamRequest(
  url,
  { method = "GET", session = { jsession8080: "", jsession9080: "" }, referer = "", isCaptcha = false, contentType = "", body = null } = {},
) {
  const headers = buildForwardHeaders({
    targetUrl: url,
    session,
    referer,
    isCaptcha,
    contentType,
  });

  return new Promise((resolve, reject) => {
    const req = requestByProtocol(url, { method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
      res.on("error", reject);
    });

    req.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
      req.destroy(new Error(`upstream_timeout_${UPSTREAM_TIMEOUT_MS}ms`));
    });

    req.on("error", reject);
    if (body && body.length > 0) {
      req.write(body);
    }
    req.end();
  });
}

function updateSessionFromSetCookie(session, targetUrl, rawSetCookie) {
  if (!rawSetCookie) return;

  const setCookieList = Array.isArray(rawSetCookie)
    ? rawSetCookie
    : [String(rawSetCookie)];

  const jsession = extractJsessionId(setCookieList);
  if (!jsession) return;

  if (targetUrl.port === "8080") {
    session.jsession8080 = jsession;
  } else if (targetUrl.port === "9080") {
    session.jsession9080 = jsession;
  }
}

function extractJsessionId(setCookieList) {
  for (const item of setCookieList) {
    const m = String(item).match(/(?:^|\s|;)JSESSIONID=([^;]+)/i);
    if (m && m[1]) {
      return m[1].trim();
    }
  }
  return "";
}

function isRedirectStatus(code) {
  return code === 301 || code === 302 || code === 303 || code === 307 || code === 308;
}

function decodeBody(buffer, contentType = "") {
  const lowered = String(contentType).toLowerCase();
  if (lowered.includes("charset=utf-8")) {
    return buffer.toString("utf8");
  }
  return buffer.toString("latin1");
}

function mask(value) {
  if (!value) return "<empty>";
  if (value.length <= 8) return "***";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

app.use((err, req, res, _next) => {
  sendJson(res, req, 500, {
    error: "internal_error",
    details: String(err),
  });
});

export default app;
