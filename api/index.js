import express from 'express';
import * as http from "node:http";
import * as https from "node:https";

const app = express();
app.use(express.json()); // support json bodies for APIs
app.use(express.raw({ type: '*/*', limit: '1mb' })); // ensure body is a buffer for proxy

// Global CORS Middleware
app.use((req, res, next) => {
    const origin = req.headers.origin || '*';
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('access-control-allow-credentials', 'true');
    res.setHeader('access-control-allow-methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('access-control-allow-headers', req.headers['access-control-request-headers'] || '*');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// --- Server-Side Orchestration APIs ---

const PORTAL_ROOT = "http://202.119.81.112:8080";
const DATA_ROOT = "http://202.119.81.112:9080/njlgdx";

// Helper for server-side requests
async function internalRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const mod = u.protocol === 'https:' ? https : http;
        const req = mod.request(u, options, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: Buffer.concat(chunks)
                });
            });
        });
        req.on('error', reject);
        if (options.body) req.write(options.body);
        req.end();
    });
}

// 1. Captcha API: Fetches captcha and the initial JSESSIONID
app.get('/api/captcha', async (req, res) => {
    try {
        console.log(`[API] Fetching Captcha from ${PORTAL_ROOT}`);
        // Init session
        const init = await internalRequest(`${PORTAL_ROOT}/Logon.do?method=logonurl`);
        const sessionCookie = init.headers['set-cookie'] ? init.headers['set-cookie'][0].split(';')[0] : '';

        // Get captcha
        const captcha = await internalRequest(`${PORTAL_ROOT}/verifycode.servlet`, {
            headers: { 'Cookie': sessionCookie }
        });

        res.json({
            image: captcha.body.toString('base64'),
            cookie: sessionCookie
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Timetable API: Handles full Login -> Fetch flow on the server
app.post('/api/timetable', async (req, res) => {
    try {
        const { username, password, captcha, cookie } = req.body;
        console.log(`[API] Orchestrating login for ${username}`);

        // Step 1: Login POST
        const body = new URLSearchParams({
            USERNAME: username,
            PASSWORD: password,
            useDogCode: '',
            RANDOMCODE: captcha,
            encoded: ''
        }).toString();

        const login = await internalRequest(`${PORTAL_ROOT}/Logon.do?method=logon`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': cookie,
                'Referer': `${PORTAL_ROOT}/Logon.do?method=logonurl`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            body: body
        });

        console.log(`[API] Login Response Status: ${login.statusCode}`);
        
        // Handle Session Upgrade: If login returns a new cookie, we MUST use it
        let activeCookie = cookie;
        if (login.headers['set-cookie']) {
            activeCookie = login.headers['set-cookie'][0].split(';')[0];
            console.log(`[API] Session Upgraded: ${activeCookie}`);
        }

        // Step 2: Fetch Data from 9080
        const fetchUrl = `${DATA_ROOT}/xskb/xskb_list.do?Ves632DSdyV=NEW_XSD_PYGL`;
        console.log(`[API] Fetching Timetable from ${fetchUrl}`);
        const timetable = await internalRequest(fetchUrl, {
            headers: {
                'Cookie': activeCookie,
                'Referer': `${PORTAL_ROOT}/Logon.do?method=logon`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        console.log(`[API] Timetable Fetch Status: ${timetable.statusCode} (${timetable.body.length} bytes)`);
        
        if (timetable.statusCode !== 200 && timetable.statusCode !== 302) {
             console.error(`[API] Unexpected response body: ${timetable.body.toString('utf8').substring(0, 200)}`);
        }

        res.send(timetable.body);
    } catch (err) {
        console.error(`[API] Error during orchestration:`, err);
        res.status(500).json({ error: err.message });
    }
});

// --- Legacy Proxy Mode ---
app.all('/', async (req, res) => {
    const targetParams = parseTargetParameters(req);
    if (!targetParams.url) {
        res.status(400).send("query parameter 'url' is required");
        return;
    }

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const targetReqUrl = targetParams.url;
    const targetReqHandler = (targetRes) => {
        console.log(`[Proxy] Response Status from Backend: ${targetRes.statusCode}`);
        console.log(`[Proxy] Response Headers:`, targetRes.headers);
        res.status(targetRes.statusCode)

        const headersMap = new Map(Object.entries(targetRes.headersDistinct));
        
        // Rewrite Set-Cookie to remove Path/Domain restrictions
        const setCookieHeaders = targetRes.headersDistinct['set-cookie'];
        if (setCookieHeaders && setCookieHeaders.length > 0) {
            console.log(`[Proxy] Outgoing Set-Cookie from Backend:`, setCookieHeaders);
            const portSuffix = targetReqUrl.port ? `_${targetReqUrl.port}` : '';
            const rewrittenCookies = setCookieHeaders.map(cookie => {
                let rewritten = cookie
                    .replace(/Path=[^;]+/i, 'Path=/')
                    .replace(/Domain=[^;]+/i, '')
                    .replace(/SameSite=[^;]+/i, '')
                    .replace(/Secure/i, '')
                    .replace(/;?\s*$/, ''); // Remove trailing semicolon/whitespace
                
                // Isolation: Rename JSESSIONID to include port if present
                if (portSuffix) {
                    rewritten = rewritten.replace(/JSESSIONID=/i, `JSESSIONID${portSuffix}=`);
                }
                
                return rewritten + '; SameSite=None; Secure';
            });
            headersMap.set('set-cookie', rewrittenCookies);
        }

        // Set headers on the client response
        for (const [name, value] of headersMap) {
            res.setHeader(name, value);
        }
        // set CORS headers - Cleaned (handled by middleware)
        
        // remove CORP headers
        res.removeHeader('cross-origin-resource-policy');
        res.removeHeader('content-security-policy');
        res.removeHeader('content-security-policy-report-only');
        res.removeHeader('reporting-endpoints');
        res.removeHeader('report-to');

        targetRes.on('data', (chunk) => res.write(chunk));
        targetRes.on('end', () => res.end());
        targetRes.on('error', (err) => res.destroy(err));

        // rewrite redirect location
        if ([301, 302, 307, 308].includes(targetRes.statusCode)) {
            const location = targetRes.headers.location;
            if (location) {
                try {
                    const absoluteLocation = new URL(location, targetReqUrl).href;
                    const proxyProtocol = req.headers['x-forwarded-proto'] || 'https';
                    const proxyHost = req.headers.host;
                    res.setHeader('location', `${proxyProtocol}://${proxyHost}/?url=${encodeURIComponent(absoluteLocation)}`);
                } catch (e) {
                    // fall back if URL parsing fails
                }
            }
        }
    };
    console.log(`[Proxy] Incoming Request: ${req.method} ${targetReqUrl.href}`);
    console.log(`[Proxy] Incoming Headers:`, req.headers);
    if (req.body && req.body.length > 0) {
        console.log(`[Proxy] Incoming Body Size: ${req.body.length} bytes`);
        console.log(`[Proxy] Incoming Body Preview: ${req.body.toString('utf8').substring(0, 100)}`);
    }

    const targetReq = request(targetReqUrl, { method: req.method }, targetReqHandler);
    
    // Copy headers from the client request
    const headers = new Map();
    for (const [name, values] of Object.entries(req.headersDistinct)) {
        if (name.startsWith('x-vercel-') || name === 'host') continue;
        
        // Join multi-value headers with semicolon for cookies, or comma for others
        if (name === 'cookie') {
            const portSuffix = targetReqUrl.port ? `_${targetReqUrl.port}` : '';
            let joinedCookies = values.join('; ');
            
            // Isolation: Restore JSESSIONID from port-suffixed version
            if (portSuffix && joinedCookies.includes(`JSESSIONID${portSuffix}`)) {
                const regex = new RegExp(`JSESSIONID${portSuffix}=([^;]+)`, 'i');
                const match = joinedCookies.match(regex);
                if (match) {
                    joinedCookies = `JSESSIONID=${match[1]}; ${joinedCookies}`;
                }
            }
            
            console.log(`[Proxy] Forwarding Cookies to Port ${targetReqUrl.port || '80'}:`, joinedCookies);
            headers.set(name, joinedCookies);
        } else {
            headers.set(name, values.join(', '));
        }
    }
    
    // Spoofing: Host and Origin MUST match the backend to avoid security blocks
    headers.set('host', targetReqUrl.host);
    headers.set('origin', targetReqUrl.origin);

    // Referer Injection: If client sent X-Alt-Referer, use it as the real Referer for the target
    const altReferer = headers.get('x-alt-referer');
    if (altReferer) {
        headers.set('referer', altReferer);
        headers.delete('x-alt-referer');
    }
    
    // Set headers on the target request
    for (const [name, value] of headers) {
        targetReq.setHeader(name, value);
    }
    if (req.body && req.body?.length > 0) {
        targetReq.write(req.body);
    }
    targetReq.on('error', (err) => {
        res.status(500).json({ error: "Proxy error", details: err.message });
    });
    targetReq.end();
});

function request(url, options = {}, callback) {
    const httpModule = url.protocol === 'https:' ? https : http;
    return httpModule.request(url, options, callback);
}

function parseTargetParameters(proxyRequest) {
    const params = {}
    // url - treat everything right to url= query parameter as target url value
    const urlMatch = proxyRequest.url.match(/(?<=[?&])url=(?<url>.*)$/);
    if (urlMatch) {
        params.url = new URL(decodeURIComponent(urlMatch.groups.url));
    }

    return params;
}

export default app;
