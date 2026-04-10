import express from 'express';
import * as http from "node:http";
import * as https from "node:https";

const app = express();
app.use(express.raw({ type: '*/*' })); // ensure body is a buffer
app.all('/', async (req, res) => {
    const targetParams = parseTargetParameters(req);
    if (!targetParams.url) {
        res.status(400).send("query parameter 'url' is required");
        return;
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
            const rewrittenCookies = setCookieHeaders.map(cookie => {
                return cookie
                    .replace(/Path=[^;]+/i, 'Path=/')
                    .replace(/Domain=[^;]+/i, '')
                    .replace(/SameSite=[^;]+/i, '')
                    .replace(/Secure/i, '')
                    .replace(/;?\s*$/, '') // Remove trailing semicolon/whitespace
                    + '; SameSite=None; Secure';
            });
            headersMap.set('set-cookie', rewrittenCookies);
        }

        // Set headers on the client response
        for (const [name, value] of headersMap) {
            res.setHeader(name, value);
        }
        // set CORS headers
        const origin = req.headers.origin || '*';
        res.setHeader('access-control-allow-origin', origin);
        res.setHeader('access-control-allow-credentials', 'true');
        res.setHeader('access-control-allow-methods', 'GET,POST,PUT,DELETE,OPTIONS');
        res.setHeader('access-control-allow-headers', req.headers['access-control-request-headers'] || '*');
        
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
            const joinedCookies = values.join('; ');
            console.log(`[Proxy] Forwarding Cookies:`, joinedCookies);
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
