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
        res.status(targetRes.statusCode)

        res.setHeaders(new Map(Object.entries(targetRes.headersDistinct)));
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
    const targetReq = request(targetReqUrl, {method: req.method}, targetReqHandler);
    targetReq.setHeaders(new Map(Object.entries(req.headersDistinct)
        .filter(([name]) => !name.startsWith('x-vercel-'))));
    targetReq.setHeader('host', targetReqUrl.host);
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
