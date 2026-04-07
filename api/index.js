export const config = { runtime: 'edge' };

export default async function handler(req: Request) {
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  const url = new URL(req.url);
  let target = url.searchParams.get('url');

  if (!target) {
    return new Response('Missing ?url= parameter', { status: 400 });
  }

  // 支持裸 IP
  if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?/.test(target) && !target.startsWith('http')) {
    target = 'http://' + target;
  }

  try {
    const targetUrl = new URL(target);

    const newReq = new Request(targetUrl, {
      method: req.method,
      headers: {
        ...Object.fromEntries(req.headers),
        'Host': targetUrl.host,
        'Referer': targetUrl.origin,   // 重要：添加 Referer
        'User-Agent': req.headers.get('user-agent') || 'Mozilla/5.0',
      },
      body: req.body,
      redirect: 'manual',   // 重要：手动处理 302，避免自动跳转
    });

    const response = await fetch(newReq);

    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    headers.set('Access-Control-Allow-Headers', '*');

    // 保留原始 Content-Type（图片必须正确）
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });

  } catch (err: any) {
    return new Response(`Proxy Error: ${err.message}`, { 
      status: 502,
      headers: { 'Access-Control-Allow-Origin': '*' }
    });
  }
}
