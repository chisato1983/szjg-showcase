const SECRET = process.env.AUTH_SECRET || 'fallback-dev-secret-change-me';

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function base64UrlFromBytes(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verify(token) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) return null;

    const encoder = new TextEncoder();
    const keyData = encoder.encode(SECRET);
    const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

    const sigBytes = Uint8Array.from(base64UrlDecode(sigB64), c => c.charCodeAt(0));
    const data = encoder.encode(`${headerB64}.${payloadB64}`);

    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;

    const payload = JSON.parse(base64UrlDecode(payloadB64));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const path = url.pathname;

  const isProtected = /^\/(gdp|dashboard|fire-event-detail|fire-cockpit|fire-control-room|yuzhong-risks|fire-water)(\/|$)/.test(path);
  if (!isProtected) return;

  const cookieHeader = req.headers.get('cookie');
  const match = cookieHeader ? cookieHeader.match(/(?:^|; )auth_token=([^;]*)/) : null;
  const token = match ? match[1] : null;

  if (!token || !(await verify(token))) {
    const redirect = encodeURIComponent(path + url.search);
    return Response.redirect(new URL(`/login.html?redirect=${redirect}`, req.url), 302);
  }
}

export const config = {
  matcher: ['/((?!api|login\\.html|_next|favicon|assets|.*\\.svg|.*\\.png|.*\\.jpg).*)'],
};
