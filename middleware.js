const crypto = require('crypto');

const AUTH_SECRET = process.env.AUTH_SECRET || 'fallback-dev-secret-change-me';

function verify(token) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split('.');
    const sig = crypto.createHmac('sha256', AUTH_SECRET).update(`${headerB64}.${payloadB64}`).digest('base64url');
    if (sig !== sigB64) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? match[1] : null;
}

module.exports = function middleware(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  const isProtected = /^\/(gdp|dashboard)(\/|$)/.test(path);

  if (!isProtected) return;

  const token = getCookie(req.headers.get('cookie'), 'auth_token');
  if (!token || !verify(token)) {
    const redirect = encodeURIComponent(path + url.search);
    return Response.redirect(new URL(`/login.html?redirect=${redirect}`, req.url), 302);
  }
};

export const config = {
  matcher: ['/((?!api|login\\.html|_next|favicon|assets|.*\\.svg|.*\\.png|.*\\.jpg).*)'],
};
