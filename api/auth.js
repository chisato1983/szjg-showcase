const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// 安全约束：不设任何默认值。环境变量缺失时由下方 handler 直接返回 503（fail-closed），
// 避免出现"环境变量丢失 → 静默回落到硬编码密码"的失效方式。
const PASSWORD_HASH = process.env.PASSWORD_HASH;
const AUTH_SECRET = process.env.AUTH_SECRET;

// ===== 登录限流 =====
// 说明：Vercel Serverless 各实例内存不共享，此计数为实例级。
// 结合 bcrypt（单次约 60-100ms）与失败递增延迟，可把单 IP 爆破速率压到每分钟个位数。
const MAX_ATTEMPTS = 5;            // 窗口内允许的失败次数
const WINDOW_MS = 15 * 60 * 1000;  // 计数窗口：15 分钟
const LOCK_MS = 15 * 60 * 1000;    // 锁定时长：15 分钟

const attempts = new Map(); // ip -> { count, firstAt, lockedUntil }

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function prune(now) {
  if (attempts.size < 500) return;
  for (const [key, rec] of attempts) {
    if (!rec.lockedUntil || rec.lockedUntil < now) attempts.delete(key);
  }
}

function sign(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Method Not Allowed' });

  // fail-closed：配置缺失时明确报错，绝不回落到任何内置默认值
  if (!PASSWORD_HASH || !AUTH_SECRET) {
    return res.status(503).json({ success: false, message: '服务未正确配置，请联系管理员' });
  }

  const ip = getClientIp(req);
  const now = Date.now();
  let rec = attempts.get(ip);

  // 锁定期内：直接拒绝，不进入 bcrypt 计算（省 CPU，也避免被当作算力入口）
  if (rec && rec.lockedUntil && rec.lockedUntil > now) {
    const retryAfter = Math.ceil((rec.lockedUntil - now) / 1000);
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({
      success: false,
      message: `尝试次数过多，请 ${Math.ceil(retryAfter / 60)} 分钟后再试`,
    });
  }

  const { password } = req.body || {};
  if (!password) return res.status(400).json({ success: false, message: '请输入密码' });

  const match = bcrypt.compareSync(String(password), PASSWORD_HASH);

  if (!match) {
    // 窗口过期则重新计数
    if (!rec || now - rec.firstAt > WINDOW_MS) {
      rec = { count: 0, firstAt: now, lockedUntil: 0 };
    }
    rec.count += 1;
    if (rec.count >= MAX_ATTEMPTS) rec.lockedUntil = now + LOCK_MS;
    attempts.set(ip, rec);
    prune(now);

    // 失败递增延迟：第 5 次约 1.25s，进一步压低爆破速率
    await new Promise((r) => setTimeout(r, Math.min(1250, 250 * rec.count)));

    const locked = Boolean(rec.lockedUntil && rec.lockedUntil > now);
    if (locked) res.setHeader('Retry-After', String(Math.ceil(LOCK_MS / 1000)));
    return res.status(locked ? 429 : 401).json({
      success: false,
      message: locked
        ? `尝试次数过多，已锁定 ${Math.ceil(LOCK_MS / 60000)} 分钟`
        : '密码错误',
    });
  }

  // 登录成功：清除该 IP 的失败记录
  attempts.delete(ip);

  const token = sign({
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + 86400,
  });

  res.setHeader('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);
  return res.status(200).json({ success: true });
};
