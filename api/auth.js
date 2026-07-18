const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const PASSWORD_HASH = process.env.PASSWORD_HASH || '$2b$10$exgu/yQGURr.2k.QBHoquO4SpiV632mzrfC/al.VsR3LU8.N8H77W';
const AUTH_SECRET = process.env.AUTH_SECRET || 'fallback-dev-secret-change-me';

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

  const { password } = req.body || {};
  if (!password) return res.status(400).json({ success: false, message: '请输入密码' });

  const match = bcrypt.compareSync(String(password), PASSWORD_HASH);
  if (!match) return res.status(401).json({ success: false, message: '密码错误' });

  const token = sign({ iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 });

  res.setHeader('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);
  return res.status(200).json({ success: true });
};
