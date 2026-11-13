
import crypto from 'node:crypto';

const SECRET = process.env.WR_SECRET;

if (!SECRET || SECRET.length < 32) {
  throw new Error('WR_SECRET must contain at least 32 characters');
}

export function hash(value) {
  return crypto
    .createHash('sha256')
    .update(value)
    .digest('hex');
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sign(payload) {
  return crypto
    .createHmac('sha256', SECRET)
    .update(payload)
    .digest('base64url');
}

function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

export function parseCookies(req) {
  const result = {};
  const raw = req.headers.cookie || '';

  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (/^[a-zA-Z0-9_-]+$/.test(name)) {
      result[name] = value;
    }
  }

  return result;
}

export function makeCookie(name, value, maxAge) {
  return [
    `${name}=${value}`,
    'Path=/',
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

export function clearCookie(name) {
  return makeCookie(name, '', 0);
}

export function createPassToken(session) {
  const payload = `${session.token_hash}.${session.expires_at}`;

  return `${payload}.${sign(payload)}`;
}

export function verifyPassToken(token, session) {
  if (!token || !session || !session.expires_at) {
    return false;
  }

  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const [sessionHash, expiry, signature] = parts;

  if (sessionHash !== session.token_hash) return false;
  if (Number(expiry) !== Number(session.expires_at)) return false;
  if (Date.now() >= Number(session.expires_at)) return false;

  const payload = `${sessionHash}.${expiry}`;

  return safeEqual(signature, sign(payload));
}

export function setCookies(res, cookies) {
  if (cookies.length) {
    res.setHeader('Set-Cookie', cookies);
  }
}

export function sendJson(res, status, data) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(data));
}

export function sameOrigin(req) {
  const origin = req.headers.origin;

  // Browser requests with Origin must match the deployment host.
  if (!origin) return true;

  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}
