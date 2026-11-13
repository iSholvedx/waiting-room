
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');

// ============================================================
// CONFIGURATION
// ============================================================

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DB_DIR = path.join(ROOT, 'data');
const DB_PATH = path.join(DB_DIR, 'waitingroom.db');
const SECRET_PATH = path.join(DB_DIR, '.secret');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT) || 3000;

const CONFIG = {
  admissionInterval: 5000,       // 5 detik per posisi
  initialPosition: 200,          // Semua pengunjung mulai dari 200
  holdMs: 15 * 60 * 1000,         // Waktu masuk: 15 menit
  queueCookieDays: 30,
  maxRequestBytes: 1024,
  rateLimitWindow: 60_000,
  rateLimitMax: 120,
  secureCookie: process.env.COOKIE_SECURE === 'true'
};

// ============================================================
// INITIALIZATION
// ============================================================

fs.mkdirSync(PUBLIC_DIR, { recursive: true });
fs.mkdirSync(DB_DIR, { recursive: true });

function loadSecret() {
  if (fs.existsSync(SECRET_PATH)) {
    return fs.readFileSync(SECRET_PATH);
  }

  const secret = crypto.randomBytes(64);

  fs.writeFileSync(SECRET_PATH, secret, {
    mode: 0o600,
    flag: 'wx'
  });

  return secret;
}

const SECRET = loadSecret();

const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS queue_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    ticket TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'waiting',
    initial_ahead INTEGER NOT NULL DEFAULT 200,
    created_at INTEGER NOT NULL,
    admitted_at INTEGER,
    expires_at INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_queue_status_created
  ON queue_sessions(status, created_at, id);

  CREATE INDEX IF NOT EXISTS idx_queue_expiry
  ON queue_sessions(expires_at);
`);

// ============================================================
// DATABASE QUERIES
// ============================================================

const queries = {
  findSession: db.prepare(`
    SELECT * FROM queue_sessions
    WHERE token_hash = ?
  `),

  insertSession: db.prepare(`
    INSERT INTO queue_sessions (
      token_hash,
      ticket,
      status,
      initial_ahead,
      created_at
    ) VALUES (?, ?, 'waiting', ?, ?)
  `),

  nextWaiting: db.prepare(`
    SELECT * FROM queue_sessions
    WHERE status = 'waiting'
    ORDER BY created_at ASC, id ASC
    LIMIT 1
  `),

  admit: db.prepare(`
    UPDATE queue_sessions
    SET status = 'admitted',
        admitted_at = ?,
        expires_at = ?
    WHERE id = ? AND status = 'waiting'
  `),

  expire: db.prepare(`
    UPDATE queue_sessions
    SET status = 'expired'
    WHERE status IN ('admitted', 'entered')
      AND expires_at <= ?
  `),

  enter: db.prepare(`
    UPDATE queue_sessions
    SET status = 'entered'
    WHERE id = ?
      AND status = 'admitted'
      AND expires_at > ?
  `)
};

// ============================================================
// SECURITY HELPERS
// ============================================================

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
};

function hash(value) {
  return crypto
    .createHash('sha256')
    .update(value)
    .digest('hex');
}

function randomToken(bytes = 32) {
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

function createPassToken(session) {
  const payload = `${session.token_hash}.${session.expires_at}`;

  return `${payload}.${sign(payload)}`;
}

function verifyPassToken(token, session) {
  if (!token || !session || !session.expires_at) {
    return false;
  }

  const parts = token.split('.');

  if (parts.length !== 3) return false;

  const [sessionHash, expiry, signature] = parts;

  if (sessionHash !== session.token_hash) return false;
  if (Number(expiry) !== session.expires_at) return false;
  if (Date.now() >= session.expires_at) return false;

  const payload = `${sessionHash}.${expiry}`;

  return safeEqual(signature, sign(payload));
}

function parseCookies(req) {
  const result = {};

  for (const part of (req.headers.cookie || '').split(';')) {
    const index = part.indexOf('=');

    if (index < 0) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (/^[a-zA-Z0-9_-]+$/.test(key)) {
      result[key] = value;
    }
  }

  return result;
}

function cookie(name, value, maxAge, httpOnly = true) {
  const parts = [
    `${name}=${value}`,
    'Path=/',
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
    'SameSite=Lax'
  ];

  if (httpOnly) parts.push('HttpOnly');
  if (CONFIG.secureCookie) parts.push('Secure');

  return parts.join('; ');
}

function clearCookie(name) {
  return cookie(name, '', 0);
}

// ============================================================
// HTTP HELPERS
// ============================================================

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store'
  };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    ...securityHeaders(),
    ...headers
  });

  res.end(body);
}

function sendJson(res, status, data, cookies = []) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8'
  };

  if (cookies.length) {
    headers['Set-Cookie'] = cookies;
  }

  send(res, status, JSON.stringify(data), headers);
}

function getClientIp(req) {
  // Do not trust forwarded headers in local deployment.
  return req.socket.remoteAddress || 'unknown';
}

// ============================================================
// RATE LIMITING
// ============================================================

const rateLimits = new Map();

function checkRateLimit(req) {
  const now = Date.now();
  const ip = getClientIp(req);

  let record = rateLimits.get(ip);

  if (!record || now - record.start >= CONFIG.rateLimitWindow) {
    record = {
      start: now,
      count: 0
    };
  }

  record.count++;
  rateLimits.set(ip, record);

  if (rateLimits.size > 10000) {
    for (const [key, value] of rateLimits) {
      if (now - value.start >= CONFIG.rateLimitWindow) {
        rateLimits.delete(key);
      }
    }
  }

  return record.count <= CONFIG.rateLimitMax;
}

// ============================================================
// REQUEST VALIDATION
// ============================================================

function sameOrigin(req) {
  const origin = req.headers.origin;

  if (!origin) return true;

  try {
    const parsed = new URL(origin);
    const host = req.headers.host;

    return parsed.host === host;
  } catch {
    return false;
  }
}

async function readBody(req) {
  let size = 0;
  const chunks = [];

  for await (const chunk of req) {
    size += chunk.length;

    if (size > CONFIG.maxRequestBytes) {
      throw new Error('Request too large');
    }

    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString('utf8');
}

// ============================================================
// QUEUE MANAGEMENT
// ============================================================

function createSession() {
  const token = randomToken();
  const tokenHash = hash(token);
  const now = Date.now();

  const transaction = db.transaction(() => {
    const initialAhead = CONFIG.initialPosition;

    const ticket = 'WR-' +
      randomToken(4).toUpperCase();

    queries.insertSession.run(
      tokenHash,
      ticket,
      initialAhead,
      now
    );
  });

  transaction();

  return {
    token,
    session: queries.findSession.get(tokenHash)
  };
}

function getOrCreateSession(req) {
  const cookies = parseCookies(req);
  const queueToken = cookies.wr_queue;

  if (queueToken && queueToken.length <= 128) {
    const session = queries.findSession.get(hash(queueToken));

    if (session) {
      return {
        token: queueToken,
        session
      };
    }
  }

  return createSession();
}

function cleanupExpired() {
  queries.expire.run(Date.now());
}

// Hitung posisi berdasarkan waktu sejak pengunjung masuk.
function getPosition(session) {
  if (session.status !== 'waiting') return 0;

  const elapsed = Math.max(0, Date.now() - session.created_at);

  const steps = Math.floor(
    elapsed / CONFIG.admissionInterval
  );

  return Math.max(
    1,
    session.initial_ahead - steps
  );
}

function getEtaSeconds(position) {
  return Math.max(
    0,
    Math.ceil(position * CONFIG.admissionInterval / 1000)
  );
}

// ============================================================
// ADMISSION SCHEDULER
// ============================================================

// Pengunjung pertama harus menyelesaikan hitungan 200 sampai 1.
// Setelah 200 interval x 5 detik, pengunjung bisa masuk.

const admitTransaction = db.transaction(() => {
  const now = Date.now();

  cleanupExpired();

  const next = queries.nextWaiting.get();

  if (!next) return;

  const elapsed = Math.max(0, now - next.created_at);

  const requiredTime =
    next.initial_ahead * CONFIG.admissionInterval;

  if (elapsed < requiredTime) return;

  queries.admit.run(
    now,
    now + CONFIG.holdMs,
    next.id
  );
});

function processQueue() {
  admitTransaction();
}

// ============================================================
// API: QUEUE STATUS
// ============================================================

function queueStatus(req, res) {
  const { token, session } = getOrCreateSession(req);

  const cookies = [];

  if (parseCookies(req).wr_queue !== token) {
    cookies.push(
      cookie(
        'wr_queue',
        token,
        CONFIG.queueCookieDays * 86400
      )
    );
  }

  const current = queries.findSession.get(session.token_hash);

  // Jika sesi lama sudah expired, buat sesi baru.
  if (current.status === 'expired') {
    const replacement = createSession();

    cookies.push(
      cookie(
        'wr_queue',
        replacement.token,
        CONFIG.queueCookieDays * 86400
      ),
      clearCookie('wr_passed')
    );

    const fresh = replacement.session;
    const position = getPosition(fresh);

    return sendJson(res, 200, {
      state: 'waiting',
      ticket: fresh.ticket,
      position,
      etaSeconds: getEtaSeconds(position),
      progress: 0,
      serverTime: Date.now()
    }, cookies);
  }

  // Jika sudah mendapat giliran.
  if (
    current.status === 'admitted' ||
    current.status === 'entered'
  ) {
    const pass = createPassToken(current);

    cookies.push(
      cookie(
        'wr_passed',
        pass,
        Math.ceil((current.expires_at - Date.now()) / 1000)
      )
    );

    return sendJson(res, 200, {
      state: current.status,
      ticket: current.ticket,
      holdExpiresAt: current.expires_at,
      serverTime: Date.now()
    }, cookies);
  }

  // Pengunjung yang masih menunggu tidak memiliki pass.
  cookies.push(clearCookie('wr_passed'));

  const position = getPosition(current);

  const progress = current.initial_ahead > 0
    ? Math.min(
        100,
        Math.max(
          0,
          ((current.initial_ahead - position) /
            current.initial_ahead) * 100
        )
      )
    : 0;

  return sendJson(res, 200, {
    state: 'waiting',
    ticket: current.ticket,
    position,
    etaSeconds: getEtaSeconds(position),
    progress: Number(progress.toFixed(1)),
    serverTime: Date.now()
  }, cookies);
}

// ============================================================
// API: ENTER WEBSITE
// ============================================================

function enterWebsite(req, res) {
  const cookies = parseCookies(req);

  const queueToken = cookies.wr_queue;
  const passToken = cookies.wr_passed;

  if (!queueToken || !passToken) {
    return sendJson(res, 403, {
      error: 'Admission required'
    });
  }

  const session = queries.findSession.get(hash(queueToken));

  if (!session || !verifyPassToken(passToken, session)) {
    return sendJson(res, 403, {
      error: 'Invalid or expired admission'
    });
  }

  if (session.status === 'entered') {
    return sendJson(res, 200, {
      success: true,
      state: 'entered',
      redirect: '/site/'
    });
  }

  const result = queries.enter.run(
    session.id,
    Date.now()
  );

  if (result.changes !== 1) {
    return sendJson(res, 403, {
      error: 'Admission expired'
    });
  }

  return sendJson(res, 200, {
    success: true,
    state: 'entered',
    redirect: '/site/'
  });
}

// ============================================================
// STATIC FILE SERVER
// ============================================================

function serveStatic(req, res, pathname) {
  const cookies = parseCookies(req);

  // Semua halaman di dalam /site memerlukan admission.
  if (pathname === '/site' || pathname.startsWith('/site/')) {
    const queueToken = cookies.wr_queue;
    const passToken = cookies.wr_passed;

    const session = queueToken
      ? queries.findSession.get(hash(queueToken))
      : null;

    if (
      !session ||
      !['admitted', 'entered'].includes(session.status) ||
      !verifyPassToken(passToken, session)
    ) {
      return send(res, 403, 'Admission required');
    }

    // Ubah status admitted menjadi entered ketika halaman dibuka.
    if (session.status === 'admitted') {
      const result = queries.enter.run(
        session.id,
        Date.now()
      );

      if (result.changes !== 1) {
        return send(res, 403, 'Admission expired');
      }
    }
  }

  let relative = pathname;

  // Mapping halaman utama.
  if (relative === '/') {
    relative = '/index.html';
  } else if (relative === '/site' || relative === '/site/') {
    relative = '/site/index.html';
  } else if (relative.endsWith('/')) {
    relative += 'index.html';
  }

  const filePath = path.resolve(
    PUBLIC_DIR,
    '.' + relative
  );

  // Cegah directory traversal.
  if (
    filePath !== PUBLIC_DIR &&
    !filePath.startsWith(PUBLIC_DIR + path.sep)
  ) {
    return send(res, 403, 'Forbidden');
  }

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      return send(res, 404, 'Not Found');
    }

    const type =
      MIME[path.extname(filePath).toLowerCase()] ||
      'application/octet-stream';

    res.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': type,
      'Content-Length': stat.size
    });

    if (req.method === 'HEAD') {
      return res.end();
    }

    const stream = fs.createReadStream(filePath);

    stream.on('error', () => {
      if (!res.headersSent) {
        send(res, 500, 'Internal Server Error');
      } else {
        res.destroy();
      }
    });

    stream.pipe(res);
  });
}

// ============================================================
// MAIN HTTP SERVER
// ============================================================

const server = http.createServer(async (req, res) => {
  let pathname;

  try {
    pathname = decodeURIComponent(
      new URL(
        req.url,
        `http://${req.headers.host || 'localhost'}`
      ).pathname
    );
  } catch {
    return send(res, 400, 'Bad Request');
  }

  if (
    req.method !== 'GET' &&
    req.method !== 'HEAD' &&
    req.method !== 'POST'
  ) {
    return send(res, 405, 'Method Not Allowed', {
      Allow: 'GET, HEAD, POST'
    });
  }

  // API ROUTES
  if (pathname.startsWith('/api/')) {
    if (!checkRateLimit(req)) {
      return sendJson(res, 429, {
        error: 'Too many requests'
      });
    }

    if (
      req.method === 'GET' &&
      pathname === '/api/queue/status'
    ) {
      return queueStatus(req, res);
    }

    if (
      req.method === 'POST' &&
      pathname === '/api/queue/enter'
    ) {
      if (!sameOrigin(req)) {
        return sendJson(res, 403, {
          error: 'Invalid request origin'
        });
      }

      try {
        await readBody(req);
      } catch {
        return sendJson(res, 413, {
          error: 'Request too large'
        });
      }

      return enterWebsite(req, res);
    }

    return sendJson(res, 404, {
      error: 'API endpoint not found'
    });
  }

  if (req.method === 'POST') {
    return send(res, 405, 'Method Not Allowed', {
      Allow: 'GET, HEAD'
    });
  }

  serveStatic(req, res, pathname);
});

// ============================================================
// STARTUP
// ============================================================

const scheduler = setInterval(
  processQueue,
  1000
);

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('====================================');
  console.log('       WAITING ROOM SERVER');
  console.log('====================================');
  console.log(`URL              : http://${HOST}:${PORT}`);
  console.log(`Database         : ${DB_PATH}`);
  console.log(`Initial position : ${CONFIG.initialPosition}`);
  console.log(`Interval         : ${CONFIG.admissionInterval}ms`);
  console.log(`Hold             : ${CONFIG.holdMs / 60000} minutes`);
  console.log('====================================');
  console.log('');
});

server.on('error', (err) => {
  console.error('Server error:', err.message);
  process.exitCode = 1;
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown() {
  console.log('\nShutting down...');

  clearInterval(scheduler);

  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
