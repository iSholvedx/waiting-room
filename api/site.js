
import { sql } from '../lib/db.js';

import {
  hash,
  parseCookies,
  verifyPassToken
} from '../lib/security.js';

export default async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    res.statusCode = 405;
    return res.end('Method not allowed');
  }

  try {
    const cookies = parseCookies(req);

    const queueToken = cookies.wr_queue;
    const passToken = cookies.wr_passed;

    if (!queueToken || !passToken) {
      res.statusCode = 403;
      return res.end('Admission required');
    }

    const [session] = await sql`
      SELECT *
      FROM queue_sessions
      WHERE token_hash = ${hash(queueToken)}
      LIMIT 1
    `;

    if (
      !session ||
      !['admitted', 'entered'].includes(session.status) ||
      !verifyPassToken(passToken, session)
    ) {
      res.statusCode = 403;
      return res.end('Admission required');
    }

    // Ubah admitted menjadi entered jika belum dilakukan.
    if (session.status === 'admitted') {
      const now = Date.now();

      const updated = await sql`
        UPDATE queue_sessions
        SET status = 'entered'
        WHERE id = ${session.id}
          AND status = 'admitted'
          AND expires_at > ${now}
        RETURNING id
      `;

      if (updated.length !== 1) {
        res.statusCode = 403;
        return res.end('Admission expired');
      }
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome Inside</title>
  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #090b10;
      color: #f5f7fa;
      font-family: Arial, sans-serif;
    }

    main {
      text-align: center;
      padding: 32px;
    }

    h1 { margin-bottom: 12px; }

    p {
      color: #a5adbb;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <main>
    <h1>Welcome inside!</h1>
    <p>Your admission has been verified by the server.</p>
  </main>
</body>
</html>`;

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    if (req.method === 'HEAD') {
      return res.end();
    }

    return res.end(html);

  } catch (error) {
    console.error('Protected site error:', error);

    res.statusCode = 500;
    return res.end('Internal server error');
  }
}
