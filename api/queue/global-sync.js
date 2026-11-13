
import { sql } from '../../lib/db.js';

import {
  hash,
  parseCookies,
  verifyPassToken,
  sameOrigin,
  sendJson
} from '../../lib/security.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');

    return sendJson(res, 405, {
      error: 'Method not allowed'
    });
  }

  if (!req.headers.origin || !sameOrigin(req)) {
    return sendJson(res, 403, {
      error: 'Invalid request origin'
    });
  }

  try {
    const cookies = parseCookies(req);
    const queueToken = cookies.wr_queue;
    const passToken = cookies.wr_passed;

    if (!queueToken || !passToken) {
      return sendJson(res, 403, {
        error: 'Waiting Room admission required'
      });
    }

    const tokenHash = hash(queueToken);

    const [session] = await sql`
      SELECT *
      FROM queue_sessions
      WHERE token_hash = ${tokenHash}
      LIMIT 1
    `;

    const now = Date.now();

    if (
      !session ||
      !['admitted', 'entered'].includes(session.status) ||
      !session.expires_at ||
      Number(session.expires_at) <= now ||
      !verifyPassToken(passToken, session)
    ) {
      return sendJson(res, 403, {
        error: 'Invalid or expired Waiting Room admission'
      });
    }

    const admittedAt = Number(session.admitted_at) || now;
    const expiresAt = Number(session.expires_at);

    await sql`
      INSERT INTO global_admission (
        id,
        admitted_at,
        expires_at
      )
      VALUES (
        1,
        ${admittedAt},
        ${expiresAt}
      )
      ON CONFLICT (id)
      DO UPDATE SET
        admitted_at = EXCLUDED.admitted_at,
        expires_at = EXCLUDED.expires_at
      WHERE global_admission.expires_at <= ${now}
    `;

    const [global] = await sql`
      SELECT admitted_at, expires_at
      FROM global_admission
      WHERE id = 1
        AND expires_at > ${now}
      LIMIT 1
    `;

    return sendJson(res, 200, {
      success: true,
      active: Boolean(global),
      expiresAt: global
        ? Number(global.expires_at)
        : null
    });

  } catch (error) {
    console.error('Global sync error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
