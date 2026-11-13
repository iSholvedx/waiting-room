
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

  if (!sameOrigin(req)) {
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
        error: 'Admission required'
      });
    }

    const tokenHash = hash(queueToken);

    const [session] = await sql`
      SELECT *
      FROM queue_sessions
      WHERE token_hash = ${tokenHash}
      LIMIT 1
    `;

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

    if (session.status !== 'admitted') {
      return sendJson(res, 403, {
        error: 'Admission required'
      });
    }

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
      return sendJson(res, 403, {
        error: 'Admission expired'
      });
    }

    return sendJson(res, 200, {
      success: true,
      state: 'entered',
      redirect: '/site/'
    });

  } catch (error) {
    console.error('Queue enter error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
