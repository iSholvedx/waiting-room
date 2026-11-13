import { sql } from '../../lib/db.js';

import {
  createDeviceToken,
  hashDeviceToken
} from '../../lib/relay.js';

import { sendJson } from '../../lib/security.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');

    return sendJson(res, 405, {
      error: 'Method not allowed'
    });
  }

  try {
    const token = createDeviceToken();
    const now = Date.now();

    await sql`
      INSERT INTO relay_devices (
        device_token_hash,
        created_at,
        last_seen
      )
      VALUES (
        ${hashDeviceToken(token)},
        ${now},
        ${now}
      )
    `;

    return sendJson(res, 201, {
      success: true,
      deviceToken: token
    });

  } catch (error) {
    console.error('Relay registration error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
