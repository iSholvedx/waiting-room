import { sql } from '../../lib/db.js';

import {
  hashDeviceToken,
  isValidDeviceToken
} from '../../lib/relay.js';

import {
  sendJson
} from '../../lib/security.js';

const EVENT_TTL = 60 * 1000;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');

    return sendJson(res, 405, {
      error: 'Method not allowed'
    });
  }

  try {
    const token = req.headers['x-relay-device'];

    if (!isValidDeviceToken(token)) {
      return sendJson(res, 401, {
        error: 'Invalid device'
      });
    }

    const tokenHash = hashDeviceToken(token);
    const now = Date.now();

    const [device] = await sql`
      SELECT id
      FROM relay_devices
      WHERE device_token_hash = ${tokenHash}
        AND active = TRUE
      LIMIT 1
    `;

    if (!device) {
      return sendJson(res, 401, {
        error: 'Device not registered'
      });
    }

    await sql`
      UPDATE relay_devices
      SET last_seen = ${now}
      WHERE id = ${device.id}
    `;

    await sql`
      INSERT INTO relay_events (
        event_type,
        created_at,
        expires_at
      )
      VALUES (
        'admission-status-changed',
        ${now},
        ${now + EVENT_TTL}
      )
    `;

    return sendJson(res, 200, {
      success: true
    });

  } catch (error) {
    console.error('Relay publish error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
