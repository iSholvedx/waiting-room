import { sql } from '../../lib/db.js';

import {
  hashDeviceToken,
  isValidDeviceToken
} from '../../lib/relay.js';

import {
  sendJson
} from '../../lib/security.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');

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

    const events = await sql`
      SELECT id, event_type, created_at
      FROM relay_events
      WHERE expires_at > ${now}
      ORDER BY id DESC
      LIMIT 10
    `;

    return sendJson(res, 200, {
      success: true,
      events
    });

  } catch (error) {
    console.error('Relay poll error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
