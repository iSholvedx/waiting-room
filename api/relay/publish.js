import { sql } from '../../lib/db.js';
import { hashDeviceToken, isValidDeviceToken } from '../../lib/relay.js';
import { sendJson } from '../../lib/security.js';

const DEFAULT_TTL = 120 * 1000;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  try {
    const token = req.headers['x-relay-device'];
    if (!isValidDeviceToken(token)) {
      return sendJson(res, 401, { error: 'Invalid device' });
    }

    const tokenHash = hashDeviceToken(token);
    const now = Date.now();

    const [device] = await sql`
      SELECT id FROM relay_devices
      WHERE device_token_hash = ${tokenHash} AND active = TRUE
      LIMIT 1
    `;
    if (!device) return sendJson(res, 401, { error: 'Device not registered' });

    const { room_id, event_type, payload, ttl_ms } = req.body ?? {};
    if (!room_id || !event_type) {
      return sendJson(res, 400, { error: 'room_id and event_type required' });
    }

    const ttl = Number(ttl_ms) > 0 ? Number(ttl_ms) : DEFAULT_TTL;

    await sql`UPDATE relay_devices SET last_seen = ${now} WHERE id = ${device.id}`;

    const [event] = await sql`
      INSERT INTO relay_events (room_id, device_id, event_type, payload, created_at, expires_at)
      VALUES (${room_id}, ${device.id}, ${event_type}, ${payload ?? null}, ${now}, ${now + ttl})
      RETURNING id, created_at, expires_at
    `;

    return sendJson(res, 200, { success: true, event });
  } catch (error) {
    console.error('Relay publish error:', error);
    return sendJson(res, 500, { error: 'Internal server error' });
  }
}
