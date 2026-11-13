import { sql } from '../../lib/db.js';
import { hashDeviceToken, isValidDeviceToken } from '../../lib/relay.js';
import { sendJson } from '../../lib/security.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
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

    await sql`UPDATE relay_devices SET last_seen = ${now} WHERE id = ${device.id}`;

    const roomId = req.query.room_id;
    const eventType = req.query.event_type ?? null;
    if (!roomId) return sendJson(res, 400, { error: 'room_id required' });

    const events = await sql`
      UPDATE relay_events
      SET consumed_at = ${now}, consumed_by = ${device.id}
      WHERE id IN (
        SELECT id FROM relay_events
        WHERE room_id = ${roomId}
          AND (${eventType}::text IS NULL OR event_type = ${eventType})
          AND consumed_at IS NULL
          AND expires_at > ${now}
          AND device_id <> ${device.id}
        ORDER BY created_at ASC
        LIMIT 10
        FOR UPDATE SKIP LOCKED
      )
      RETURNING id, event_type, payload, created_at, expires_at
    `;

    return sendJson(res, 200, { success: true, events });
  } catch (error) {
    console.error('Relay poll error:', error);
    return sendJson(res, 500, { error: 'Internal server error' });
  }
}
