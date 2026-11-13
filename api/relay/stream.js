import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

export const config = {
  runtime: 'edge' // ⚠️ Edge runtime — support streaming
};

export default async function handler(req) {
  const url = new URL(req.url);
  const token = req.headers.get('x-relay-device');
  const roomId = url.searchParams.get('room_id');
  const eventType = url.searchParams.get('event_type') || 'session-share';

  if (!token || !roomId) {
    return new Response('Missing token or room_id', { status: 400 });
  }

  // Validasi token
  const tokenHash = await sha256(token);
  const devices = await sql`
    SELECT id FROM relay_devices
    WHERE device_token_hash = ${tokenHash} AND active = TRUE
    LIMIT 1
  `;
  if (!devices.length) {
    return new Response('Invalid device', { status: 401 });
  }
  const deviceId = devices[0].id;

  // SSE stream
  const encoder = new TextEncoder();
  let closed = false;

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch {}
      };

      // Kirim ping awal biar koneksi kebuka
      send({ type: 'connected', deviceId });

      // Loop: cek DB tiap 500ms
      const pollInterval = setInterval(async () => {
        if (closed) return;
        try {
          const now = Date.now();
          const events = await sql`
            UPDATE relay_events
            SET consumed_at = ${now}, consumed_by = ${deviceId}
            WHERE id IN (
              SELECT id FROM relay_events
              WHERE room_id = ${roomId}
                AND event_type = ${eventType}
                AND consumed_at IS NULL
                AND expires_at > ${now}
                AND device_id <> ${deviceId}
              ORDER BY created_at ASC
              LIMIT 5
              FOR UPDATE SKIP LOCKED
            )
            RETURNING id, event_type, payload, created_at, expires_at
          `;

          for (const ev of events) {
            send({ type: 'event', event: ev });
          }
        } catch (err) {
          console.error('[stream] poll error:', err);
        }
      }, 500);

      // Cleanup kalau client disconnect
      req.signal.addEventListener('abort', () => {
        closed = true;
        clearInterval(pollInterval);
        try { controller.close(); } catch {}
      });

      // Auto-close setelah 5 menit (biar nggak nyangkut)
      setTimeout(() => {
        closed = true;
        clearInterval(pollInterval);
        try { controller.close(); } catch {}
      }, 5 * 60 * 1000);
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    }
  });
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
