
import { sql } from '../../lib/db.js';

import {
  hash,
  randomToken,
  parseCookies,
  makeCookie,
  clearCookie,
  createPassToken,
  setCookies,
  sendJson
} from '../../lib/security.js';

const INITIAL_POSITION = 200;
const INTERVAL_MS = 5000;
const HOLD_MS = 15 * 60 * 1000;
const COOKIE_DAYS = 30;

async function createSession() {
  const token = randomToken();
  const tokenHash = hash(token);
  const now = Date.now();
  const ticket = `WR-${randomToken(4).toUpperCase()}`;

  const [session] = await sql`
    INSERT INTO queue_sessions (
      token_hash,
      ticket,
      status,
      initial_ahead,
      created_at
    )
    VALUES (
      ${tokenHash},
      ${ticket},
      'waiting',
      ${INITIAL_POSITION},
      ${now}
    )
    RETURNING *
  `;

  return { token, session };
}

function positionOf(session, now) {
  if (session.status !== 'waiting') return 0;

  const elapsed = Math.max(
    0,
    now - Number(session.created_at)
  );

  const steps = Math.floor(elapsed / INTERVAL_MS);

  return Math.max(
    1,
    Number(session.initial_ahead) - steps
  );
}

async function publishGlobalAdmission(now) {
  await sql`
    INSERT INTO global_admission (
      id,
      admitted_at,
      expires_at
    )
    VALUES (
      1,
      ${now},
      ${now + HOLD_MS}
    )
    ON CONFLICT (id)
    DO UPDATE SET
      admitted_at = EXCLUDED.admitted_at,
      expires_at = EXCLUDED.expires_at
    WHERE global_admission.expires_at <= EXCLUDED.admitted_at
  `;
}

async function applyGlobalAdmission(tokenHash, now) {
  const [global] = await sql`
    SELECT admitted_at, expires_at
    FROM global_admission
    WHERE id = 1
      AND expires_at > ${now}
    LIMIT 1
  `;

  if (!global) return false;

  await sql`
    UPDATE queue_sessions
    SET
      status = 'admitted',
      admitted_at = ${Number(global.admitted_at)},
      expires_at = ${Number(global.expires_at)}
    WHERE token_hash = ${tokenHash}
      AND status = 'waiting'
      AND expires_at IS NULL
  `;

  return true;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');

    return sendJson(res, 405, {
      error: 'Method not allowed'
    });
  }

  try {
    const now = Date.now();
    const cookies = parseCookies(req);
    const responseCookies = [];

    // Expire admission yang sudah melewati batas waktu.
    await sql`
      UPDATE queue_sessions
      SET status = 'expired'
      WHERE status IN ('admitted', 'entered')
        AND expires_at <= ${now}
    `;

    let token = cookies.wr_queue;
    let session = null;

    // Cari sesi browser saat ini.
    if (token && token.length <= 128) {
      const [existing] = await sql`
        SELECT *
        FROM queue_sessions
        WHERE token_hash = ${hash(token)}
        LIMIT 1
      `;

      session = existing || null;
    }

    // Buat sesi baru jika cookie tidak valid atau expired.
    if (!session || session.status === 'expired') {
      const fresh = await createSession();

      token = fresh.token;
      session = fresh.session;

      responseCookies.push(
        makeCookie(
          'wr_queue',
          token,
          COOKIE_DAYS * 86400
        ),
        clearCookie('wr_passed')
      );
    }

    const tokenHash = hash(token);

    // Admission normal berdasarkan waktu antrean.
    const admissionThreshold =
      now - (INITIAL_POSITION * INTERVAL_MS);

    const newlyAdmitted = await sql`
      UPDATE queue_sessions
      SET
        status = 'admitted',
        admitted_at = ${now},
        expires_at = ${now + HOLD_MS}
      WHERE status = 'waiting'
        AND created_at <= ${admissionThreshold}
      RETURNING id
    `;

    // Sesi yang baru admitted menerbitkan izin global.
    // Izin aktif tidak diperpanjang oleh polling biasa.
    if (newlyAdmitted.length > 0) {
      await publishGlobalAdmission(now);
    }

    // Jika izin global masih aktif, berikan admission
    // kepada sesi browser ini dengan expiry yang sama.
    await applyGlobalAdmission(tokenHash, now);

    // Ambil status terbaru.
    const [current] = await sql`
      SELECT *
      FROM queue_sessions
      WHERE token_hash = ${tokenHash}
      LIMIT 1
    `;

    if (!current) {
      setCookies(res, responseCookies);

      return sendJson(res, 500, {
        error: 'Unable to retrieve queue session'
      });
    }

    // Browser yang admitted memperoleh token sendiri.
    if (
      current.status === 'admitted' ||
      current.status === 'entered'
    ) {
      const remaining = Math.ceil(
        (Number(current.expires_at) - now) / 1000
      );

      if (remaining <= 0) {
        return sendJson(res, 403, {
          error: 'Admission expired'
        });
      }

      const pass = createPassToken(current);

      responseCookies.push(
        makeCookie(
          'wr_passed',
          pass,
          remaining
        )
      );

      setCookies(res, responseCookies);

      return sendJson(res, 200, {
        state: current.status,
        ticket: current.ticket,
        holdExpiresAt: Number(current.expires_at),
        serverTime: now,
        admissionType: 'global-or-individual'
      });
    }

    responseCookies.push(clearCookie('wr_passed'));

    setCookies(res, responseCookies);

    const position = positionOf(current, now);

    const progress = Math.min(
      100,
      Math.max(
        0,
        (
          (INITIAL_POSITION - position) /
          INITIAL_POSITION
        ) * 100
      )
    );

    return sendJson(res, 200, {
      state: 'waiting',
      ticket: current.ticket,
      position,
      etaSeconds: Math.ceil(
        position * INTERVAL_MS / 1000
      ),
      progress: Number(progress.toFixed(1)),
      serverTime: now
    });

  } catch (error) {
    console.error('Queue status error:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  }
}
