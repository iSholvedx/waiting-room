CREATE TABLE IF NOT EXISTS relay_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_token_hash TEXT UNIQUE NOT NULL,
    created_at BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS relay_events (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS relay_events_expiry_idx
ON relay_events (expires_at);
