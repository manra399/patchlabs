-- PatchLabs database. Idempotent: the API runs this on start.

CREATE TABLE IF NOT EXISTS checks (
    id            uuid PRIMARY KEY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    email         text NOT NULL,
    repo          text NOT NULL,              -- owner/name on GitHub
    verify_code   text NOT NULL,
    status        text NOT NULL DEFAULT 'awaiting_verification'
                  CHECK (status IN ('awaiting_verification', 'queued', 'running', 'done', 'no_leaks', 'needs_review', 'failed')),
    verified_at   timestamptz,
    claimed_at    timestamptz,
    finished_at   timestamptz,
    ip_hash       text,
    summary       jsonb,
    report_md     text,
    fix_sql       text,
    cost_usd      numeric(8, 4),
    error         text
);
ALTER TABLE checks ADD COLUMN IF NOT EXISTS branch text;  -- default branch, for the verification file
CREATE INDEX IF NOT EXISTS checks_status_created ON checks (status, created_at);
CREATE INDEX IF NOT EXISTS checks_email ON checks (lower(email));

-- One row per thing that happened to a check: the receipt trail.
CREATE TABLE IF NOT EXISTS check_events (
    id        bigserial PRIMARY KEY,
    check_id  uuid NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    at        timestamptz NOT NULL DEFAULT now(),
    kind      text NOT NULL,
    detail    text
);
CREATE INDEX IF NOT EXISTS check_events_check ON check_events (check_id, at);

-- Small key/value store, e.g. the worker's last heartbeat.
CREATE TABLE IF NOT EXISTS kv (
    key        text PRIMARY KEY,
    value      text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
