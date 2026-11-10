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

-- ---- v2: accounts, workspaces, monitored apps -------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id             uuid PRIMARY KEY,
    email          text NOT NULL,             -- stored lower-case
    name           text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (lower(email));

-- Magic-link sign-in tokens: only the sha256 of the token is stored. Single use, 20 minutes.
CREATE TABLE IF NOT EXISTS login_tokens (
    token_hash  text PRIMARY KEY,
    email       text NOT NULL,
    next        text,
    ip_hash     text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);
CREATE INDEX IF NOT EXISTS login_tokens_email ON login_tokens (lower(email), created_at);
CREATE INDEX IF NOT EXISTS login_tokens_ip ON login_tokens (ip_hash, created_at);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  text PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

-- Plan limits come from the plan; the *_limit columns are admin overrides (NULL = plan default).
CREATE TABLE IF NOT EXISTS workspaces (
    id           uuid PRIMARY KEY,
    name         text NOT NULL,
    plan         text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'maker', 'agency', 'enterprise')),
    app_limit    integer,
    run_limit    integer,
    seat_limit   integer,
    webhook_url  text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role          text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS workspace_members_user ON workspace_members (user_id);

CREATE TABLE IF NOT EXISTS invites (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    email         text NOT NULL,
    role          text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    token_hash    text NOT NULL UNIQUE,
    invited_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    accepted_at   timestamptz
);
CREATE INDEX IF NOT EXISTS invites_workspace ON invites (workspace_id);

-- A monitored repo inside a workspace.
CREATE TABLE IF NOT EXISTS apps (
    id             uuid PRIMARY KEY,
    workspace_id   uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    repo           text NOT NULL,
    branch         text,
    client_label   text,
    verify_code    text NOT NULL,
    verified_at    timestamptz,
    schedule       text NOT NULL DEFAULT 'monthly' CHECK (schedule IN ('off', 'weekly', 'monthly')),
    next_check_at  timestamptz,
    badge_public   boolean NOT NULL DEFAULT false,
    created_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS apps_workspace_repo ON apps (workspace_id, lower(repo));
CREATE INDEX IF NOT EXISTS apps_due ON apps (next_check_at) WHERE verified_at IS NOT NULL AND schedule <> 'off';

CREATE TABLE IF NOT EXISTS api_keys (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name          text NOT NULL,
    prefix        text NOT NULL,              -- first characters, shown in the UI
    key_hash      text NOT NULL UNIQUE,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE TABLE IF NOT EXISTS upgrade_requests (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    plan          text NOT NULL,
    note          text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Checks gain an owner: anonymous checks link to a user by email; app checks belong to an app.
ALTER TABLE checks ADD COLUMN IF NOT EXISTS app_id uuid REFERENCES apps (id) ON DELETE CASCADE;
ALTER TABLE checks ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE checks ADD COLUMN IF NOT EXISTS trigger text;   -- verify | manual | scheduled | api (NULL for anonymous checks)
CREATE INDEX IF NOT EXISTS checks_app ON checks (app_id, created_at);
CREATE INDEX IF NOT EXISTS checks_user ON checks (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS checks_one_open_per_app ON checks (app_id) WHERE app_id IS NOT NULL AND status IN ('queued', 'running');

-- ---- v2 additions: owner decisions, answers, signed receipts, free RLS tool ---------------------------------------

-- An owner's call on a finished app check. 'reject' means "these flagged tables are meant to be readable".
CREATE TABLE IF NOT EXISTS decisions (
    id          uuid PRIMARY KEY,
    check_id    uuid NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    by_label    text,                       -- who decided, as shown on the receipt
    action      text NOT NULL CHECK (action IN ('approve', 'reject')),
    tables      text[] NOT NULL DEFAULT '{}',
    reason      text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS decisions_check ON decisions (check_id, created_at);

-- Tables an owner rejected as findings: later checks mark them suppressed and send no alert for them.
CREATE TABLE IF NOT EXISTS finding_suppressions (
    app_id       uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    table_name   text NOT NULL,
    decision_id  uuid REFERENCES decisions (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, table_name)
);

-- Answers to the report's questions for the owner (summary.questions_for_owner).
CREATE TABLE IF NOT EXISTS check_answers (
    check_id    uuid NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    question    text NOT NULL,
    answer      text NOT NULL,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    by_label    text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (check_id, question)
);

-- Free tools: one row per request (rate limits) and a short-lived result cache per repo + commit.
CREATE TABLE IF NOT EXISTS tool_runs (
    id          bigserial PRIMARY KEY,
    tool        text NOT NULL,
    ip_hash     text,
    repo        text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tool_runs_ip ON tool_runs (tool, ip_hash, created_at);

CREATE TABLE IF NOT EXISTS rls_cache (
    repo        text NOT NULL,              -- lower-case owner/name
    sha         text NOT NULL,
    result      jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo, sha)
);

-- Usage log for limits that must survive deletes: monthly runs, invites, upgrade requests, re-verified repos.
CREATE TABLE IF NOT EXISTS usage_events (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL,
    subject     text NOT NULL,              -- usually a workspace id
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS usage_events_lookup ON usage_events (kind, subject, created_at);

-- Webhook signing secret (whsec_...): created with the first webhook URL, rotatable by owners.
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS webhook_secret text;
