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

-- ---- support tickets ----------------------------------------------------------------------------------------------

-- A customer's support ticket. It belongs to a workspace: every member sees it. user_id is who raised it (NULL after they
-- delete their account: the ticket stays with the workspace, anonymised; deleting the workspace deletes its tickets).
CREATE TABLE IF NOT EXISTS support_tickets (
    id            uuid PRIMARY KEY,
    number        bigint GENERATED BY DEFAULT AS IDENTITY UNIQUE,   -- shown as #1, #2 … in emails and the UI
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    app_id        uuid REFERENCES apps (id) ON DELETE SET NULL,
    subject       text NOT NULL,
    category      text NOT NULL CHECK (category IN ('billing', 'finding', 'fix', 'account', 'bug', 'other')),
    priority      text NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal', 'urgent')),
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'waiting_on_customer', 'resolved', 'closed')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    closed_at     timestamptz
);
CREATE INDEX IF NOT EXISTS support_tickets_workspace ON support_tickets (workspace_id, updated_at);
CREATE INDEX IF NOT EXISTS support_tickets_status ON support_tickets (status, updated_at);
CREATE INDEX IF NOT EXISTS support_tickets_user ON support_tickets (user_id);

-- The thread: customer messages, support replies, internal notes (admin only) and status changes.
CREATE TABLE IF NOT EXISTS support_messages (
    id          uuid PRIMARY KEY,
    ticket_id   uuid NOT NULL REFERENCES support_tickets (id) ON DELETE CASCADE,
    author      text NOT NULL CHECK (author IN ('customer', 'support')),
    kind        text NOT NULL DEFAULT 'message' CHECK (kind IN ('message', 'note', 'status')),   -- note = internal, never shown to customers
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,                                    -- customer messages: who wrote it
    body        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_messages_ticket ON support_messages (ticket_id, created_at);
CREATE INDEX IF NOT EXISTS support_messages_user ON support_messages (user_id);

-- ---- roles, client app access, account audit log, chat alert format ------------------------------------------------

-- Roles beyond owner/member: owner, admin, approver, member, viewer, client. Existing rows keep their role (member stays
-- member). The CHECK constraints are widened in place, only when they don't list the new roles yet (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workspace_members_role_check'
                   AND pg_get_constraintdef(oid) LIKE '%client%') THEN
        ALTER TABLE workspace_members DROP CONSTRAINT IF EXISTS workspace_members_role_check;
        ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_role_check
            CHECK (role IN ('owner', 'admin', 'approver', 'member', 'viewer', 'client'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'invites_role_check'
                   AND pg_get_constraintdef(oid) LIKE '%client%') THEN
        ALTER TABLE invites DROP CONSTRAINT IF EXISTS invites_role_check;
        ALTER TABLE invites ADD CONSTRAINT invites_role_check
            CHECK (role IN ('owner', 'admin', 'approver', 'member', 'viewer', 'client'));
    END IF;
END $$;

-- An invite for a client carries the apps they will see.
ALTER TABLE invites ADD COLUMN IF NOT EXISTS app_ids uuid[] NOT NULL DEFAULT '{}';

-- The apps a 'client' member may see (read-only). Other roles see every app in the workspace.
CREATE TABLE IF NOT EXISTS member_app_access (
    workspace_id  uuid NOT NULL,
    user_id       uuid NOT NULL,
    app_id        uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id, app_id),
    FOREIGN KEY (workspace_id, user_id) REFERENCES workspace_members (workspace_id, user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS member_app_access_app ON member_app_access (app_id);

-- Webhook message format: auto (detect Slack, Discord, Teams from the URL; anything else gets the signed JSON) or forced.
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS webhook_format text NOT NULL DEFAULT 'auto';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workspaces_webhook_format_check') THEN
        ALTER TABLE workspaces ADD CONSTRAINT workspaces_webhook_format_check
            CHECK (webhook_format IN ('auto', 'json', 'slack', 'discord', 'teams'));
    END IF;
END $$;

-- Account audit log: append-only. Rows are never updated or deleted, with two exceptions the trigger allows:
-- personal data can be scrubbed (actor_id/actor_name/actor_email/target_email/target_label, when an account is deleted),
-- and rows go when their workspace is deleted. Never holds secrets, tokens or full webhook URLs.
CREATE TABLE IF NOT EXISTS audit_log (
    id            bigserial PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    action        text NOT NULL,                 -- e.g. member.role_changed (audit.ACTIONS)
    actor_kind    text NOT NULL CHECK (actor_kind IN ('user', 'api_key', 'admin', 'system')),
    actor_id      uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_name    text,
    actor_email   text,
    target_type   text,                          -- member | invite | app | check | api_key | webhook | ticket | workspace
    target_id     text,
    target_label  text,                          -- never an email address (that goes in target_email)
    target_email  text,
    detail        jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_workspace ON audit_log (workspace_id, id DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor ON audit_log (actor_id);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM workspaces WHERE id = OLD.workspace_id) THEN
            RAISE EXCEPTION 'audit_log is append-only';
        END IF;
        RETURN OLD;
    END IF;
    IF (NEW.id, NEW.workspace_id, NEW.at, NEW.action, NEW.actor_kind, NEW.target_type, NEW.target_id, NEW.detail)
       IS DISTINCT FROM (OLD.id, OLD.workspace_id, OLD.at, OLD.action, OLD.actor_kind, OLD.target_type, OLD.target_id, OLD.detail)
       OR (NEW.actor_id IS NOT NULL AND NEW.actor_id IS DISTINCT FROM OLD.actor_id) THEN
        RAISE EXCEPTION 'audit_log is append-only';
    END IF;
    RETURN NEW;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_log_append_only') THEN
        CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
    END IF;
END $$;
