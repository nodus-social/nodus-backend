ALTER TABLE account ADD COLUMN admin boolean NOT NULL DEFAULT false;

CREATE TABLE admin_alert (
    id            text PRIMARY KEY,
    kind          text NOT NULL,
    severity      text NOT NULL DEFAULT 'warning',
    method        text,
    path          text,
    status        integer,
    remote_ip     text,
    account_id    text REFERENCES account (id) ON DELETE SET NULL,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    acknowledged_by text REFERENCES account (id) ON DELETE SET NULL
);

CREATE INDEX admin_alert_recent_idx ON admin_alert (created_at DESC);
CREATE INDEX admin_alert_unack_idx ON admin_alert (created_at DESC)
    WHERE acknowledged_at IS NULL;
