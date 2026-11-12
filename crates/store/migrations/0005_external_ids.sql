-- Stable ids for client dialects that use their own identifier space.
-- The local row keeps its primary key; this table is the only place a dialect id
-- is authoritative, so changing an encoding never rewrites timeline rows.
CREATE TABLE external_id (
    kind text NOT NULL,
    local_id text NOT NULL,
    external_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, local_id),
    UNIQUE (kind, external_id)
);
