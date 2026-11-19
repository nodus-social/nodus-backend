-- Which media nodes are alive.
--
-- Media is content-addressed, so placement is a pure function of the digest and the
-- current member set: there is deliberately no table saying "this node holds that file",
-- which is one fewer thing to keep in sync when a node dies.
--
-- A node announces itself by upserting its row on a heartbeat. A node that stops
-- heartbeating ages out of every membership read, and is eventually forgotten here.
CREATE TABLE media_node (
    name         text PRIMARY KEY CHECK (btrim(name) <> ''),
    endpoint     text NOT NULL CHECK (btrim(endpoint) <> ''),
    capacity_bytes bigint,
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Membership is read by heartbeat age and the sweeper deletes by it.
CREATE INDEX media_node_heartbeat_idx ON media_node (heartbeat_at);
