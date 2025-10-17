-- Add migration script here
CREATE TABLE IF NOT EXISTS "MPCKeys" (
    pubkey TEXT NOT NULL,
    user_email TEXT NOT NULL,
    node_id SMALLINT NOT NULL,
    key_pkg BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (pubkey, node_id)
);
