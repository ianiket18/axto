CREATE TABLE axto_signing_keys (
	key_id       TEXT PRIMARY KEY,
	instance_id  TEXT NOT NULL,
	public_key   JSONB NOT NULL,
	published_at TIMESTAMPTZ NOT NULL,
	retire_at    TIMESTAMPTZ
);
