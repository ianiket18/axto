package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" sql driver
)

// createTableSQL is run by NewPostgresRegistry so a fresh deployment works
// without a separate migration step. This is a deliberate simplification
// for an early-stage project with one table; if Axto grows a real schema,
// replace this with a proper migration tool instead of adding more
// CREATE TABLE IF NOT EXISTS statements here.
const createTableSQL = `
CREATE TABLE IF NOT EXISTS axto_signing_keys (
	key_id       TEXT PRIMARY KEY,
	instance_id  TEXT NOT NULL,
	public_key   JSONB NOT NULL,
	published_at TIMESTAMPTZ NOT NULL,
	retire_at    TIMESTAMPTZ
)`

// PostgresRegistry is a Registry backed by a shared Postgres database --
// the intended backing store for a horizontally scaled Axto deployment.
type PostgresRegistry struct {
	db *sql.DB
}

// bootstrapLockKey is an arbitrary constant used with pg_advisory_lock to
// serialize schema bootstrap across every process racing to start up at
// once. Plain "CREATE TABLE IF NOT EXISTS" is not safe against concurrent
// callers -- Postgres can raise a duplicate-key error on its own catalog
// index when two sessions attempt the create at the same time, which is
// exactly the failure mode multiple Axto instances starting together will
// hit without this lock.
const bootstrapLockKey = 0x4178746f5f4b6579 // "AxtoKey" in hex, arbitrary

// NewPostgresRegistry opens a connection pool against dsn and ensures the
// backing table exists.
func NewPostgresRegistry(ctx context.Context, dsn string) (*PostgresRegistry, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("registry: open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("registry: ping postgres: %w", err)
	}
	if err := bootstrapSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &PostgresRegistry{db: db}, nil
}

// bootstrapSchema runs the CREATE TABLE under a session-scoped
// pg_advisory_lock so concurrently starting instances serialize instead of
// racing on Postgres's own catalog. The lock and the DDL must share one
// physical connection, hence db.Conn instead of db.ExecContext.
func bootstrapSchema(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("registry: acquire connection for schema bootstrap: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", bootstrapLockKey); err != nil {
		return fmt.Errorf("registry: acquire bootstrap lock: %w", err)
	}
	defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", bootstrapLockKey)

	if _, err := conn.ExecContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("registry: create table: %w", err)
	}
	return nil
}

func (r *PostgresRegistry) Close() error {
	return r.db.Close()
}

func (r *PostgresRegistry) Publish(ctx context.Context, rec PublicKeyRecord) error {
	jwkJSON, err := json.Marshal(rec.PublicKey)
	if err != nil {
		return fmt.Errorf("registry: marshal public key: %w", err)
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO axto_signing_keys (key_id, instance_id, public_key, published_at, retire_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (key_id) DO NOTHING`,
		rec.KeyID, rec.InstanceID, jwkJSON, rec.PublishedAt, rec.RetireAt)
	if err != nil {
		return fmt.Errorf("registry: publish %q: %w", rec.KeyID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("registry: publish %q: %w", rec.KeyID, err)
	}
	if n == 0 {
		return fmt.Errorf("registry: key %q already published", rec.KeyID)
	}
	return nil
}

func (r *PostgresRegistry) Retire(ctx context.Context, keyID string, retireAt time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE axto_signing_keys
		SET retire_at = CASE WHEN retire_at IS NULL OR $2 < retire_at THEN $2 ELSE retire_at END
		WHERE key_id = $1`,
		keyID, retireAt)
	if err != nil {
		return fmt.Errorf("registry: retire %q: %w", keyID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("registry: retire %q: %w", keyID, err)
	}
	if n == 0 {
		return fmt.Errorf("registry: key %q not found", keyID)
	}
	return nil
}

func (r *PostgresRegistry) ListServable(ctx context.Context, asOf time.Time) ([]PublicKeyRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT key_id, instance_id, public_key, published_at, retire_at
		FROM axto_signing_keys
		WHERE retire_at IS NULL OR retire_at > $1`,
		asOf)
	if err != nil {
		return nil, fmt.Errorf("registry: list servable: %w", err)
	}
	defer rows.Close()

	var out []PublicKeyRecord
	for rows.Next() {
		var (
			rec     PublicKeyRecord
			jwkJSON []byte
		)
		if err := rows.Scan(&rec.KeyID, &rec.InstanceID, &jwkJSON, &rec.PublishedAt, &rec.RetireAt); err != nil {
			return nil, fmt.Errorf("registry: scan row: %w", err)
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
			return nil, fmt.Errorf("registry: unmarshal public key %q: %w", rec.KeyID, err)
		}
		rec.PublicKey = jwk
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("registry: list servable: %w", err)
	}
	return out, nil
}
