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

// PostgresRegistry is a Registry backed by a shared Postgres database --
// the intended backing store for a horizontally scaled Axto deployment.
type PostgresRegistry struct {
	db *sql.DB
}

// NewPostgresRegistry opens a connection pool against dsn and applies any
// pending migrations, matching every replica's own startup path.
func NewPostgresRegistry(ctx context.Context, dsn string) (*PostgresRegistry, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("registry: open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("registry: ping postgres: %w", err)
	}
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}
	return &PostgresRegistry{db: db}, nil
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
