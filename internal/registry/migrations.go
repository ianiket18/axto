package registry

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// runMigrations applies every pending migration to db. It's called on
// every NewPostgresRegistry, so it must be safe against several processes
// calling it at once -- golang-migrate's Postgres driver takes a session
// advisory lock around the run, so concurrent callers serialize instead
// of racing on schema DDL.
func runMigrations(db *sql.DB) error {
	source, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("registry: load embedded migrations: %w", err)
	}
	driver, err := pgmigrate.WithInstance(db, &pgmigrate.Config{})
	if err != nil {
		return fmt.Errorf("registry: init migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("registry: init migrator: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("registry: run migrations: %w", err)
	}
	return nil
}
