package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadSignerConfig_AppliesDefaultsForOmittedFields(t *testing.T) {
	path := writeTempConfig(t, `internalToken: s3cret`)

	cfg, err := LoadSignerConfig(path)
	if err != nil {
		t.Fatalf("LoadSignerConfig: %v", err)
	}
	if cfg.Addr != ":8090" {
		t.Errorf("expected default addr, got %q", cfg.Addr)
	}
	if time.Duration(cfg.Keys.Lifetime) != 24*time.Hour {
		t.Errorf("expected default key lifetime of 24h, got %v", time.Duration(cfg.Keys.Lifetime))
	}
	if time.Duration(cfg.Keys.CheckInterval) != time.Minute {
		t.Errorf("expected default check interval of 1m, got %v", time.Duration(cfg.Keys.CheckInterval))
	}
	if time.Duration(cfg.Keys.MaxTokenTTL) != 15*time.Minute {
		t.Errorf("expected default max token TTL of 15m, got %v", time.Duration(cfg.Keys.MaxTokenTTL))
	}
	if cfg.InternalToken != "s3cret" {
		t.Errorf("expected internalToken to be read from the file, got %q", cfg.InternalToken)
	}
}

func TestLoadSignerConfig_ExplicitValuesOverrideDefaults(t *testing.T) {
	path := writeTempConfig(t, `
addr: :9999
internalToken: s3cret
instanceId: signer-a
database:
  url: postgres://localhost/axto
keys:
  lifetime: 1h
  checkInterval: 10s
  maxTokenTTL: 5m
`)

	cfg, err := LoadSignerConfig(path)
	if err != nil {
		t.Fatalf("LoadSignerConfig: %v", err)
	}
	if cfg.Addr != ":9999" {
		t.Errorf("expected explicit addr to win, got %q", cfg.Addr)
	}
	if cfg.InstanceID != "signer-a" {
		t.Errorf("expected instanceId to be read, got %q", cfg.InstanceID)
	}
	if cfg.Database.URL != "postgres://localhost/axto" {
		t.Errorf("expected database url to be read, got %q", cfg.Database.URL)
	}
	if time.Duration(cfg.Keys.Lifetime) != time.Hour {
		t.Errorf("expected explicit lifetime to win, got %v", time.Duration(cfg.Keys.Lifetime))
	}
}

func TestLoadSignerConfig_ResolvesEnvPrefixedSecrets(t *testing.T) {
	t.Setenv("AXTO_TEST_TOKEN", "from-env")
	t.Setenv("AXTO_TEST_DSN", "postgres://from-env")
	path := writeTempConfig(t, `
internalToken: "env:AXTO_TEST_TOKEN"
database:
  url: "env:AXTO_TEST_DSN"
`)

	cfg, err := LoadSignerConfig(path)
	if err != nil {
		t.Fatalf("LoadSignerConfig: %v", err)
	}
	if cfg.InternalToken != "from-env" {
		t.Errorf("expected internalToken resolved from env, got %q", cfg.InternalToken)
	}
	if cfg.Database.URL != "postgres://from-env" {
		t.Errorf("expected database url resolved from env, got %q", cfg.Database.URL)
	}
}

func TestLoadSignerConfig_MissingFileFails(t *testing.T) {
	if _, err := LoadSignerConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestLoadSignerConfig_InvalidDurationFails(t *testing.T) {
	path := writeTempConfig(t, `
keys:
  lifetime: "not-a-duration"
`)
	if _, err := LoadSignerConfig(path); err == nil {
		t.Fatal("expected an error for an invalid duration")
	}
}

func TestLoadAggregatorConfig_AppliesDefaults(t *testing.T) {
	path := writeTempConfig(t, `database: {url: postgres://localhost/axto}`)

	cfg, err := LoadAggregatorConfig(path)
	if err != nil {
		t.Fatalf("LoadAggregatorConfig: %v", err)
	}
	if cfg.Addr != ":8091" {
		t.Errorf("expected default addr, got %q", cfg.Addr)
	}
	if time.Duration(cfg.JWKSCacheTTL) != 10*time.Second {
		t.Errorf("expected default cache TTL of 10s, got %v", time.Duration(cfg.JWKSCacheTTL))
	}
}
