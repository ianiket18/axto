// Package config loads Axto's YAML config files. Each binary has its own
// config type here; adding a new setting means adding a field to the
// relevant struct and, if it needs one, a default in that struct's
// applyDefaults.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DatabaseConfig is shared by every binary that talks to the key registry.
type DatabaseConfig struct {
	URL string `yaml:"url"`
}

// KeyLifecycleConfig controls keys.ManagedStore's timing.
type KeyLifecycleConfig struct {
	Lifetime      Duration `yaml:"lifetime"`
	CheckInterval Duration `yaml:"checkInterval"`
	MaxTokenTTL   Duration `yaml:"maxTokenTTL"`
}

// SignerConfig configures cmd/axto.
type SignerConfig struct {
	Addr          string             `yaml:"addr"`
	InternalToken string             `yaml:"internalToken"`
	InstanceID    string             `yaml:"instanceId"`
	Database      DatabaseConfig     `yaml:"database"`
	Keys          KeyLifecycleConfig `yaml:"keys"`
}

// AggregatorConfig configures cmd/axto-jwks.
type AggregatorConfig struct {
	Addr         string         `yaml:"addr"`
	Database     DatabaseConfig `yaml:"database"`
	JWKSCacheTTL Duration       `yaml:"jwksCacheTTL"`
}

func LoadSignerConfig(path string) (*SignerConfig, error) {
	var cfg SignerConfig
	if err := loadYAML(path, &cfg); err != nil {
		return nil, err
	}
	cfg.InternalToken = resolveSecret(cfg.InternalToken)
	cfg.Database.URL = resolveSecret(cfg.Database.URL)
	cfg.applyDefaults()
	return &cfg, nil
}

func LoadAggregatorConfig(path string) (*AggregatorConfig, error) {
	var cfg AggregatorConfig
	if err := loadYAML(path, &cfg); err != nil {
		return nil, err
	}
	cfg.Database.URL = resolveSecret(cfg.Database.URL)
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *SignerConfig) applyDefaults() {
	if c.Addr == "" {
		c.Addr = ":8090"
	}
	if c.Keys.Lifetime == 0 {
		c.Keys.Lifetime = Duration(24 * time.Hour)
	}
	if c.Keys.CheckInterval == 0 {
		c.Keys.CheckInterval = Duration(time.Minute)
	}
	if c.Keys.MaxTokenTTL == 0 {
		c.Keys.MaxTokenTTL = Duration(15 * time.Minute)
	}
}

func (c *AggregatorConfig) applyDefaults() {
	if c.Addr == "" {
		c.Addr = ":8091"
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = Duration(10 * time.Second)
	}
}

func loadYAML(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

// resolveSecret lets a config value of the form "env:VAR_NAME" be read
// from the environment instead of written in the file, so secrets don't
// have to sit in a file on disk. This is the one extension point for
// pulling values from somewhere other than the file; a future "file:" or
// secret-manager prefix would follow the same pattern.
func resolveSecret(v string) string {
	const prefix = "env:"
	if strings.HasPrefix(v, prefix) {
		return os.Getenv(strings.TrimPrefix(v, prefix))
	}
	return v
}
