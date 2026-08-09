package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration lets config files write "24h" instead of a raw nanosecond
// count. Cast to time.Duration to use it: time.Duration(cfg.Keys.Lifetime).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}
