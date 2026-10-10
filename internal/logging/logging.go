// Package logging configures structured slog loggers for hub, agent, and relay.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config controls log level and encoding.
// Defaults: level=info, format=text (readable on servers). Use format=json for collectors.
type Config struct {
	Level  string // info | debug
	Format string // text | json
}

// DefaultConfig returns operator-friendly defaults.
func DefaultConfig() Config {
	return Config{
		Level:  "info",
		Format: "text",
	}
}

// Normalize fills empty fields and lowercases level/format.
func (c *Config) Normalize() {
	d := DefaultConfig()
	if strings.TrimSpace(c.Level) == "" {
		c.Level = d.Level
	} else {
		c.Level = strings.ToLower(strings.TrimSpace(c.Level))
	}
	if strings.TrimSpace(c.Format) == "" {
		c.Format = d.Format
	} else {
		c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	}
}

// Validate checks level and format values.
func (c *Config) Validate() error {
	c.Normalize()
	switch c.Level {
	case "info", "debug":
	default:
		return fmt.Errorf("log_level must be info or debug (got %q)", c.Level)
	}
	switch c.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log_format must be text or json (got %q)", c.Format)
	}
	return nil
}

// New builds a slog.Logger writing to stdout (or w if non-nil).
func New(c Config, w io.Writer) (*slog.Logger, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if w == nil {
		w = os.Stdout
	}
	level := slog.LevelInfo
	if c.Level == "debug" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch c.Format {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("log_format must be text or json (got %q)", c.Format)
	}
	return slog.New(h), nil
}

// MustNew is like New but panics on invalid config (tests / early main only).
func MustNew(c Config, w io.Writer) *slog.Logger {
	log, err := New(c, w)
	if err != nil {
		panic(err)
	}
	return log
}
