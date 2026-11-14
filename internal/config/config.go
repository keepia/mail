// Package config reads Keepia Mail's configuration from the environment.
// Each command loads it and checks only what it needs, so a command that
// needs no database also runs without a database URL.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// Environment variables.
const (
	// EnvDatabaseURL is the PostgreSQL URL, required by serve and migrate.
	// It holds the database password: it is never logged.
	EnvDatabaseURL = "KEEPIA_DATABASE_URL"
	// EnvListen is the HTTP listen address (host:port), default
	// DefaultListen.
	EnvListen = "KEEPIA_LISTEN"
	// EnvLogLevel is the log level (debug, info, warn, error), default
	// DefaultLogLevel.
	EnvLogLevel = "KEEPIA_LOG_LEVEL"
	// EnvKEKFile is the key-encryption key's file (#96, CD1), default
	// DefaultKEKFile. serve creates it at its first start; its kek.new
	// lives next to it.
	EnvKEKFile = "KEEPIA_KEK_FILE"
)

// Defaults.
const (
	DefaultListen   = "127.0.0.1:8080"
	DefaultLogLevel = "info"
	// DefaultKEKFile is the KEK file on the volume keepia-kek.
	DefaultKEKFile = "/var/lib/keepia/kek/kek"
)

// Config is Keepia Mail's configuration.
type Config struct {
	DatabaseURL string
	Listen      string
	LogLevel    string
	KEKFile     string
}

// Load reads the configuration with getenv (os.Getenv outside tests) and
// fills in the defaults. It checks nothing; see RequireDatabaseURL,
// CheckListen and ParseLogLevel.
func Load(getenv func(string) string) Config {
	c := Config{
		DatabaseURL: getenv(EnvDatabaseURL),
		Listen:      getenv(EnvListen),
		LogLevel:    getenv(EnvLogLevel),
		KEKFile:     getenv(EnvKEKFile),
	}
	if c.KEKFile == "" {
		c.KEKFile = DefaultKEKFile
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	return c
}

// RequireDatabaseURL returns the database URL, or an error naming
// EnvDatabaseURL when it is not set.
func (c Config) RequireDatabaseURL() (string, error) {
	if c.DatabaseURL == "" {
		return "", errors.New(EnvDatabaseURL + " is not set: it must hold the PostgreSQL URL")
	}
	return c.DatabaseURL, nil
}

// CheckListen checks that addr is a host:port listen address with a
// numeric port (0 picks a free one).
func CheckListen(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: want host:port: %w", addr, err)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || port != strconv.FormatUint(n, 10) {
		return fmt.Errorf("listen address %q: port must be a number from 0 to 65535", addr)
	}
	return nil
}

// ParseLogLevel parses a log level: debug, info, warn or error.
func ParseLogLevel(level string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return 0, fmt.Errorf("%s %q: want debug, info, warn or error", EnvLogLevel, level)
	}
	return l, nil
}
