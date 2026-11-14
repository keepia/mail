package config

import (
	"log/slog"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c := Load(env(nil))
	if c.Listen != DefaultListen || c.LogLevel != DefaultLogLevel || c.DatabaseURL != "" || c.KEKFile != "/var/lib/keepia/kek/kek" ||
		c.ControlGateDir != "/var/lib/keepia/control-gate" {
		t.Errorf("defaults: %+v", c)
	}
	c = Load(env(map[string]string{
		EnvDatabaseURL:    "postgres://db/keepia",
		EnvListen:         "0.0.0.0:9000",
		EnvLogLevel:       "debug",
		EnvKEKFile:        "/k/kek",
		EnvControlGateDir: "/k/gate",
	}))
	if c.Listen != "0.0.0.0:9000" || c.LogLevel != "debug" || c.DatabaseURL != "postgres://db/keepia" || c.KEKFile != "/k/kek" ||
		c.ControlGateDir != "/k/gate" {
		t.Errorf("from the environment: %+v", c)
	}
}

func TestRequireDatabaseURL(t *testing.T) {
	_, err := Load(env(nil)).RequireDatabaseURL()
	if err == nil || !strings.Contains(err.Error(), EnvDatabaseURL) {
		t.Errorf("missing URL: %v, want an error naming %s", err, EnvDatabaseURL)
	}
	u, err := Load(env(map[string]string{EnvDatabaseURL: "postgres://db/keepia"})).RequireDatabaseURL()
	if err != nil || u != "postgres://db/keepia" {
		t.Errorf("set URL: %q, %v", u, err)
	}
}

func TestCheckListen(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", ":8080", "[::1]:0", "localhost:65535"} {
		if err := CheckListen(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "nope", "127.0.0.1", "127.0.0.1:http", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:+80", "127.0.0.1:080"} {
		if err := CheckListen(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseLogLevel(t *testing.T) {
	if l, err := ParseLogLevel("warn"); err != nil || l != slog.LevelWarn {
		t.Errorf("warn: %v, %v", l, err)
	}
	if _, err := ParseLogLevel("loud"); err == nil || !strings.Contains(err.Error(), EnvLogLevel) {
		t.Errorf("loud: %v", err)
	}
}
