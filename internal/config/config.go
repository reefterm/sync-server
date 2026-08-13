// Package config reads this server's settings from the environment, the
// usual way to configure something meant to run in a container.
package config

import (
	"os"
	"time"
)

type Config struct {
	// DBPath is where the SQLite file lives (or is created on first run).
	DBPath string
	// ListenAddr is host:port to listen on.
	ListenAddr string
	// AllowRegistration gates POST /api/v1/register. An operator who wants
	// to run this for a fixed set of people -- themselves, a household, a
	// small team -- can register everyone once and then close the door,
	// the same shape as Vaultwarden's SIGNUPS_ALLOWED.
	AllowRegistration bool
	// SessionTTL is how long a session token is valid before login is
	// required again.
	SessionTTL time.Duration
}

func Load() Config {
	return Config{
		DBPath:            getString("REEFTERM_SYNC_DB_PATH", "reefterm-sync.db"),
		ListenAddr:        getString("REEFTERM_SYNC_LISTEN_ADDR", ":8420"),
		AllowRegistration: getBool("REEFTERM_SYNC_ALLOW_REGISTRATION", true),
		SessionTTL:        getDuration("REEFTERM_SYNC_SESSION_TTL", 30*24*time.Hour),
	}
}

func getString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "True":
		return true
	case "0", "false", "FALSE", "False":
		return false
	default:
		return fallback
	}
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
