// Package config reads this server's settings from the environment, the
// usual way to configure something meant to run in a container.
package config

import (
	"os"
	"strconv"
	"time"

	"github.com/reefterm/sync-server/internal/mail"
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
	// RecoveryTokenTTL is how long an emailed recovery link is valid for.
	RecoveryTokenTTL time.Duration
	// SMTP is generic on purpose: every transactional-mail provider speaks
	// it (Zeptomail included, alongside its own API), and it is the only
	// option that also works for an operator relaying through their own
	// mail server. Email-based recovery (see internal/api's recover
	// handlers) is simply unavailable if this is left unset.
	SMTP mail.Config
}

func Load() Config {
	return Config{
		DBPath:            getString("REEFTERM_SYNC_DB_PATH", "reefterm-sync.db"),
		ListenAddr:        getString("REEFTERM_SYNC_LISTEN_ADDR", ":8420"),
		AllowRegistration: getBool("REEFTERM_SYNC_ALLOW_REGISTRATION", true),
		SessionTTL:        getDuration("REEFTERM_SYNC_SESSION_TTL", 30*24*time.Hour),
		RecoveryTokenTTL:  getDuration("REEFTERM_SYNC_RECOVERY_TOKEN_TTL", 30*time.Minute),
		SMTP: mail.Config{
			Host:               getString("REEFTERM_SYNC_SMTP_HOST", ""),
			Port:               getInt("REEFTERM_SYNC_SMTP_PORT", 587),
			Username:           getString("REEFTERM_SYNC_SMTP_USERNAME", ""),
			Password:           getString("REEFTERM_SYNC_SMTP_PASSWORD", ""),
			From:               getString("REEFTERM_SYNC_SMTP_FROM", ""),
			TLSMode:            mail.TLSMode(getString("REEFTERM_SYNC_SMTP_TLS", "starttls")),
			InsecureSkipVerify: getBool("REEFTERM_SYNC_SMTP_INSECURE_SKIP_VERIFY", false),
		},
	}
}

func getString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
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
