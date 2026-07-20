// Package config parses gateway configuration from environment variables.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr             string
	ControlBaseURL   string
	ControlAPIKey    string
	Tenant           string
	Environment      string
	SigningKeyID     string
	SigningPublicKey ed25519.PublicKey
	UpstreamBaseURL  string
	PollInterval     time.Duration
	StaleBundleGrace time.Duration
}

// Load reads config from GUARDX_* environment variables.
// See deploy/compose/docker-compose.yml for the canonical dev set.
func Load() (*Config, error) {
	c := &Config{
		Addr:             getenv("GUARDX_GATEWAY_ADDR", ":8081"),
		ControlBaseURL:   getenv("GUARDX_CONTROL_BASE_URL", "http://control:8080"),
		ControlAPIKey:    getenv("GUARDX_CONTROL_API_KEY", "dev-service-key"),
		Tenant:           getenv("GUARDX_TENANT", "acme"),
		Environment:      getenv("GUARDX_ENV", "prod"),
		SigningKeyID:     getenv("GUARDX_SIGNING_KEY_ID", "dev-local"),
		UpstreamBaseURL:  getenv("GUARDX_UPSTREAM_BASE_URL", "http://upstream:9000"),
		PollInterval:     mustDur("GUARDX_BUNDLE_POLL_INTERVAL", "2s"),
		StaleBundleGrace: mustDur("GUARDX_STALE_BUNDLE_GRACE", "72h"),
	}

	// Public key bootstrap: either base64 in env, or file path.
	if b64 := os.Getenv("GUARDX_SIGNING_PUBLIC_KEY_B64"); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("signing public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing public key: wrong length %d", len(raw))
		}
		c.SigningPublicKey = ed25519.PublicKey(raw)
	} else if path := os.Getenv("GUARDX_SIGNING_PUBLIC_KEY_PATH"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("signing public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing public key: wrong length %d (path=%s)", len(raw), path)
		}
		c.SigningPublicKey = ed25519.PublicKey(raw)
	}
	// If neither is set, the gateway will bootstrap from Control API's
	// /signing-key endpoint on first poll (dev convenience — Prod should pin).

	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustDur(k, def string) time.Duration {
	v := getenv(k, def)
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(fmt.Errorf("bad duration %s=%s: %w", k, v, err))
	}
	return d
}

// GetenvInt is a convenience for optional numeric config.
func GetenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
