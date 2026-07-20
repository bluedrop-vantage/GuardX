package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Client polls the Control API for bundles and pushes verified manifests
// through Updates.
type Client struct {
	HTTP         *http.Client
	BaseURL      string
	APIKey       string
	Tenant       string
	Environment  string
	Trust        TrustStore
	Interval     time.Duration
	Logger       *slog.Logger

	lastSeq   int64
	updatesCh chan *Manifest

	mu           sync.Mutex
	lastKnownOK  *Manifest
}

func NewClient(baseURL, apiKey, tenant, env string, trust TrustStore, interval time.Duration, logger *slog.Logger) *Client {
	return &Client{
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		BaseURL:     baseURL,
		APIKey:      apiKey,
		Tenant:      tenant,
		Environment: env,
		Trust:       trust,
		Interval:    interval,
		Logger:      logger,
		updatesCh:   make(chan *Manifest, 1),
	}
}

func (c *Client) Updates() <-chan *Manifest { return c.updatesCh }

func (c *Client) LastKnownGood() *Manifest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastKnownOK
}

// Run polls until ctx is done. Each poll that finds a newer verified bundle
// sends on Updates(). Errors are logged; policy stays at the last-known-good.
func (c *Client) Run(ctx context.Context) {
	// First tick immediately so the gateway warms up.
	c.tick(ctx)
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

func (c *Client) tick(ctx context.Context) {
	m, err := c.PollOnce(ctx)
	if err != nil {
		c.Logger.Warn("bundle poll failed", "err", err)
		return
	}
	if m == nil {
		return
	}
	c.mu.Lock()
	c.lastKnownOK = m
	c.mu.Unlock()

	select {
	case c.updatesCh <- m:
	default:
		// Coalesce — the consumer only needs the freshest.
		select {
		case <-c.updatesCh:
		default:
		}
		c.updatesCh <- m
	}
}

// PollOnce performs one bundle pull. Returns (nil, nil) when up to date.
func (c *Client) PollOnce(ctx context.Context) (*Manifest, error) {
	u := fmt.Sprintf(
		"%s/v1/bundles/%s?tenant=%s&since=%d",
		c.BaseURL, url.PathEscape(c.Environment), url.QueryEscape(c.Tenant), c.lastSeq,
	)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-GuardX-Key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bundle pull: status=%d body=%s", resp.StatusCode, body)
	}

	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("bundle pull: decode: %w", err)
	}

	m, err := Verify(&env, c.Trust)
	if err != nil {
		return nil, fmt.Errorf("bundle pull: verify: %w", err)
	}
	c.lastSeq = env.BundleSeq
	return m, nil
}

// BootstrapKey fetches the current signing pubkey from the Control API.
// Dev convenience — prod should pin.
func BootstrapKey(ctx context.Context, baseURL, apiKey, env string) (keyID string, pub ed25519.PublicKey, err error) {
	u := fmt.Sprintf("%s/v1/bundles/%s/signing-key", baseURL, url.PathEscape(env))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("X-GuardX-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, errors.New("bootstrap key: non-200")
	}
	var body struct {
		KeyID       string `json:"key_id"`
		Algorithm   string `json:"algorithm"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(body.PublicKeyB64)
	if err != nil {
		return "", nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("bad pubkey length %d", len(raw))
	}
	return body.KeyID, ed25519.PublicKey(raw), nil
}

// ParseSeqHeader is a small helper for tests / external tools.
func ParseSeqHeader(h http.Header) int64 {
	if v := h.Get("X-Bundle-Seq"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}
