package domainconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Size represents UX modal dimensions.
type Size struct {
	Width, Height int
}

// Config holds Domain Connect settings for a domain.
type Config struct {
	Domain              string
	DomainRoot          string
	Host                string
	URLSyncUX           string
	URLAsyncUX          string
	URLAPI              string
	ProviderID          string
	ProviderName        string
	ProviderDisplayName string
	UXSize              *Size
	URLControlPanel     string
	Hosts               map[string]any
}

// Client is a Domain Connect client.
type Client struct {
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.httpClient = c
	}
}

// New creates a new Domain Connect client.
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// IdentifyDomainRoot extracts the registrable domain (eTLD+1) from a domain name.
func IdentifyDomainRoot(domain string) (string, error) {
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", fmt.Errorf("identify domain root: %w", err)
	}
	return root, nil
}

// GetDomainConfig discovers Domain Connect settings for a domain.
func (c *Client) GetDomainConfig(ctx context.Context, domain string) (*Config, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	domainRoot, err := IdentifyDomainRoot(domain)
	if err != nil {
		return nil, err
	}

	// Extract host (subdomain portion)
	host := ""
	if domain != domainRoot {
		host = strings.TrimSuffix(domain, "."+domainRoot)
	}

	// Look up _domainconnect TXT record
	dcHost, err := lookupDomainConnectRecord(ctx, domainRoot)
	if err != nil {
		return nil, err
	}

	// Fetch settings from the Domain Connect API
	settingsURL := fmt.Sprintf("https://%s/v2/%s/settings", dcHost, domainRoot)
	var settings struct {
		ProviderID          string      `json:"providerId"`
		ProviderName        string      `json:"providerName"`
		ProviderDisplayName string      `json:"providerDisplayName"`
		URLSyncUX           string      `json:"urlSyncUX"`
		URLAsyncUX          string      `json:"urlAsyncUX"`
		URLAPI              string      `json:"urlAPI"`
		Width               json.Number `json:"width"`
		Height              json.Number `json:"height"`
		URLControlPanel     string          `json:"urlControlPanel"`
		Hosts               json.RawMessage `json:"hosts"`
	}

	if err := c.doJSON(ctx, http.MethodGet, settingsURL, &settings); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDomainConnectSettings, err)
	}

	if settings.ProviderID == "" {
		return nil, ErrInvalidSettings
	}

	cfg := &Config{
		Domain:              domain,
		DomainRoot:          domainRoot,
		Host:                host,
		URLSyncUX:           settings.URLSyncUX,
		URLAsyncUX:          settings.URLAsyncUX,
		URLAPI:              settings.URLAPI,
		ProviderID:          settings.ProviderID,
		ProviderName:        settings.ProviderName,
		ProviderDisplayName: settings.ProviderDisplayName,
		URLControlPanel:     settings.URLControlPanel,
	}

	if len(settings.Hosts) > 0 {
		var hosts map[string]any
		if err := json.Unmarshal(settings.Hosts, &hosts); err == nil {
			cfg.Hosts = hosts
		}
	}

	if w, err := settings.Width.Int64(); err == nil && w > 0 {
		if h, err := settings.Height.Int64(); err == nil && h > 0 {
			cfg.UXSize = &Size{Width: int(w), Height: int(h)}
		}
	}

	return cfg, nil
}

// CheckTemplateSupported verifies the provider supports the given template.
func (c *Client) CheckTemplateSupported(ctx context.Context, cfg *Config, providerID string, serviceIDs []string) error {
	apiURL := cfg.URLAPI
	if apiURL == "" {
		apiURL = cfg.URLSyncUX
	}
	if apiURL == "" {
		return ErrInvalidSettings
	}

	baseURL := ensureScheme(apiURL)

	for _, serviceID := range serviceIDs {
		checkURL := fmt.Sprintf("%s/v2/domainTemplates/providers/%s/services/%s",
			baseURL, providerID, serviceID)

		var result struct {
			ProviderID string `json:"providerId"`
			ServiceID  string `json:"serviceId"`
		}
		if err := c.doJSON(ctx, http.MethodGet, checkURL, &result); err != nil {
			return fmt.Errorf("%w: %s/%s: %v", ErrTemplateNotSupported, providerID, serviceID, err)
		}
	}

	return nil
}

// SyncURLOptions configures sync URL generation.
type SyncURLOptions struct {
	Config        *Config
	ProviderID    string
	ServiceID     string
	Params        map[string]string
	RedirectURL   string
	State         string
	GroupIDs      []string
	PrivateKey    []byte // PEM-encoded RSA private key for signing
	KeyID         string
	ForceProvider bool
}

// GetSyncURL generates a synchronous Domain Connect URL.
func (c *Client) GetSyncURL(ctx context.Context, opts SyncURLOptions) (string, error) {
	cfg := opts.Config
	if cfg == nil {
		return "", ErrInvalidSettings
	}

	if cfg.URLSyncUX == "" {
		return "", ErrInvalidSettings
	}

	// Build base URL
	baseURL := fmt.Sprintf("%s/v2/domainTemplates/providers/%s/services/%s/apply",
		ensureScheme(cfg.URLSyncUX), opts.ProviderID, opts.ServiceID)

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("domain", cfg.DomainRoot)
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}

	// Add template params
	for k, v := range opts.Params {
		q.Set(k, v)
	}

	if opts.RedirectURL != "" {
		q.Set("redirect_uri", opts.RedirectURL)
	}
	if opts.State != "" {
		q.Set("state", opts.State)
	}

	// Add group IDs
	for _, gid := range opts.GroupIDs {
		q.Add("groupId", gid)
	}

	if opts.ForceProvider {
		q.Set("force", "1")
	}

	// Sign all query params (spec: sign everything except sig and key)
	if len(opts.PrivateKey) > 0 {
		sig, sigts, err := generateSignature(q, opts.PrivateKey, opts.KeyID)
		if err != nil {
			return "", fmt.Errorf("generate signature: %w", err)
		}
		q.Set("sigts", sigts)
		if opts.KeyID != "" {
			q.Set("key", opts.KeyID)
		}
		// sig must be last (Cloudflare requirement)
		u.RawQuery = q.Encode() + "&sig=" + sig
	} else {
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
