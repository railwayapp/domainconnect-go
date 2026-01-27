package domainconnect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AsyncContext holds state for async Domain Connect flow.
type AsyncContext struct {
	Config               *Config
	ProviderID           string
	ServiceID            string
	AsyncConsentURL      string
	Code                 string
	Params               map[string]string
	ReturnURL            string
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresIn int
	IssuedAt             int64
}

// AsyncCredentials holds OAuth client credentials.
type AsyncCredentials struct {
	ClientID     string
	ClientSecret string
	APIURL       string
}

// AsyncContextOptions configures async context creation.
type AsyncContextOptions struct {
	Config      *Config
	ProviderID  string
	ServiceID   string
	Params      map[string]string
	RedirectURL string
	State       string
	GroupIDs    []string
}

// GetAsyncContext creates an async context with consent URL.
func (c *Client) GetAsyncContext(ctx context.Context, opts AsyncContextOptions) (*AsyncContext, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, ErrInvalidSettings
	}

	if cfg.URLAsyncUX == "" {
		return nil, ErrInvalidSettings
	}

	// Build consent URL
	baseURL := fmt.Sprintf("%s/v2/domainTemplates/providers/%s",
		ensureScheme(cfg.URLAsyncUX), opts.ProviderID)

	// Add service IDs
	if opts.ServiceID != "" {
		baseURL += "?services=" + opts.ServiceID
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("domain", cfg.DomainRoot)
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}

	if opts.RedirectURL != "" {
		q.Set("redirect_uri", opts.RedirectURL)
	}
	if opts.State != "" {
		q.Set("state", opts.State)
	}

	// Add params
	for k, v := range opts.Params {
		q.Set(k, v)
	}

	// Add group IDs
	for _, gid := range opts.GroupIDs {
		q.Add("groupId", gid)
	}

	u.RawQuery = q.Encode()

	return &AsyncContext{
		Config:          cfg,
		ProviderID:      opts.ProviderID,
		ServiceID:       opts.ServiceID,
		AsyncConsentURL: u.String(),
		Params:          opts.Params,
		ReturnURL:       opts.RedirectURL,
	}, nil
}

// GetAsyncToken exchanges auth code for access token.
func (c *Client) GetAsyncToken(ctx context.Context, asyncCtx *AsyncContext, creds AsyncCredentials) (*AsyncContext, error) {
	if asyncCtx.Code == "" {
		return nil, fmt.Errorf("%w: no authorization code", ErrAsyncToken)
	}

	apiURL := creds.APIURL
	if apiURL == "" {
		apiURL = asyncCtx.Config.URLAPI
	}
	if apiURL == "" {
		return nil, fmt.Errorf("%w: no API URL", ErrAsyncToken)
	}

	tokenURL := fmt.Sprintf("%s/v2/oauth/access_token", ensureScheme(apiURL))

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", asyncCtx.Code)
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)
	if asyncCtx.ReturnURL != "" {
		data.Set("redirect_uri", asyncCtx.ReturnURL)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := c.postForm(ctx, tokenURL, data, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAsyncToken, err)
	}

	asyncCtx.AccessToken = tokenResp.AccessToken
	asyncCtx.RefreshToken = tokenResp.RefreshToken
	asyncCtx.AccessTokenExpiresIn = tokenResp.ExpiresIn
	asyncCtx.IssuedAt = time.Now().Unix()

	return asyncCtx, nil
}

// RefreshAsyncToken refreshes an expired access token.
func (c *Client) RefreshAsyncToken(ctx context.Context, asyncCtx *AsyncContext, creds AsyncCredentials) (*AsyncContext, error) {
	if asyncCtx.RefreshToken == "" {
		return nil, fmt.Errorf("%w: no refresh token", ErrAsyncToken)
	}

	apiURL := creds.APIURL
	if apiURL == "" {
		apiURL = asyncCtx.Config.URLAPI
	}
	if apiURL == "" {
		return nil, fmt.Errorf("%w: no API URL", ErrAsyncToken)
	}

	tokenURL := fmt.Sprintf("%s/v2/oauth/access_token", ensureScheme(apiURL))

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", asyncCtx.RefreshToken)
	data.Set("client_id", creds.ClientID)
	data.Set("client_secret", creds.ClientSecret)

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := c.postForm(ctx, tokenURL, data, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAsyncToken, err)
	}

	asyncCtx.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		asyncCtx.RefreshToken = tokenResp.RefreshToken
	}
	asyncCtx.AccessTokenExpiresIn = tokenResp.ExpiresIn
	asyncCtx.IssuedAt = time.Now().Unix()

	return asyncCtx, nil
}

// ApplyAsyncOptions configures async template application.
type ApplyAsyncOptions struct {
	ServiceID   string
	Params      map[string]string
	GroupIDs    []string
	ForceUpdate bool
	PrivateKey  []byte
	KeyID       string
}

// ApplyAsync applies a template using async credentials.
func (c *Client) ApplyAsync(ctx context.Context, asyncCtx *AsyncContext, opts ApplyAsyncOptions) error {
	if asyncCtx.AccessToken == "" {
		return fmt.Errorf("%w: no access token", ErrApply)
	}

	cfg := asyncCtx.Config
	apiURL := cfg.URLAPI
	if apiURL == "" {
		return fmt.Errorf("%w: no API URL", ErrApply)
	}

	serviceID := opts.ServiceID
	if serviceID == "" {
		serviceID = asyncCtx.ServiceID
	}

	applyURL := fmt.Sprintf("%s/v2/domainTemplates/providers/%s/services/%s/apply",
		ensureScheme(apiURL), asyncCtx.ProviderID, serviceID)

	u, err := url.Parse(applyURL)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("domain", cfg.DomainRoot)
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}

	// Merge params from context and options
	params := make(map[string]string)
	for k, v := range asyncCtx.Params {
		params[k] = v
	}
	for k, v := range opts.Params {
		params[k] = v
	}

	for k, v := range params {
		q.Set(k, v)
	}

	for _, gid := range opts.GroupIDs {
		q.Add("groupId", gid)
	}

	if opts.ForceUpdate {
		q.Set("force", "1")
	}

	// Sign if private key provided
	if len(opts.PrivateKey) > 0 {
		sigParams, err := generateSignature(cfg.DomainRoot, cfg.Host, params, opts.PrivateKey, opts.KeyID)
		if err != nil {
			return fmt.Errorf("generate signature: %w", err)
		}
		for k, v := range sigParams {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+asyncCtx.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return ErrConflictOnApply
	default:
		return fmt.Errorf("%w: HTTP %d", ErrApply, resp.StatusCode)
	}
}

// TokenValid checks if the access token is still valid.
func (a *AsyncContext) TokenValid() bool {
	if a.AccessToken == "" {
		return false
	}
	if a.AccessTokenExpiresIn == 0 {
		return true // No expiry set
	}
	expiresAt := a.IssuedAt + int64(a.AccessTokenExpiresIn)
	return time.Now().Unix() < expiresAt
}

// DeleteAsync removes records applied by a template.
func (c *Client) DeleteAsync(ctx context.Context, asyncCtx *AsyncContext, serviceID string) error {
	if asyncCtx.AccessToken == "" {
		return fmt.Errorf("%w: no access token", ErrApply)
	}

	cfg := asyncCtx.Config
	apiURL := cfg.URLAPI
	if apiURL == "" {
		return fmt.Errorf("%w: no API URL", ErrApply)
	}

	if serviceID == "" {
		serviceID = asyncCtx.ServiceID
	}

	deleteURL := fmt.Sprintf("%s/v2/domainTemplates/providers/%s/services/%s/apply",
		ensureScheme(apiURL), asyncCtx.ProviderID, serviceID)

	u, err := url.Parse(deleteURL)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("domain", cfg.DomainRoot)
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+asyncCtx.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: HTTP %d", ErrApply, resp.StatusCode)
	}

	return nil
}

// parseCallbackURL extracts code and state from OAuth callback URL.
func ParseCallbackURL(callbackURL string) (code, state string, err error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", "", err
	}

	q := u.Query()
	if errParam := q.Get("error"); errParam != "" {
		errDesc := q.Get("error_description")
		if errDesc != "" {
			return "", "", fmt.Errorf("%s: %s", errParam, errDesc)
		}
		return "", "", fmt.Errorf("%s", errParam)
	}

	code = q.Get("code")
	state = q.Get("state")

	if code == "" {
		return "", "", fmt.Errorf("missing authorization code")
	}

	return code, state, nil
}

// SetCodeFromCallback is a helper to set code on AsyncContext from callback URL.
func (a *AsyncContext) SetCodeFromCallback(callbackURL string) error {
	code, _, err := ParseCallbackURL(callbackURL)
	if err != nil {
		return err
	}
	a.Code = code
	return nil
}

// BuildAsyncConsentURL is a helper to build the consent URL with additional parameters.
func (a *AsyncContext) BuildAsyncConsentURL(clientID string, scope string) string {
	u, err := url.Parse(a.AsyncConsentURL)
	if err != nil {
		return a.AsyncConsentURL
	}

	q := u.Query()
	q.Set("client_id", clientID)
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// ServiceIDsFromCallback extracts granted service IDs from callback.
func ServiceIDsFromCallback(callbackURL string) ([]string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, err
	}

	granted := u.Query().Get("granted")
	if granted == "" {
		return nil, nil
	}

	return strings.Split(granted, ","), nil
}
