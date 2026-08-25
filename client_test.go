package domainconnect

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestIdentifyDomainRoot(t *testing.T) {
	// Test cases from Python test_get_domain_root
	tests := []struct {
		domain   string
		expected string
		wantErr  bool
	}{
		{"example.com", "example.com", false},
		{"www.example.com", "example.com", false},
		{"sub.www.example.com", "example.com", false},
		{"example.co.uk", "example.co.uk", false},
		{"www.example.co.uk", "example.co.uk", false},
		{"sub.www.example.co.uk", "example.co.uk", false},
		{"example.com.au", "example.com.au", false},
		{"www.example.com.au", "example.com.au", false},
		{"example.org", "example.org", false},
		{"deep.sub.example.org", "example.org", false},
		{"Example.COM", "example.com", false},
		{".example.com", "example.com", false},
		{"example.com.", "example.com", false},
		{".example.com.", "example.com", false},
		// Public suffix list special cases
		{"example.blogspot.com", "example.blogspot.com", false},
		{"www.example.blogspot.com", "example.blogspot.com", false},
		{"example.github.io", "example.github.io", false},
		{"app.example.github.io", "example.github.io", false},
		// Error cases
		{"com", "", true},
		{"", "", true},
		{"co.uk", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result, err := IdentifyDomainRoot(tt.domain)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tt.domain)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.domain, err)
				return
			}
			if result != tt.expected {
				t.Errorf("IdentifyDomainRoot(%q) = %q, want %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestGenerateSignature(t *testing.T) {
	privateKey, pub := loadTestKey(t)

	query := "IP=192.168.1.1&RANDOMID=abc123&domain=example.com&host=www"
	sig, err := generateSignature(query, privateKey)
	if err != nil {
		t.Fatalf("generateSignature failed: %v", err)
	}
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify signature is standard base64 (not base64url) and verifies over the query
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("sig should be standard base64, got %q: %v", sig, err)
	}
	hash := sha256.Sum256([]byte(query))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], raw); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestGenerateSignature_NoHost(t *testing.T) {
	privateKey, pub := loadTestKey(t)

	client := New()
	u, err := client.GetSyncURL(context.Background(), SyncURLOptions{
		Config: &Config{
			DomainRoot: "example.com",
			URLSyncUX:  "connect.provider.com",
		},
		ProviderID: "provider1",
		ServiceID:  "svc1",
		Params:     map[string]string{"IP": "1.2.3.4"},
		PrivateKey: privateKey,
		KeyID:      "key1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if parsed.Query().Has("host") {
		t.Errorf("apex request should not carry an empty host param: %q", parsed.RawQuery)
	}

	verifyAsDNSProvider(t, parsed.RawQuery, pub)
}

func TestGetSyncURL_InvalidDomain(t *testing.T) {
	client := New()

	_, err := client.GetSyncURL(context.Background(), SyncURLOptions{
		Config:     nil,
		ProviderID: "test",
		ServiceID:  "test",
	})

	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestGetSyncURL(t *testing.T) {
	// Test cases inspired by Python test_get_domain_connect_template_sync_url
	tests := []struct {
		name     string
		opts     SyncURLOptions
		contains []string
	}{
		{
			name: "basic",
			opts: SyncURLOptions{
				Config: &Config{
					DomainRoot: "example.com",
					URLSyncUX:  "connect.provider.com",
				},
				ProviderID: "exampleservice",
				ServiceID:  "template1",
			},
			contains: []string{
				"https://connect.provider.com/v2/domainTemplates/providers/exampleservice/services/template1/apply",
				"domain=example.com",
			},
		},
		{
			name: "with_host",
			opts: SyncURLOptions{
				Config: &Config{
					DomainRoot: "example.com",
					Host:       "www",
					URLSyncUX:  "connect.provider.com",
				},
				ProviderID: "provider1",
				ServiceID:  "svc1",
			},
			contains: []string{
				"domain=example.com",
				"host=www",
			},
		},
		{
			name: "with_params",
			opts: SyncURLOptions{
				Config: &Config{
					DomainRoot: "example.com",
					URLSyncUX:  "connect.provider.com",
				},
				ProviderID: "provider1",
				ServiceID:  "svc1",
				Params: map[string]string{
					"IP":   "1.2.3.4",
					"name": "test",
				},
			},
			contains: []string{
				"IP=1.2.3.4",
				"name=test",
			},
		},
		{
			name: "with_redirect",
			opts: SyncURLOptions{
				Config: &Config{
					DomainRoot: "example.com",
					URLSyncUX:  "connect.provider.com",
				},
				ProviderID:  "provider1",
				ServiceID:   "svc1",
				RedirectURL: "https://myapp.com/callback",
				State:       "mystate123",
			},
			contains: []string{
				"redirect_uri=https",
				"state=mystate123",
			},
		},
		{
			name: "with_group_ids",
			opts: SyncURLOptions{
				Config: &Config{
					DomainRoot: "example.com",
					URLSyncUX:  "connect.provider.com",
				},
				ProviderID: "provider1",
				ServiceID:  "svc1",
				GroupIDs:   []string{"group1", "group2"},
			},
			contains: []string{
				"groupId=group1",
				"groupId=group2",
			},
		},
	}

	client := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := client.GetSyncURL(context.Background(), tt.opts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, substr := range tt.contains {
				if !strings.Contains(url, substr) {
					t.Errorf("URL %q should contain %q", url, substr)
				}
			}
		})
	}
}

func TestGetSyncURL_WithSignature(t *testing.T) {
	privateKey, err := os.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}

	client := New()

	url, err := client.GetSyncURL(context.Background(), SyncURLOptions{
		Config: &Config{
			DomainRoot: "example.com",
			Host:       "mail",
			URLSyncUX:  "connect.provider.com",
		},
		ProviderID: "provider1",
		ServiceID:  "svc1",
		Params:     map[string]string{"IP": "1.2.3.4"},
		PrivateKey: privateKey,
		KeyID:      "1",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(url, "sig=") {
		t.Error("URL should contain sig parameter")
	}
	if !strings.Contains(url, "key=1") {
		t.Error("URL should contain key parameter")
	}
}

// Integration test - tests against real Domain Connect enabled domains
func TestGetDomainConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := New()
	ctx := context.Background()

	// diabtrack.com is the official Domain Connect test domain
	cfg, err := client.GetDomainConfig(ctx, "diabtrack.com")
	if err != nil {
		t.Fatalf("GetDomainConfig failed: %v", err)
	}

	if cfg.ProviderID == "" {
		t.Error("expected non-empty provider ID")
	}
	if cfg.DomainRoot != "diabtrack.com" {
		t.Errorf("DomainRoot = %q, want %q", cfg.DomainRoot, "diabtrack.com")
	}
	if cfg.URLSyncUX == "" && cfg.URLAsyncUX == "" {
		t.Error("expected at least one UX URL")
	}

	t.Logf("Provider: %s (%s)", cfg.ProviderName, cfg.ProviderID)
	t.Logf("SyncUX: %s", cfg.URLSyncUX)
	t.Logf("AsyncUX: %s", cfg.URLAsyncUX)
	t.Logf("API: %s", cfg.URLAPI)
}

func TestGetDomainConfig_WithHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := New()
	ctx := context.Background()

	// Test subdomain extraction
	cfg, err := client.GetDomainConfig(ctx, "www.diabtrack.com")
	if err != nil {
		t.Fatalf("GetDomainConfig failed: %v", err)
	}

	if cfg.DomainRoot != "diabtrack.com" {
		t.Errorf("DomainRoot = %q, want %q", cfg.DomainRoot, "diabtrack.com")
	}
	if cfg.Host != "www" {
		t.Errorf("Host = %q, want %q", cfg.Host, "www")
	}
}

func TestGetDomainConfig_InvalidDomain(t *testing.T) {
	client := New()
	ctx := context.Background()

	// Domain that doesn't support Domain Connect
	_, err := client.GetDomainConfig(ctx, "google.com")
	if err == nil {
		t.Error("expected error for domain without Domain Connect")
	}
}

func TestGetAsyncContext(t *testing.T) {
	client := New()

	asyncCtx, err := client.GetAsyncContext(context.Background(), AsyncContextOptions{
		Config: &Config{
			DomainRoot: "example.com",
			Host:       "www",
			URLAsyncUX: "async.provider.com",
		},
		ProviderID:  "provider1",
		ServiceID:   "svc1",
		RedirectURL: "https://myapp.com/callback",
		State:       "state123",
		Params: map[string]string{
			"IP": "1.2.3.4",
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if asyncCtx.ProviderID != "provider1" {
		t.Errorf("expected providerID=provider1, got %q", asyncCtx.ProviderID)
	}
	if asyncCtx.ServiceID != "svc1" {
		t.Errorf("expected serviceID=svc1, got %q", asyncCtx.ServiceID)
	}

	url := asyncCtx.AsyncConsentURL
	if !strings.Contains(url, "https://async.provider.com/v2/domainTemplates/providers/provider1") {
		t.Errorf("unexpected consent URL: %s", url)
	}
	if !strings.Contains(url, "domain=example.com") {
		t.Error("consent URL should contain domain")
	}
	if !strings.Contains(url, "host=www") {
		t.Error("consent URL should contain host")
	}
	if !strings.Contains(url, "redirect_uri=") {
		t.Error("consent URL should contain redirect_uri")
	}
	if !strings.Contains(url, "state=state123") {
		t.Error("consent URL should contain state")
	}
}

func TestGetAsyncContext_NoHost(t *testing.T) {
	client := New()

	asyncCtx, err := client.GetAsyncContext(context.Background(), AsyncContextOptions{
		Config: &Config{
			DomainRoot: "example.com",
			URLAsyncUX: "async.provider.com",
		},
		ProviderID: "provider1",
		ServiceID:  "svc1",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	url := asyncCtx.AsyncConsentURL
	if strings.Contains(url, "host=") {
		t.Error("consent URL should not contain host when empty")
	}
}

func TestGetAsyncContext_NoAsyncURL(t *testing.T) {
	client := New()

	_, err := client.GetAsyncContext(context.Background(), AsyncContextOptions{
		Config: &Config{
			DomainRoot: "example.com",
			URLSyncUX:  "sync.provider.com",
			// URLAsyncUX is empty
		},
		ProviderID: "provider1",
		ServiceID:  "svc1",
	})

	if err == nil {
		t.Error("expected error when URLAsyncUX is empty")
	}
}

func TestParseCallbackURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantCode  string
		wantState string
		wantErr   bool
	}{
		{
			name:      "success",
			url:       "https://myapp.com/callback?code=abc123&state=mystate",
			wantCode:  "abc123",
			wantState: "mystate",
		},
		{
			name:      "code_only",
			url:       "https://myapp.com/callback?code=xyz789",
			wantCode:  "xyz789",
			wantState: "",
		},
		{
			name:    "error_response",
			url:     "https://myapp.com/callback?error=access_denied&error_description=User%20denied",
			wantErr: true,
		},
		{
			name:    "missing_code",
			url:     "https://myapp.com/callback?state=mystate",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, state, err := ParseCallbackURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if state != tt.wantState {
				t.Errorf("state = %q, want %q", state, tt.wantState)
			}
		})
	}
}

func TestServiceIDsFromCallback(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    []string
		wantNil bool
	}{
		{
			name: "single",
			url:  "https://app.com/callback?code=abc&granted=svc1",
			want: []string{"svc1"},
		},
		{
			name: "multiple",
			url:  "https://app.com/callback?code=abc&granted=svc1,svc2,svc3",
			want: []string{"svc1", "svc2", "svc3"},
		},
		{
			name:    "none",
			url:     "https://app.com/callback?code=abc",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ServiceIDsFromCallback(tt.url)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if len(result) != len(tt.want) {
				t.Errorf("len = %d, want %d", len(result), len(tt.want))
				return
			}
			for i, v := range tt.want {
				if result[i] != v {
					t.Errorf("result[%d] = %q, want %q", i, result[i], v)
				}
			}
		})
	}
}

func TestAsyncContext_TokenValid(t *testing.T) {
	tests := []struct {
		name  string
		ctx   AsyncContext
		valid bool
	}{
		{
			name:  "no_token",
			ctx:   AsyncContext{},
			valid: false,
		},
		{
			name: "no_expiry",
			ctx: AsyncContext{
				AccessToken: "token123",
			},
			valid: true,
		},
		{
			name: "not_expired",
			ctx: AsyncContext{
				AccessToken:          "token123",
				AccessTokenExpiresIn: 3600,
				IssuedAt:             9999999999, // far future
			},
			valid: true,
		},
		{
			name: "expired",
			ctx: AsyncContext{
				AccessToken:          "token123",
				AccessTokenExpiresIn: 3600,
				IssuedAt:             0, // epoch
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.TokenValid(); got != tt.valid {
				t.Errorf("TokenValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestAsyncContext_BuildAsyncConsentURL(t *testing.T) {
	ctx := &AsyncContext{
		AsyncConsentURL: "https://provider.com/auth?domain=example.com",
	}

	url := ctx.BuildAsyncConsentURL("myclient", "dns")

	if !strings.Contains(url, "client_id=myclient") {
		t.Error("URL should contain client_id")
	}
	if !strings.Contains(url, "scope=dns") {
		t.Error("URL should contain scope")
	}
	if !strings.Contains(url, "domain=example.com") {
		t.Error("URL should preserve existing params")
	}
}

func TestAsyncContext_SetCodeFromCallback(t *testing.T) {
	ctx := &AsyncContext{}

	err := ctx.SetCodeFromCallback("https://app.com/callback?code=authcode123&state=mystate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctx.Code != "authcode123" {
		t.Errorf("Code = %q, want %q", ctx.Code, "authcode123")
	}
}

// Integration test - check template support against real provider
func TestCheckTemplateSupported(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := New()
	ctx := context.Background()

	// First get config
	cfg, err := client.GetDomainConfig(ctx, "diabtrack.com")
	if err != nil {
		t.Fatalf("GetDomainConfig failed: %v", err)
	}

	// Check a known template - exampleservice.domainconnect.org/template1 is the test template
	err = client.CheckTemplateSupported(ctx, cfg, "exampleservice.domainconnect.org", []string{"template1"})
	if err != nil {
		t.Logf("Template check failed (may be expected if provider doesn't support this template): %v", err)
	}
}

func TestGetDomainConfig_NoDomainConnectRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := New()
	_, err := client.GetDomainConfig(context.Background(), "randomnonexistent.bike")
	if !errors.Is(err, ErrNoDomainConnectRecord) {
		t.Errorf("expected ErrNoDomainConnectRecord, got %v", err)
	}
}

func TestCheckTemplateSupported_NotSupported(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := New()
	cfg, err := client.GetDomainConfig(context.Background(), "diabtrack.com")
	if err != nil {
		t.Fatalf("GetDomainConfig failed: %v", err)
	}

	err = client.CheckTemplateSupported(context.Background(), cfg,
		"exampleservice.domainconnect.org", []string{"template_not_exists"})
	if !errors.Is(err, ErrTemplateNotSupported) {
		t.Errorf("expected ErrTemplateNotSupported, got %v", err)
	}
}

func TestGetAsyncToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/oauth/access_token" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("wrong method: %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("grant_type") != "authorization_code" {
			t.Errorf("wrong grant_type: %s", q.Get("grant_type"))
		}
		if q.Get("code") != "testcode" {
			t.Errorf("wrong code: %s", q.Get("code"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test_access_token",
			"refresh_token": "test_refresh_token",
			"expires_in":    3600,
		})
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		Code:   "testcode",
		Config: &Config{URLAPI: srv.URL},
	}

	result, err := client.GetAsyncToken(context.Background(), asyncCtx, AsyncCredentials{
		ClientID: "myclient", ClientSecret: "mysecret", APIURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "test_access_token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "test_access_token")
	}
	if result.RefreshToken != "test_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "test_refresh_token")
	}
	if result.AccessTokenExpiresIn != 3600 {
		t.Errorf("AccessTokenExpiresIn = %d, want %d", result.AccessTokenExpiresIn, 3600)
	}
	if result.IssuedAt == 0 {
		t.Error("IssuedAt not set")
	}
}

func TestGetAsyncToken_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{Code: "badcode", Config: &Config{URLAPI: srv.URL}}
	_, err := client.GetAsyncToken(context.Background(), asyncCtx, AsyncCredentials{
		ClientID: "x", ClientSecret: "x", APIURL: srv.URL,
	})
	if !errors.Is(err, ErrAsyncToken) {
		t.Errorf("expected ErrAsyncToken, got %v", err)
	}
}

func TestRefreshAsyncToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("grant_type") != "refresh_token" {
			t.Errorf("wrong grant_type: %s", q.Get("grant_type"))
		}
		if q.Get("refresh_token") != "oldrefresh" {
			t.Errorf("wrong refresh_token: %s", q.Get("refresh_token"))
		}

		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new_access_token",
			"refresh_token": "new_refresh_token",
			"expires_in":    7200,
		})
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		RefreshToken: "oldrefresh",
		Config:       &Config{URLAPI: srv.URL},
	}
	result, err := client.RefreshAsyncToken(context.Background(), asyncCtx, AsyncCredentials{
		ClientID: "x", ClientSecret: "x", APIURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "new_access_token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "new_access_token")
	}
	if result.RefreshToken != "new_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "new_refresh_token")
	}
}

func TestApplyAsync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("wrong method: %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer mytoken" {
			t.Errorf("wrong auth: %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		AccessToken: "mytoken",
		ProviderID:  "provider",
		ServiceID:   "svc",
		Config:      &Config{DomainRoot: "example.com", URLAPI: srv.URL},
	}
	err := client.ApplyAsync(context.Background(), asyncCtx, ApplyAsyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyAsync_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		AccessToken: "mytoken",
		ProviderID:  "provider",
		ServiceID:   "svc",
		Config:      &Config{DomainRoot: "example.com", URLAPI: srv.URL},
	}
	err := client.ApplyAsync(context.Background(), asyncCtx, ApplyAsyncOptions{})
	if !errors.Is(err, ErrConflictOnApply) {
		t.Errorf("expected ErrConflictOnApply, got %v", err)
	}
}

func TestGetSyncURL_SigIsLast(t *testing.T) {
	privateKey, err := os.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}

	client := New()
	u, err := client.GetSyncURL(context.Background(), SyncURLOptions{
		Config: &Config{
			DomainRoot: "example.com",
			Host:       "www",
			URLSyncUX:  "connect.provider.com",
		},
		ProviderID: "provider1",
		ServiceID:  "svc1",
		Params:     map[string]string{"IP": "1.2.3.4", "RANDOMTEXT": "hello"},
		PrivateKey: privateKey,
		KeyID:      "key1",
		GroupIDs:   []string{"g1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Extract raw query string and verify sig is the last parameter
	parts := strings.SplitN(u, "?", 2)
	if len(parts) != 2 {
		t.Fatalf("expected query string in URL %q", u)
	}
	params := strings.Split(parts[1], "&")
	last := params[len(params)-1]
	if !strings.HasPrefix(last, "sig=") {
		t.Errorf("expected sig as last param, got %q (full query: %s)", last, parts[1])
	}
}

func TestDeleteAsync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("wrong method: %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		AccessToken: "mytoken",
		ProviderID:  "provider",
		ServiceID:   "svc",
		Config:      &Config{DomainRoot: "example.com", URLAPI: srv.URL},
	}
	err := client.DeleteAsync(context.Background(), asyncCtx, "")
	if err != nil {
		t.Fatal(err)
	}
}

// loadTestKey reads testdata/private_key.pem and returns it with its public key.
func loadTestKey(t *testing.T) ([]byte, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := os.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}
	rsaKey, err := parsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return privateKey, &rsaKey.PublicKey
}

// verifyAsDNSProvider verifies a signed query like a DNS provider does (see DomainConnectApplyZone):
// strip sig and key from the raw query, keep the rest as-is, and verify RSA-SHA256 over it.
func verifyAsDNSProvider(t *testing.T, rawQuery string, pub *rsa.PublicKey) {
	t.Helper()

	var kept []string
	var sig, key string
	for _, pair := range strings.Split(rawQuery, "&") {
		switch {
		case strings.HasPrefix(pair, "sig="):
			sig = strings.TrimPrefix(pair, "sig=")
		case strings.HasPrefix(pair, "key="):
			key = strings.TrimPrefix(pair, "key=")
		default:
			kept = append(kept, pair)
		}
	}
	if sig == "" {
		t.Fatalf("no sig in query %q", rawQuery)
	}
	if key == "" {
		t.Fatalf("no key in query %q", rawQuery)
	}

	// sig is URL-encoded standard base64
	unescaped, err := url.QueryUnescape(sig)
	if err != nil {
		t.Fatalf("unescape sig: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		t.Fatalf("sig is not standard base64: %v (sig=%q)", err, unescaped)
	}

	signed := strings.Join(kept, "&")
	hash := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], raw); err != nil {
		t.Fatalf("signature does not verify over query %q: %v", signed, err)
	}
}

func TestGetSyncURL_SignatureVerifiesAsDNSProvider(t *testing.T) {
	privateKey, pub := loadTestKey(t)

	client := New()
	u, err := client.GetSyncURL(context.Background(), SyncURLOptions{
		Config: &Config{
			DomainRoot: "example.com",
			Host:       "www",
			URLSyncUX:  "https://connect.provider.com",
		},
		ProviderID:  "provider1",
		ServiceID:   "svc1",
		Params:      map[string]string{"IP": "1.2.3.4", "RANDOMTEXT": "shm:1531371203:Hejo"},
		RedirectURL: "https://app.example.net/return?x=1&y=2",
		State:       "opaque state",
		GroupIDs:    []string{"g1", "g2"},
		PrivateKey:  privateKey,
		KeyID:       "_dck1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	// All params must be present and covered by the signature (redirect_uri, state, groupId were previously unsigned)
	q := parsed.Query()
	for _, p := range []string{"domain", "host", "IP", "RANDOMTEXT", "redirect_uri", "state", "groupId"} {
		if q.Get(p) == "" {
			t.Errorf("missing %s in query %q", p, parsed.RawQuery)
		}
	}
	if q.Get("key") != "_dck1" {
		t.Errorf("key = %q, want %q", q.Get("key"), "_dck1")
	}
	// sigts is not part of the spec
	if q.Has("sigts") {
		t.Errorf("unexpected sigts in query %q", parsed.RawQuery)
	}

	verifyAsDNSProvider(t, parsed.RawQuery, pub)
}

func TestApplyAsync_SignatureVerifiesAsDNSProvider(t *testing.T) {
	privateKey, pub := loadTestKey(t)

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	asyncCtx := &AsyncContext{
		Config:      &Config{DomainRoot: "example.com", Host: "www", URLAPI: srv.URL},
		ProviderID:  "provider1",
		ServiceID:   "svc1",
		AccessToken: "token",
		Params:      map[string]string{"IP": "1.2.3.4"},
	}
	err := client.ApplyAsync(context.Background(), asyncCtx, ApplyAsyncOptions{
		Params:      map[string]string{"RANDOMTEXT": "hello world"},
		GroupIDs:    []string{"g1"},
		ForceUpdate: true,
		PrivateKey:  privateKey,
		KeyID:       "_dck1",
	})
	if err != nil {
		t.Fatalf("ApplyAsync failed: %v", err)
	}
	if gotQuery == "" {
		t.Fatal("server received no query string")
	}

	q, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	for _, p := range []string{"domain", "host", "IP", "RANDOMTEXT", "groupId", "force"} {
		if q.Get(p) == "" {
			t.Errorf("missing %s in query %q", p, gotQuery)
		}
	}
	if q.Has("sigts") {
		t.Errorf("unexpected sigts in query %q", gotQuery)
	}

	verifyAsDNSProvider(t, gotQuery, pub)
}
