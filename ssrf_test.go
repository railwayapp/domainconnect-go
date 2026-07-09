package domainconnect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"172.16.5.4", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // cloud metadata
		{"fe80::1", false},
		{"fc00::1", false},    // unique local
		{"100.64.0.1", false}, // carrier-grade NAT
		{"0.0.0.0", false},
		{"224.0.0.1", false},        // multicast
		{"::ffff:127.0.0.1", false}, // IPv4-mapped loopback
		{"::ffff:169.254.169.254", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid test IP %q", tt.ip)
			}
			if got := isPublicIP(ip); got != tt.public {
				t.Errorf("isPublicIP(%s) = %v, want %v", tt.ip, got, tt.public)
			}
		})
	}
}

// TestGuardedClientBlocksLoopback proves the default client refuses a settings
// fetch that resolves to a non-public address, which is the SSRF sink.
func TestGuardedClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"providerId":"attacker"}`))
	}))
	defer srv.Close()

	client := New()
	err := client.doJSON(context.Background(), http.MethodGet, srv.URL, &struct{}{})
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got %v", err)
	}
}

// TestWithHTTPClientBypassesGuard documents that callers can opt out with a
// custom client, which is how the loopback-based tests reach httptest servers.
func TestWithHTTPClientBypassesGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"providerId":"ok"}`))
	}))
	defer srv.Close()

	client := New(WithHTTPClient(srv.Client()))
	var result struct {
		ProviderID string `json:"providerId"`
	}
	if err := client.doJSON(context.Background(), http.MethodGet, srv.URL, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProviderID != "ok" {
		t.Errorf("providerId = %q, want %q", result.ProviderID, "ok")
	}
}
