package caddy_cdn_ranges

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newJSONServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestPullConfigFetchValidation(t *testing.T) {
	server := newJSONServer(t, `{"items": []}`)
	tests := []struct {
		name      string
		provider  PullConfig
		expectErr string
	}{
		{
			name:      "missing URL",
			provider:  PullConfig{JMESPath: "items"},
			expectErr: "URL is required",
		},
		{
			name:      "missing JMESPath",
			provider:  PullConfig{URL: server.URL},
			expectErr: "JMESPath is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.provider.Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error containing %q, got %v", tt.expectErr, err)
			}
		})
	}
}

func TestPullConfigFetch_ArrayResult(t *testing.T) {
	server := newJSONServer(t, `{"items": ["1.2.3.4/32", "5.6.7.8/32"]}`)
	provider := PullConfig{URL: server.URL, JMESPath: "items"}

	ips, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
}

func TestPullConfigFetch_StringResult(t *testing.T) {
	server := newJSONServer(t, `{"item": "1.2.3.4/32"}`)
	provider := PullConfig{URL: server.URL, JMESPath: "item"}

	ips, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(ips) != 1 || ips[0] != "1.2.3.4/32" {
		t.Fatalf("expected single IP, got: %v", ips)
	}
}

func TestPullConfigFetch_UnexpectedType(t *testing.T) {
	server := newJSONServer(t, `{"item": 42}`)
	provider := PullConfig{URL: server.URL, JMESPath: "item"}

	_, err := provider.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected result type") {
		t.Fatalf("expected unexpected type error, got: %v", err)
	}
}

func TestPullConfigFetch_ArrayWithNonString(t *testing.T) {
	server := newJSONServer(t, `{"items": [42]}`)
	provider := PullConfig{URL: server.URL, JMESPath: "items"}

	_, err := provider.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid IP prefix") {
		t.Fatalf("expected invalid IP prefix error, got: %v", err)
	}
}

func TestProviderFetch_NoPrefixes(t *testing.T) {
	provider := &Provider{ProviderName: "empty"}

	_, _, err := provider.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no prefixes found") {
		t.Fatalf("expected no prefixes error, got: %v", err)
	}
}

func TestProviderFetch_URLs(t *testing.T) {
	ipv4Server := newJSONServer(t, `{"items": ["1.2.3.4/32", "5.6.7.8/32"]}`)
	ipv6Server := newJSONServer(t, `{"items": ["2001:db8::/32"]}`)

	provider := &Provider{
		ProviderName: "custom",
		IPv4_URL:     &PullConfig{URL: ipv4Server.URL, JMESPath: "items"},
		IPv6_URL:     &PullConfig{URL: ipv6Server.URL, JMESPath: "items"},
	}

	v4, v6, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(v4) != 2 {
		t.Fatalf("expected 2 IPv4 prefixes, got: %d", len(v4))
	}

	if len(v6) != 1 {
		t.Fatalf("expected 1 IPv6 prefix, got: %d", len(v6))
	}
}
