package caddy_cdn_ranges

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"                       // cSpell: words caddyserver
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile" // cSpell: words caddyconfig caddyfile
	"github.com/taythebot/cdn-ranges/provider"              // cSpell: words taythebot
)

func init() {
	provider.Providers = []provider.Provider{
		&testProvider{
			name: "Cloudflare",
			v4:   []string{"1.2.3.4/32", "5.6.7.8/32", "2001:db8::/32"},
			v6:   []string{"2001:db8::/32"},
		},
		&testProvider{
			name: "Cloudfront",
			v4:   []string{"9.10.11.12/32", "2001:db8:1234::/32"},
			v6:   []string{"2001:db8:1234::/32"},
		},
	}
}

type testProvider struct {
	name string
	v4   []string
	v6   []string
	err  error
}

func (p *testProvider) Name() string {
	return p.name
}

func (p *testProvider) Fetch(_ context.Context) ([]string, []string, error) {
	return p.v4, p.v6, p.err
}

func TestCaddyModule(t *testing.T) {
	module := CaddyTrustedProxiesCDN{}
	info := module.CaddyModule()

	if info.ID != "http.ip_sources.trusted_proxies_cdn_ranges" {
		t.Errorf("Expected module ID 'http.ip_sources.trusted_proxies_cdn_ranges', got '%s'", info.ID)
	}

	if info.New == nil {
		t.Error("Expected New function to be defined")
	}

	newModule := info.New()
	if _, ok := newModule.(*CaddyTrustedProxiesCDN); !ok {
		t.Error("Expected New to return *CaddyTrustedProxiesCDN")
	}
}

func TestUnmarshalCaddyfile_Interval(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		interval 2h
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	expected := caddy.Duration(2 * time.Hour)
	if module.Interval != expected {
		t.Errorf("Expected interval %v, got %v", expected, module.Interval)
	}
}

func TestUnmarshalCaddyfile_Providers(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider cloudflare cloudfront
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	expected := []string{"cloudflare", "cloudfront"}
	if len(module.Providers) != len(expected) {
		t.Fatalf("Expected %d providers, got %d", len(expected), len(module.Providers))
	}

	actualProviders := toStringProviders(t, module.Providers)
	for i, p := range expected {
		if actualProviders[i] != p {
			t.Errorf("Expected provider[%d] = %s, got %s", i, p, actualProviders[i])
		}
	}
}

func TestUnmarshalCaddyfile_Concurrency(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		concurrency 10
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if module.Concurrency != 10 {
		t.Errorf("Expected concurrency 10, got %d", module.Concurrency)
	}
}

func TestUnmarshalCaddyfile_IPv4IPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIPv4 *bool
		wantIPv6 *bool
	}{
		{
			name: "IPv4 enabled",
			input: `trusted_proxies_cdn_ranges {
				ipv4 true
			}`,
			wantIPv4: boolPtr(true),
			wantIPv6: nil,
		},
		{
			name: "IPv4 disabled",
			input: `trusted_proxies_cdn_ranges {
				ipv4 false
			}`,
			wantIPv4: boolPtr(false),
			wantIPv6: nil,
		},
		{
			name: "IPv6 enabled",
			input: `trusted_proxies_cdn_ranges {
				ipv6 true
			}`,
			wantIPv4: nil,
			wantIPv6: boolPtr(true),
		},
		{
			name: "Both configured",
			input: `trusted_proxies_cdn_ranges {
				ipv4 true
				ipv6 false
			}`,
			wantIPv4: boolPtr(true),
			wantIPv6: boolPtr(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			module := &CaddyTrustedProxiesCDN{}

			err := module.UnmarshalCaddyfile(d)
			if err != nil {
				t.Fatalf("UnmarshalCaddyfile failed: %v", err)
			}

			if !boolPtrEqual(module.IPv4, tt.wantIPv4) {
				t.Errorf("IPv4: expected %v, got %v", boolPtrValue(tt.wantIPv4), boolPtrValue(module.IPv4))
			}

			if !boolPtrEqual(module.IPv6, tt.wantIPv6) {
				t.Errorf("IPv6: expected %v, got %v", boolPtrValue(tt.wantIPv6), boolPtrValue(module.IPv6))
			}
		})
	}
}

func TestUnmarshalCaddyfile_Complete(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		interval 30m
		provider cloudflare
		concurrency 3
		ipv4 true
		ipv6 false
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if module.Interval != caddy.Duration(30*time.Minute) {
		t.Errorf("Expected interval 30m, got %v", module.Interval)
	}

	actualProviders := toStringProviders(t, module.Providers)
	if len(actualProviders) != 1 || actualProviders[0] != "cloudflare" {
		t.Errorf("Expected providers [cloudflare], got %v", actualProviders)
	}

	if module.Concurrency != 3 {
		t.Errorf("Expected concurrency 3, got %d", module.Concurrency)
	}

	if !boolPtrEqual(module.IPv4, boolPtr(true)) {
		t.Errorf("Expected IPv4 true")
	}

	if !boolPtrEqual(module.IPv6, boolPtr(false)) {
		t.Errorf("Expected IPv6 false")
	}
}

func TestUnmarshalCaddyfile_CustomProvider(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider {
			custom {
				ipv4_url https://example.com/ipv4
				ipv6_url https://example.com/ipv6 items
				asn_list 13335 20940
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	if err := module.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if len(module.Providers) != 1 {
		t.Fatalf("Expected 1 provider, got %d", len(module.Providers))
	}

	providerConfig := toProvider(t, module.Providers[0])
	if providerConfig.ProviderName != "custom" {
		t.Fatalf("Expected provider name custom, got %s", providerConfig.ProviderName)
	}

	if providerConfig.IPv4_URL == nil || providerConfig.IPv4_URL.URL != "https://example.com/ipv4" {
		t.Fatalf("Expected ipv4_url to be set")
	}

	if providerConfig.IPv4_URL.JMESPath != "@" {
		t.Fatalf("Expected ipv4_url JMESPath '@', got %s", providerConfig.IPv4_URL.JMESPath)
	}

	if providerConfig.IPv6_URL == nil || providerConfig.IPv6_URL.URL != "https://example.com/ipv6" {
		t.Fatalf("Expected ipv6_url to be set")
	}

	if providerConfig.IPv6_URL.JMESPath != "items" {
		t.Fatalf("Expected ipv6_url JMESPath 'items', got %s", providerConfig.IPv6_URL.JMESPath)
	}

	if len(providerConfig.ASNList) != 2 || providerConfig.ASNList[0] != 13335 || providerConfig.ASNList[1] != 20940 {
		t.Fatalf("Expected ASN list [13335 20940], got %v", providerConfig.ASNList)
	}
}

func TestUnmarshalCaddyfile_CustomProviderEmptyASNList(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider {
			custom {
				ipv4_url https://example.com/ipv4
				asn_list []
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	if err := module.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	providerConfig := toProvider(t, module.Providers[0])
	if len(providerConfig.ASNList) != 0 {
		t.Fatalf("Expected empty ASN list, got %v", providerConfig.ASNList)
	}
}

func TestUnmarshalCaddyfile_ProviderBlockMixed(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider {
			cloudflare
			custom {
				asn_list 13335
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	if err := module.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if len(module.Providers) != 2 {
		t.Fatalf("Expected 2 providers, got %d", len(module.Providers))
	}

	if providerName, ok := module.Providers[0].(string); !ok || providerName != "cloudflare" {
		t.Fatalf("Expected first provider to be cloudflare, got %v", module.Providers[0])
	}

	customProvider := toProvider(t, module.Providers[1])
	if customProvider.ProviderName != "custom" {
		t.Fatalf("Expected custom provider name, got %s", customProvider.ProviderName)
	}

	if len(customProvider.ASNList) != 1 || customProvider.ASNList[0] != 13335 {
		t.Fatalf("Expected ASN list [13335], got %v", customProvider.ASNList)
	}
}

func TestUnmarshalCaddyfile_ProviderBlockUnexpectedArgs(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider {
			custom unexpected
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments for provider") {
		t.Fatalf("Expected unexpected arguments error, got %v", err)
	}
}

func TestUnmarshalCaddyfile_CustomProviderASNListBrackets(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		provider {
			custom {
				asn_list [13335, 20940]
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	if err := module.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	providerConfig := toProvider(t, module.Providers[0])
	if len(providerConfig.ASNList) != 2 || providerConfig.ASNList[0] != 13335 || providerConfig.ASNList[1] != 20940 {
		t.Fatalf("Expected ASN list [13335 20940], got %v", providerConfig.ASNList)
	}
}

func TestUnmarshalCaddyfile_InvalidArgument(t *testing.T) {
	input := `trusted_proxies_cdn_ranges unexpected_arg`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("Expected error for unexpected argument")
	}
}

func TestUnmarshalCaddyfile_InvalidOption(t *testing.T) {
	input := `trusted_proxies_cdn_ranges {
		invalid_option value
	}`

	d := caddyfile.NewTestDispenser(input)
	module := &CaddyTrustedProxiesCDN{}

	err := module.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("Expected error for invalid option")
	}
}

func TestFetchPrefixes_AllProviders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"cloudflare", "cloudfront"},
		Concurrency: 5,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(true),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected at least some prefixes from all providers")
	}

	// Verify all prefixes are valid
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			t.Errorf("Invalid prefix: %v", prefix)
		}
	}
}

func TestFetchPrefixes_SpecificProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Test with Cloudflare which is known to be available
	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"cloudflare"},
		Concurrency: 3,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(true),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected prefixes from Cloudflare")
	}

	// Cloudflare should have both IPv4 and IPv6 ranges
	hasIPv4 := false
	hasIPv6 := false
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			hasIPv4 = true
		}
		if prefix.Addr().Is6() {
			hasIPv6 = true
		}
	}

	if !hasIPv4 && !hasIPv6 {
		t.Error("Expected at least one IPv4 or IPv6 prefix from Cloudflare")
	}
}

func TestFetchPrefixes_InvalidProvider(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"nonexistent_provider"},
		Concurrency: 3,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(true),
	}

	_, err := module.fetchPrefixes()
	if err == nil {
		t.Error("Expected error for invalid provider")
	}

	if !strings.Contains(err.Error(), "no valid providers found") {
		t.Errorf("Expected 'no valid providers found' error, got: %v", err)
	}
}

func TestFetchPrefixes_CaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"CLOUDFLARE", "CloudFront"},
		Concurrency: 3,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(false),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected prefixes from case-insensitive provider names")
	}
}

func TestFetchPrefixes_IPv4Only(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"cloudflare"},
		Concurrency: 3,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(false),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected IPv4 prefixes")
	}

	// Verify only IPv4 prefixes
	for _, prefix := range prefixes {
		if !prefix.Addr().Is4() {
			t.Errorf("Expected only IPv4 prefixes, got IPv6: %v", prefix)
		}
	}
}

func TestFetchPrefixes_IPv6Only(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"cloudflare"},
		Concurrency: 3,
		IPv4:        boolPtr(false),
		IPv6:        boolPtr(true),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected IPv6 prefixes")
	}

	// Verify only IPv6 prefixes
	for _, prefix := range prefixes {
		if !prefix.Addr().Is6() {
			t.Errorf("Expected only IPv6 prefixes, got IPv4: %v", prefix)
		}
	}
}

func TestFetchPrefixes_HighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Test with concurrency higher than number of providers
	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{"cloudflare", "cloudfront"},
		Concurrency: 10,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(true),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes with high concurrency failed: %v", err)
	}

	if len(prefixes) == 0 {
		t.Error("Expected prefixes with high concurrency")
	}
}

func TestGetIPRanges(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{}

	// Set some test ranges
	testPrefix := netip.MustParsePrefix("192.0.2.0/24")
	module.ranges = []netip.Prefix{testPrefix}

	ranges := module.GetIPRanges(&http.Request{})

	if len(ranges) != 1 {
		t.Errorf("Expected 1 range, got %d", len(ranges))
	}

	if len(ranges) > 0 && ranges[0] != testPrefix {
		t.Errorf("Expected %v, got %v", testPrefix, ranges[0])
	}
}

func TestProvision_Defaults(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	err := module.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
}

func TestProviderNamesAvailable(t *testing.T) {
	// Verify expected providers are available
	expectedProviders := []string{
		"Cloudflare",
		"Cloudfront",
	}

	availableProviders := make(map[string]bool)
	for _, p := range provider.Providers {
		availableProviders[p.Name()] = true
	}

	for _, expected := range expectedProviders {
		if !availableProviders[expected] {
			t.Errorf("Expected provider %s not found in available providers", expected)
		}
	}

	if len(provider.Providers) == 0 {
		t.Error("Expected at least some providers to be available")
	}
}

func TestFetchPrefixes_CustomProvider(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{
		Providers: []any{&testProvider{
			name: "Custom",
			v4:   []string{"203.0.113.0/24"},
			v6:   []string{},
		}},
		Concurrency: 2,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(false),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	customPrefix := netip.MustParsePrefix("203.0.113.0/24")
	if !containsPrefix(prefixes, customPrefix) {
		t.Errorf("Expected custom prefix %v to be present", customPrefix)
	}
}

func TestFetchPrefixes_MixedProviders(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{
		Providers: []any{
			"cloudflare",
			&testProvider{name: "Custom", v4: []string{"198.51.100.0/24"}},
		},
		Concurrency: 3,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(false),
	}

	prefixes, err := module.fetchPrefixes()
	if err != nil {
		t.Fatalf("fetchPrefixes failed: %v", err)
	}

	customPrefix := netip.MustParsePrefix("198.51.100.0/24")
	if !containsPrefix(prefixes, customPrefix) {
		t.Errorf("Expected mixed custom prefix %v to be present", customPrefix)
	}
}

func TestFetchPrefixes_UnsupportedProviderType(t *testing.T) {
	module := &CaddyTrustedProxiesCDN{
		Providers:   []any{123},
		Concurrency: 1,
		IPv4:        boolPtr(true),
		IPv6:        boolPtr(true),
	}

	_, err := module.fetchPrefixes()
	if err == nil || !strings.Contains(err.Error(), "unsupported provider type") {
		t.Fatalf("Expected unsupported provider type error, got %v", err)
	}
}

// Helper functions

func boolPtr(b bool) *bool {
	return &b
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func boolPtrValue(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func toStringProviders(t *testing.T, providers []any) []string {
	t.Helper()
	result := make([]string, 0, len(providers))
	for _, p := range providers {
		value, ok := p.(string)
		if !ok {
			t.Fatalf("Expected provider to be string, got %T", p)
		}
		result = append(result, value)
	}
	return result
}

func toProvider(t *testing.T, value any) *Provider {
	t.Helper()
	switch providerValue := value.(type) {
	case *Provider:
		return providerValue
	case Provider:
		return &providerValue
	default:
		t.Fatalf("Expected provider to be Provider, got %T", value)
	}
	return nil
}

func containsPrefix(prefixes []netip.Prefix, target netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == target {
			return true
		}
	}
	return false
}
