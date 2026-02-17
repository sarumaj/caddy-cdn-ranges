package caddy_cdn_ranges

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"                       // cSpell: words caddyserver
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile" // cSpell: words caddyconfig caddyfile
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"     // cSpell: words caddyhttp
	"github.com/taythebot/cdn-ranges/provider"              // cSpell: words taythebot
	"golang.org/x/sync/errgroup"                            // cSpell: words errgroup
)

func init() {
	caddy.RegisterModule(CaddyTrustedProxiesCDN{})
}

// CaddyTrustedProxiesCDN is a Caddy IP source module that automatically fetches and maintains
// a list of trusted proxy IP ranges from CDN and cloud providers. It periodically updates the
// IP ranges and makes them available to Caddy's trusted proxies configuration.
//
// The module supports:
//   - Built-in providers (Cloudflare, AWS CloudFront, Google Cloud, etc.) from the cdn-ranges library
//   - Custom providers with configurable URL endpoints and JMESPath filters
//   - Autonomous System Number (ASN) based IP range lookups
//   - Both JSON and plain text response formats
//   - Separate IPv4 and IPv6 filtering
//   - Concurrent fetching for improved performance
//
// Example Caddyfile configuration (short form):
//
//	servers {
//		trusted_proxies {
//			source cdn_ranges {
//				interval 24h
//				provider cloudflare cloudfront
//				concurrency 5
//				ipv4 true
//				ipv6 true
//			}
//		}
//	}
//
// Example with custom provider (block form):
//
//	servers {
//		trusted_proxies {
//			source cdn_ranges {
//				provider {
//					cloudflare
//					custom_cdn {
//						ipv4_url https://api.example.com/ipv4.json "prefixes[].cidr"
//						ipv6_url https://api.example.com/ipv6.json "prefixes[].cidr"
//						asn_list 13335 20940
//					}
//				}
//			}
//		}
//	}
type CaddyTrustedProxiesCDN struct {
	// Interval is the duration between refreshes of the IP ranges list. Defaults to 24 hours.
	// The module fetches updated ranges from providers at this interval. Set to smaller values
	// for more frequent updates (at the cost of increased network requests) or larger values
	// to reduce update frequency.
	// Examples: "12h", "1h", "30m"
	Interval caddy.Duration `json:"interval,omitempty"`

	// Providers is a list of providers to fetch IP ranges from. Each element can be:
	//   - A string: built-in provider name (e.g., "cloudflare", "cloudfront")
	//   - A *Provider: custom provider with URL endpoints and/or ASN lookups
	//
	// Built-in providers are matched case-insensitively. If this list is empty,
	// all available built-in providers from the cdn-ranges library will be used.
	// If specified providers are not found, the module will fail during provisioning.
	//
	// Example: providers cloudflare cloudfront
	//
	// Example with custom provider:
	//
	// 	providers {
	// 		cloudflare
	// 		custom_cdn {
	// 			ipv4_url https://api.example.com/ipv4.json "prefixes[].cidr"
	// 			ipv6_url https://api.example.com/ipv6.json "prefixes[].cidr"
	// 			asn_list 13335 20940
	// 		}
	// }
	Providers []any `json:"provider,omitempty"`

	// Concurrency is the number of concurrent goroutines used to fetch IP ranges from providers.
	// Higher values speed up updates but use more resources. Defaults to 5.
	// Set to 1 for sequential fetching or increase for faster parallel updates.
	// Recommended values: 3-10 depending on provider availability and network conditions.
	Concurrency int `json:"concurrency,omitempty"`

	// IPv4 controls whether IPv4 CIDR blocks are included in the trusted proxies list.
	// If nil (not set), it defaults to true (unless IPv6 is also nil, then both default to true).
	// Set to false to exclude IPv4 ranges. Useful if you only trust IPv6 proxies.
	// Examples: true (enable IPv4), false (disable IPv4)
	IPv4 *bool `json:"ipv4,omitempty"`

	// IPv6 controls whether IPv6 CIDR blocks are included in the trusted proxies list.
	// If nil (not set), it defaults to true (unless IPv4 is also nil, then both default to true).
	// Set to false to exclude IPv6 ranges. Useful if you only trust IPv4 proxies.
	// Examples: true (enable IPv6), false (disable IPv6)
	IPv6 *bool `json:"ipv6,omitempty"`

	ranges []netip.Prefix
	ctx    caddy.Context
	lock   *sync.RWMutex
}

func (CaddyTrustedProxiesCDN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.ip_sources.cdn_ranges",
		New: func() caddy.Module { return new(CaddyTrustedProxiesCDN) },
	}
}

func (s *CaddyTrustedProxiesCDN) getIPv4() bool      { return s.IPv4 != nil && *s.IPv4 }
func (s *CaddyTrustedProxiesCDN) getIPv6() bool      { return s.IPv6 != nil && *s.IPv6 }
func (s *CaddyTrustedProxiesCDN) setIPv4(value bool) { s.IPv4 = &value }
func (s *CaddyTrustedProxiesCDN) setIPv6(value bool) { s.IPv6 = &value }

func (s *CaddyTrustedProxiesCDN) Provision(ctx caddy.Context) error {
	s.ctx = ctx

	if s.lock == nil {
		s.lock = &sync.RWMutex{}
	}

	if s.Interval == 0 {
		s.Interval = caddy.Duration(24 * time.Hour) // default to 24 hours
	}

	if s.Concurrency <= 0 {
		s.Concurrency = 5 // default concurrency
	}

	if s.IPv4 == nil && s.IPv6 == nil {
		s.setIPv4(true)
		s.setIPv6(true)
	}

	// update cron
	go func() {
		ticker := time.NewTicker(time.Duration(s.Interval))
		s.lock.Lock()
		s.ranges, _ = s.fetchPrefixes()
		s.lock.Unlock()

		for {
			select {
			case <-ticker.C:
				prefixes, err := s.fetchPrefixes()
				if err != nil {
					break
				}

				s.lock.Lock()
				s.ranges = prefixes
				s.lock.Unlock()

			case <-s.ctx.Done():
				ticker.Stop()
				return

			}
		}
	}()
	return nil
}

func (s *CaddyTrustedProxiesCDN) fetchPrefixes() ([]netip.Prefix, error) {
	providers, err := s.resolveProviders()
	if err != nil {
		return nil, err
	}

	queue := make(chan provider.Provider, len(providers))
	for _, p := range providers {
		queue <- p
	}
	close(queue)

	var (
		g        errgroup.Group
		lock     sync.Mutex
		prefixes []netip.Prefix
	)
	for i := 0; i < s.Concurrency; i++ {
		g.Go(func() error {
			var local []netip.Prefix
			for p := range queue {
				v4, v6, err := p.Fetch(context.Background())
				if err != nil {
					return err
				}

				var rawPrefixes []string
				if s.getIPv4() {
					rawPrefixes = append(rawPrefixes, v4...)
				}
				if s.getIPv6() {
					rawPrefixes = append(rawPrefixes, v6...)
				}

				for _, prefixStr := range rawPrefixes {
					prefix, err := caddyhttp.CIDRExpressionToPrefix(prefixStr)
					if err != nil {
						return fmt.Errorf("failed to parse prefix %s from provider %s: %w", prefixStr, p.Name(), err)
					}

					if !s.getIPv4() && prefix.Addr().Is4() {
						continue
					}
					if !s.getIPv6() && prefix.Addr().Is6() {
						continue
					}

					local = append(local, prefix)
				}
			}

			if len(local) > 0 {
				lock.Lock()
				prefixes = append(prefixes, local...)
				lock.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return prefixes, nil
}

func (s *CaddyTrustedProxiesCDN) resolveProviders() ([]provider.Provider, error) {
	if len(s.Providers) == 0 {
		return provider.Providers, nil
	}

	var (
		providers          []provider.Provider
		validProviderNames []string
		missingNames       []string
	)

	for _, p := range provider.Providers {
		validProviderNames = append(validProviderNames, p.Name())
	}

	for _, specified := range s.Providers {
		switch v := specified.(type) {
		case string:
			name := strings.TrimSpace(v)
			if name == "" {
				continue
			}
			matched := false
			for _, p := range provider.Providers {
				if strings.EqualFold(p.Name(), name) {
					providers = append(providers, p)
					matched = true
				}
			}
			if !matched {
				missingNames = append(missingNames, name)
			}
		case Provider:
			providers = append(providers, &v)
		case *Provider:
			providers = append(providers, v)
		case provider.Provider:
			providers = append(providers, v)
		default:
			return nil, fmt.Errorf("unsupported provider type: %T", specified)
		}
	}

	if len(providers) == 0 {
		if len(missingNames) > 0 {
			return nil, fmt.Errorf("no valid providers found for specified names: %v, valid provider names: %v", missingNames, validProviderNames)
		}
		return nil, fmt.Errorf("no valid providers found")
	}

	return providers, nil
}

func (s *CaddyTrustedProxiesCDN) GetIPRanges(_ *http.Request) []netip.Prefix {
	if s.lock == nil {
		s.lock = &sync.RWMutex{}
	}

	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.ranges
}

func (m *CaddyTrustedProxiesCDN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() { // consume the directive name
		return d.ArgErr()
	}

	if d.CountRemainingArgs() > 0 { // no positional args allowed
		return d.Err("unexpected positional arguments")
	}

	// cSpell: words errf
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch key := d.Val(); key {
		case "interval":
			var value string
			if !d.AllArgs(&value) {
				return d.Errf("expected exactly one argument for '%s'", key)
			}

			parsedValue, err := caddy.ParseDuration(value)
			if err != nil {
				return err
			}

			m.Interval = caddy.Duration(parsedValue)

		case "provider":
			if d.CountRemainingArgs() > 0 {
				for _, arg := range d.RemainingArgs() {
					name := strings.TrimSpace(arg)
					if name == "" {
						continue
					}
					m.Providers = append(m.Providers, name)
				}
			}

			for d.NextBlock(nesting + 1) {
				providerName := strings.TrimSpace(d.Val())
				if providerName == "" {
					return d.Errf("provider name cannot be empty")
				}

				if d.CountRemainingArgs() > 0 {
					return d.Errf("unexpected arguments for provider '%s'", providerName)
				}

				providerConfig, hasConfig, err := parseProviderBlock(d, providerName, nesting+1)
				if err != nil {
					return err
				}

				if hasConfig {
					m.Providers = append(m.Providers, providerConfig)
				} else {
					m.Providers = append(m.Providers, providerName)
				}
			}

		case "concurrency":
			var value string
			if !d.AllArgs(&value) {
				return d.Errf("expected exactly one argument for '%s'", key)
			}

			val, err := strconv.Atoi(value)
			if err != nil {
				return err
			}

			m.Concurrency = val

		case "ipv4", "ipv6":
			var value string
			if !d.AllArgs(&value) {
				return d.Errf("expected exactly one argument for '%s'", key)
			}

			parsedValue, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}

			switch key {
			case "ipv4":
				m.setIPv4(parsedValue)
			case "ipv6":
				m.setIPv6(parsedValue)
			}

		default:
			return d.Errf("unexpected argument '%s'", key) // cSpell: ignore Errf
		}
	}

	return nil
}

func parseProviderBlock(d *caddyfile.Dispenser, name string, nesting int) (*Provider, bool, error) {
	providerConfig := &Provider{ProviderName: name}
	hasConfig := false

	for d.NextBlock(nesting + 1) {
		hasConfig = true
		switch subKey := d.Val(); subKey {
		case "ipv4_url":
			pull, err := parsePullConfig(d, subKey)
			if err != nil {
				return nil, false, err
			}
			providerConfig.IPv4_URL = pull

		case "ipv6_url":
			pull, err := parsePullConfig(d, subKey)
			if err != nil {
				return nil, false, err
			}
			providerConfig.IPv6_URL = pull

		case "asn_list":
			asnList, err := parseASNList(d, subKey)
			if err != nil {
				return nil, false, err
			}
			providerConfig.ASNList = append(providerConfig.ASNList, asnList...)

		default:
			return nil, false, d.Errf("unexpected argument '%s'", subKey)
		}
	}

	return providerConfig, hasConfig, nil
}

func parsePullConfig(d *caddyfile.Dispenser, key string) (*PullConfig, error) {
	var url string
	if !d.Args(&url) {
		return nil, d.Errf("expected at least one argument for '%s'", key)
	}

	if d.CountRemainingArgs() == 0 {
		return &PullConfig{
			URL:      strings.TrimSpace(url),
			JMESPath: "@",
		}, nil
	}

	var jmespath string // cSpell: words jmespath
	if !d.AllArgs(&jmespath) {
		return nil, d.Errf("expected at most two arguments for '%s'", key)
	}

	return &PullConfig{
		URL:      strings.TrimSpace(url),
		JMESPath: strings.TrimSpace(jmespath),
	}, nil
}

func parseASNList(d *caddyfile.Dispenser, key string) ([]int, error) {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return nil, nil
	}

	var asnList []int
	for _, arg := range args {
		clean := strings.TrimSpace(strings.Trim(arg, "[],"))
		if clean == "" {
			continue
		}

		for _, part := range strings.Split(clean, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				continue
			}

			asn, err := strconv.Atoi(value)
			if err != nil {
				return nil, d.Errf("invalid ASN '%s' for '%s'", value, key)
			}

			asnList = append(asnList, asn)
		}
	}

	return asnList, nil
}

// Interface guards
var (
	_ caddy.Module            = (*CaddyTrustedProxiesCDN)(nil)
	_ caddy.Provisioner       = (*CaddyTrustedProxiesCDN)(nil)
	_ caddyfile.Unmarshaler   = (*CaddyTrustedProxiesCDN)(nil)
	_ caddyhttp.IPRangeSource = (*CaddyTrustedProxiesCDN)(nil)
)
