package caddy_cdn_ranges

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp" // cSpell: words caddyhttp caddyserver
	"github.com/jmespath/go-jmespath"                   // cSpell: words jmespath
	cdn_ranges "github.com/taythebot/cdn-ranges"        // cSpell: words taythebot
	"github.com/taythebot/cdn-ranges/provider"
)

type PullConfig struct {
	URL      string `json:"url,omitempty"`
	JMESPath string `json:"xpath,omitempty"`
}

func (u PullConfig) Fetch(ctx context.Context) ([]string, error) {
	if u.URL == "" {
		return nil, fmt.Errorf("URL is required for PullConfig")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := cdn_ranges.GetHttpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result any
	switch ct := resp.Header.Get("Content-Type"); {
	case strings.Contains(ct, "application/json"):
		var data any
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, err
		}

		if u.JMESPath == "" {
			return nil, fmt.Errorf("JMESPath is required for PullConfig")
		}

		result, err = jmespath.Search(u.JMESPath, data)
		if err != nil {
			return nil, err
		}

	case strings.Contains(ct, "text/plain"):
		// If the response is plain text read line by line and return as a slice
		var lines []string
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") { // skip empty lines and comments
				lines = append(lines, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}

		result = lines

	default:
		return nil, fmt.Errorf("unsupported content type: %s", resp.Header.Get("Content-Type"))
	}

	v := reflect.ValueOf(result)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		var ipList []string
		for i := 0; i < v.Len(); i++ {
			ip := fmt.Sprintf("%v", v.Index(i).Interface())
			if _, err := caddyhttp.CIDRExpressionToPrefix(ip); err != nil {
				return nil, fmt.Errorf("invalid IP prefix %s: %w", ip, err)
			}
			ipList = append(ipList, ip)
		}
		return ipList, nil

	case reflect.String:
		ip := fmt.Sprintf("%v", result)
		if _, err := caddyhttp.CIDRExpressionToPrefix(ip); err != nil {
			return nil, fmt.Errorf("invalid IP prefix %s: %w", ip, err)
		}
		return []string{ip}, nil

	default:
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
}

type Provider struct {
	ProviderName string      `json:"name,omitempty"`
	IPv4_URL     *PullConfig `json:"ipv4_url,omitempty"`
	IPv6_URL     *PullConfig `json:"ipv6_url,omitempty"`
	ASNList      []int       `json:"asn_list,omitempty"`
}

func (c *Provider) Name() string { return c.ProviderName }

func (c *Provider) Fetch(ctx context.Context) ([]string, []string, error) {
	var (
		v4 []string
		v6 []string
	)
	for _, asn := range c.ASNList {
		asn_v4, asn_v6, err := cdn_ranges.ASNPrefixes(ctx, asn)
		if err != nil {
			return nil, nil, err
		}

		parsed4, parsed6, err := parseIPs(append(asn_v4, asn_v6...))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ASN prefixes for ASN %d: %w", asn, err)
		}

		v4 = append(v4, parsed4...)
		v6 = append(v6, parsed6...)
	}

	for _, urlProvider := range []*PullConfig{c.IPv4_URL, c.IPv6_URL} {
		if urlProvider != nil {
			ips, err := urlProvider.Fetch(ctx)
			if err != nil {
				return nil, nil, err
			}

			parsed4, parsed6, err := parseIPs(ips)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse IPs from provider %s: %w", c.ProviderName, err)
			}

			v4 = append(v4, parsed4...)
			v6 = append(v6, parsed6...)
		}
	}

	if len(v4)+len(v6) == 0 {
		return nil, nil, fmt.Errorf("no prefixes found for provider %s", c.ProviderName)
	}

	return v4, v6, nil
}

func parseIPs(in []string) (out4 []string, out6 []string, error error) {
	for _, ip := range in {
		parsed, err := caddyhttp.CIDRExpressionToPrefix(ip) // Validate CIDR format
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse IP prefix %s: %w", ip, err)
		}

		if parsed.Addr().Is4() {
			out4 = append(out4, parsed.String())
		} else if parsed.Addr().Is4In6() {
			out4 = append(out4, parsed.Addr().Unmap().String()+"/32")
			out6 = append(out6, parsed.String())
		} else if parsed.Addr().Is6() {
			out6 = append(out6, parsed.String())
		} else {
			return nil, nil, fmt.Errorf("invalid IP address %s", ip)
		}
	}

	return out4, out6, nil
}

// Type Guard
var _ provider.Provider = (*Provider)(nil)
