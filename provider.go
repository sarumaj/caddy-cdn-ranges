package caddy_cdn_ranges

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/jmespath/go-jmespath"            // cSpell: words jmespath
	cdn_ranges "github.com/taythebot/cdn-ranges" // cSpell: words taythebot
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
			ip, ok := v.Index(i).Interface().(string)
			if !ok {
				return nil, fmt.Errorf("unexpected IP type: %T", v.Index(i).Interface())
			}
			ipList = append(ipList, ip)
		}
		return ipList, nil

	case reflect.String:
		return []string{result.(string)}, nil

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
		v4 = append(v4, asn_v4...)
		v6 = append(v6, asn_v6...)
	}

	if c.IPv4_URL != nil {
		ips, err := c.IPv4_URL.Fetch(ctx)
		if err != nil {
			return nil, nil, err
		}
		v4 = append(v4, ips...)
	}

	if c.IPv6_URL != nil {
		ips, err := c.IPv6_URL.Fetch(ctx)
		if err != nil {
			return nil, nil, err
		}
		v6 = append(v6, ips...)
	}

	if len(v4)+len(v6) == 0 {
		return nil, nil, fmt.Errorf("no prefixes found for provider %s", c.ProviderName)
	}

	return v4, v6, nil
}

// Type Guard
var _ provider.Provider = (*Provider)(nil)
