# caddy-cdn-ranges

Use CDN provider IP ranges as a trusted proxies source for Caddy.

This module periodically fetches IP ranges from the `cdn-ranges` providers list and exposes them to Caddy's `trusted_proxies` IP source.

## Why use this module?

Trusted proxies are critical for applications behind reverse proxies or load balancers. This module automatically:

- Fetches the latest IP ranges from major CDN and cloud providers
- Updates them periodically to stay in sync with provider changes
- Supports custom providers for specialized use cases
- Filters by IPv4/IPv6 as needed
- Handles concurrent fetches for performance

## Features

- Periodic refresh of CDN IP ranges (default: 24h).
- Filter by provider name(s).
- Custom provider support with JMESPath filtering and plain text handling.
- IPv4 and/or IPv6 selection.
- Concurrent fetching for faster updates.

## Caddyfile usage

<!--cSpell: words caddyfile -->

```caddyfile
{
  servers {
    trusted_proxies {
      source trusted_proxies_cdn_ranges {
        interval 24h
        provider cloudflare cloudfront
        concurrency 5
        ipv4 true
        ipv6 true
      }
    }
  }
}
```

Custom provider block form:

```caddyfile
{
  servers {
    trusted_proxies {
      source trusted_proxies_cdn_ranges {
        provider {
          cloudflare
          custom_cdn {
            ipv4_url https://example.com/ipv4
            ipv6_url https://example.com/ipv6 items
            asn_list [13335, 20940]
          }
        }
      }
    }
  }
}
```

## Custom Provider Configuration

Define custom providers inline in your Caddyfile to fetch from arbitrary sources:

### JSON Response with JMESPath

If your provider returns JSON, use JMESPath to extract the IP list:

```caddyfile
provider {
  my_custom_cdn {
    ipv4_url https://api.example.com/ipv4.json "prefixes[].cidr"
    ipv6_url https://api.example.com/ipv6.json "prefixes[].cidr"
  }
}
```

**JMESPath examples:**

- `@` (default): Return the entire response as-is (must be an array or string)
- `items`: Extract the `items` array from the response
- `prefixes[].cidr`: Extract the `cidr` field from each item in the `prefixes` array
- `data.networks`: Navigate nested objects

See [JMESPath Reference](https://jmespath.org/reference.html) for more complex queries.

### Plain Text Response

If your provider returns plain text (one IP per line), simply omit the JMESPath argument:

```caddyfile
provider {
  my_static_list {
    ipv4_url https://example.com/ipv4.txt
    ipv6_url https://example.com/ipv6.txt
  }
}
```

Plain text responses automatically skip empty lines and lines starting with `#` or `//`.

### Using ASN Lookups

Fetch prefixes for Autonomous System Numbers (ASNs):

```caddyfile
provider {
  my_asn_provider {
    asn_list 13335 15169 8452
  }
}
```

### Combining Multiple Sources

A single custom provider can combine ASNs, IPv4 URLs, and IPv6 URLs:

```caddyfile
provider {
  all_sources {
    asn_list [13335, 20940]
    ipv4_url https://api.example.com/v4 "items[].network"
    ipv6_url https://api.example.com/v6 "items[].network"
  }
}
```

## Directive options

<!-- cSpell:words jmespath -->

- `provider <name...>`: One or more provider names (space-separated). If omitted, all providers are used.
  - Short form: `provider cloudflare cloudfront`
  - Block form: `provider { cloudflare custom { ... } }`

- `provider { <name> { ... } }`: Define custom providers inline. Each custom provider block can set:
  - `ipv4_url <url> [jmespath]`: Fetch IPv4 ranges from a URL. Uses JMESPath to extract CIDR blocks from JSON. For plain text, omit JMESPath. Default JMESPath is `@` (return entire response).
  - `ipv6_url <url> [jmespath]`: Fetch IPv6 ranges from a URL. Uses JMESPath to extract CIDR blocks from JSON. For plain text, omit JMESPath. Default JMESPath is `@` (return entire response).
  - `asn_list <asn...>`: Fetch ranges for one or more Autonomous System Numbers. Can be space-separated or comma-separated with brackets: `asn_list 13335 20940` or `asn_list [13335, 20940]`.

- `concurrency <number>`: Number of concurrent provider fetches. Default: `5`.
- `ipv4 <true|false>`: Enable IPv4 ranges. Default: `true`.
- `ipv6 <true|false>`: Enable IPv6 ranges. Default: `true`.
- `interval <duration>`: Refresh interval. Default: `24h`.

## Provider names

Provider names come from the `cdn-ranges` library. Use the provider names listed in that project (see [CDN Providers](https://github.com/taythebot/cdn-ranges/tree/main?tab=readme-ov-file#cdn-providers)).

Built-in providers include:

- `cloudflare`
- `cloudfront` (AWS CloudFront)
- And more — check the [cdn-ranges repository](https://github.com/taythebot/cdn-ranges/tree/main?tab=readme-ov-file#cdn-providers) for a complete list.

## Troubleshooting

### Module fails to fetch ranges

Check the logs for provider errors. Common causes:

- Network timeouts or DNS failures
- Invalid JMESPath in custom provider configuration
- Provider returning an unexpected content type

### Incorrect IP ranges returned

Verify your custom provider configuration:

- Test the URL in your browser to see the response format
- Verify the JMESPath extraction by testing it at [jmespath.org](https://jmespath.org/)
- Ensure the response contains valid CIDR blocks (e.g., `192.0.2.0/24`)

### Performance concerns

If fetching takes too long:

- Increase `concurrency` (default: 5)
- Increase `interval` to fetch less frequently
- Reduce the number of providers being fetched

## Build with xcaddy or custom image

<!-- cSpell: words xcaddy sarumaj gotoolchain -->

Use `xcaddy` to build a Caddy binary that includes this module:

```bash
xcaddy build \
  --with github.com/sarumaj/caddy-cdn-ranges
```

Example Dockerfile that builds a custom Caddy image with this module:

```dockerfile
FROM caddy:2.11-builder-alpine AS builder

WORKDIR /build

ENV GOTOOLCHAIN=go1.25.0

RUN xcaddy build \
  --with github.com/sarumaj/caddy-cdn-ranges

FROM caddy:2.11-alpine
COPY --from=builder /build/caddy /usr/bin/caddy
```

## Notes

- The module reuses its fetched ranges for all requests until the next refresh.
- If provider names are specified and none match, the module fails during provisioning.
- Custom providers must return one of:
  - JSON (for JMESPath extraction)
  - Plain text with one CIDR block per line
- Invalid CIDR blocks are rejected and will cause fetch failures. Ensure your data is well-formed.

## License

See [LICENSE](LICENSE).
