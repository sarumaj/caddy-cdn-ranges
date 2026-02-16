# caddy-cdn-ranges

Use CDN provider IP ranges as a trusted proxies source for Caddy.

This module periodically fetches IP ranges from the `cdn-ranges` providers list and exposes them to Caddy's `trusted_proxies` IP source.

## Features

- Periodic refresh of CDN IP ranges (default: 24h).
- Filter by provider name(s).
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

## Directive options

<!-- cSpell: words jmespath -->

- `interval <duration>`: Refresh interval. Default: `24h`.
- `timeout <duration>`: Alias for `interval` (kept for compatibility).
- `provider <name...>`: One or more provider names (space-separated). If omitted, all providers are used.
- `provider { <name> { ... } }`: Define custom providers inline. Each custom provider block can set:
  - `ipv4_url <url> [jmespath]`
  - `ipv6_url <url> [jmespath]`
  - `asn_list <asn...>`
- `concurrency <number>`: Number of concurrent provider fetches. Default: `5`.
- `ipv4 <true|false>`: Enable IPv4 ranges. Default: `true`.
- `ipv6 <true|false>`: Enable IPv6 ranges. Default: `true`.

**JMESPath** expression is optional for endpoints returning JSON

## Provider names

Provider names come from the `cdn-ranges` library. Use the provider names listed in that project (see [CDN Providers](https://github.com/taythebot/cdn-ranges/tree/main?tab=readme-ov-file#cdn-providers)).

## Notes

- The module reuses its fetched ranges for all requests until the next refresh.
- If provider names are specified and none match, the module fails during provisioning.

## License

See [LICENSE](LICENSE).
