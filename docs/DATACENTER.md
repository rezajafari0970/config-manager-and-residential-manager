# Datacenter, CDN and IP-family exports

The Datacenter navigation page exposes three independent dimensions for the current
ordinary Output inventory. Residential acceptance, retention, country guards,
source controls and conversion proof are unchanged. This feature neither creates
configurations nor changes their existing template.

| Datacenter group | Verified origin ASNs (2026-11-17) |
| --- | --- |
| Amazon AWS | 16509, 14618, 8987 |
| Hetzner | 24940, 213230, 212317, 215859 |
| DigitalOcean | 14061 |
| OVHcloud | 16276 |
| Google Cloud | 396982, 19527, 139070, 15169 **and** an exact match in the official Google Cloud prefix feed |
| Microsoft Azure | 8075 |
| Oracle Cloud | 31898 |
| Vultr | 20473 |
| Akamai Linode | 63949 |
| Scaleway | 12876 |

Unknown includes other providers, unresolved destinations, unsupported/chained
transports, conflicting origins and expired classifications. These ASN labels
identify the observable entry network operator, not the physical facility,
reseller, VPN exit or exact cloud product. Google consumer AS15169 is deliberately
not relabeled Google Cloud without matching its dedicated cloud-prefix feed. Azure AS8075 includes Microsoft's broader network.

The five positive CDN groups are Cloudflare, Amazon CloudFront, Fastly, Bunny.net
and ArvanCloud. Official edge-prefix feeds, including IPv6 where published, are
used instead of treating a display name, SNI or Host header as proof. A CDN match
sets the datacenter to Unknown: the hidden origin cannot be inferred from its
edge. `none` means no match in these five current feeds, with a recognized hosting
network and no known CDN ASN; it is not proof that no other CDN exists. Unresolved,
ambiguous and uncovered networks have a separate CDN Unknown group.

All A/AAAA answers and all supported proxy destinations must agree for a known
provider. DNS is a five-minute snapshot (not authoritative TTL tracking); a local
client using different DNS may take another path. RIPEstat network-info supplies
BGP origin ASN evidence, which itself reflects upstream routing snapshots and
cannot guarantee instant ownership changes. Each result has an expiry. Expired
results are immediately excluded from named exports until refreshed.

## Modules and bounded work

- `internal/networkclass`: endpoint drivers, official-feed parsers, resolver,
  ASN driver and conservative evidence classifier; interfaces allow replacement.
- `internal/panel/network_store.go`: additive schema42, durable cache, two bounded
  I/O workers, automatic refresh/retry and metadata cleanup. No Xray processes,
  user-traffic probes, external AI calls or new service are required.
- `internal/panel/network_http.go`: group summary and independent persistent rounds.
- `internal/panel/web/datacenter.*`: desktop/mobile management page.

DNS successes cache for five minutes, failures for 30 seconds; ASN successes for
six hours, failures for one minute. CDN feeds refresh every six hours; failed
refreshes retry after five minutes while preserving a last-good snapshot for at
most 24 hours. Each lookup has a deadline; each classification has a 30-second
budget. Cache metadata without live ownership is pruned; encrypted raw blobs are
not pinned by this feature. No credentials or complete configurations are sent
to providers: only public endpoint IPs go to RIPEstat and hostnames to the system
DNS resolver. Background errors retry without blocking collector startup or HTTP.

## API and outputs

`GET /api/datacenter` returns all 11 datacenter, 7 CDN and 4 IP-family groups, raw and ready
counts, token-scoped links, pending count and feed validity. The existing panel's
access policy applies. See `openapi-network.json` for the additive API contract.

`GET /subscription/network/{axis}/{group}/{token}/raw.txt` preserves original
healthy configuration bodies and separates them with a newline. `received.txt`
is explicitly unverified diagnostic inventory. `next.json` returns one current,
healthy stored Xray template; native sing-box uses `native-next.json`.
`configs.json` and `native.jsonl` expose all verified templates for their engine.
Each axis/group has an independent round over canonical identities, and usable
raw count equals Xray plus native template count. No new proxy test is scheduled
by membership in another group or by downloading an export.

Tokens bind the axis, group and format. HEAD and prefetch do not consume turns.
Empty groups return 204; missing/corrupt bodies and concurrent eligibility changes
fail with 503 instead of falling back to another group. Membership, source state,
expiry, controls and exact conversion proof are rechecked after vault reads.
Global/source rounds use separate tables and remain independent.

Schema42 adds four tables and one index without changing existing rows or the
conversion/Residential policy epoch. Existing schema41 binaries cannot open it.
Take matched key/database/blob backups under the deployment lock before upgrade;
never restore an old database after services have resumed writes.

## Authoritative sources

- https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html
- https://stat.ripe.net/data/as-overview/data.json?resource=AS16509 (same endpoint for every ASN above)
- https://www.gstatic.com/ipranges/cloud.json (Google Cloud service prefixes)
- https://www.cloudflare.com/ips/
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
- https://ip-ranges.amazonaws.com/ip-ranges.json (`CLOUDFRONT`, excluding origin-facing ranges)
- https://api.fastly.com/public-ip-list
- https://api.bunny.net/system/edgeserverlist and its `/ipv6` endpoint
- https://www.arvancloud.ir/fa/ips.txt

## IPv6 and address families

`ip-family` has four mutually exclusive groups: `ipv6`, `dual`, `ipv4`, `unknown`.
The classifier reads only supported transport entry destinations. IPv6-only
means all resolved destinations are IPv6; any mixture of IPv4 and IPv6 is dual.
IPv4-mapped IPv6 literals are normalized to IPv4. Tunnel interface addresses,
inbounds, DNS servers, SNI, HTTP Host and display names never determine the family.
Xray WireGuard peer endpoints and native sing-box WireGuard endpoints are supported.
Unsupported chains, incomplete DNS resolution and ambiguous structures stay unknown.

Literal families are immutable properties of the raw hash and do not expire with
ASN/CDN metadata. Domain families reuse the same five-minute A/AAAA cache and
become unknown on expiry; this is a server-side DNS snapshot, not proof that a
client selected IPv6 or that the VPN carries IPv6 traffic. Classification needs
no extra proxy tests, core processes or service. The existing bounded network
workers refresh a versioned JSON evidence envelope; legacy array records initially
show unknown family and are refreshed automatically. Database schema44, health
proofs, source controls and Residential policy remain unchanged.
