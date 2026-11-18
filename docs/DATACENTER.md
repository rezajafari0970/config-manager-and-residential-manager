# Datacenter, CDN and literal IPv6 exports

The Datacenter navigation page exposes two independent dimensions for the current
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

`GET /api/datacenter` returns all 11 datacenter and 7 CDN groups plus one literal IPv6 card, raw and ready
counts, token-scoped links, pending count and feed validity. The existing panel's
access policy applies. See `openapi-network.json` for the additive API contract.

`GET /subscription/network/{axis}/{group}/{token}/raw.txt` preserves original
healthy configuration bodies and separates them with a newline. `received.txt`
is the explicitly unverified diagnostic inventory. `next.json` returns one current,
healthy stored Xray template; `native-next.json` returns one native sing-box template.
`configs.json` and `native.jsonl` expose all verified templates for their engine.
Usable raw count equals Xray plus native template count. The scopes have independent
rounds over canonical identities and reuse the existing exact-byte health proof.

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

## Literal IPv6 addresses

The page includes one IPv6 card, exposed as `ipv6` in `/api/datacenter` and
`address/ipv6` in signed network exports. Membership requires explicit, valid
IPv6 in the configured server address. Domains are excluded even if they resolve
to AAAA-only addresses. IPv4, mapped IPv4, names such as `ipv6`, DNS servers, SNI,
inbound/interface addresses and mixed-address profiles do not qualify. Supported
JSON/json://, VMess and native protocol formats use their actual entry fields.

This is a local syntax predicate cached by immutable raw hash (at most 8192
booleans). It has no DNS queries, provider requests, queue, background workers,
expiry or persistent classification records. Existing health results are reused
for raw, all-template and rotating exports; received.txt remains diagnostic.
Counts and final writer checks use the same canonical input selection.

The former four-family UI/API/routes and DNS-family workers are removed. Startup
unwraps their metadata back to the original provider evidence array and deletes
only their rotation scopes. Database schema, ordinary/Residential health proofs,
provider evidence, raw blobs and other export scopes remain unchanged.
