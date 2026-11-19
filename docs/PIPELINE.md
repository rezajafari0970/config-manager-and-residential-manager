# Preparation and connection testing

Preparation and health validation are independent stages. The preparation worker
processes at most 128 current inputs per batch, one at a time, without starting a
core or making a network request. Prepared JSON is encrypted in the existing
content-addressed vault and retained by explicit GC references. Source counts
separate prepared templates, structural failures, queued probes and health results.
A structural failure is recorded immediately; it does not wait for network slots.
Missing blobs are retried without blocking the rest of a batch.
Formatting and encrypted blob writes happen outside the database writer. Current
ownership is materialized once per bounded batch, then preparation references are
committed together. Export still rechecks ownership and exact-candidate evidence
before publishing, so batching does not retain access for revoked members.

The received bytes remain immutable. `json://`, `custom://`, JSON strings,
percent encoding and nested standard/URL-safe base64 are decoded with size and
nesting limits. This is representation decoding, not cryptographic decryption.
Encrypted formats requiring an unavailable key remain unsupported.

Known VMess exporters that put a cipher in the TLS field produce two explicitly
unverified TLS-mode hypotheses. Explicit cipher, endpoint and authentication are
preserved. REALITY can try a Chrome fingerprint alternative without changing its
public key, UUID, short ID or SNI. Missing credentials, rejected server credentials,
unsupported extensions and inaccessible servers cannot be repaired by guessing.
TLS certificate verification is never disabled to obtain a passing result.

Hysteria 1 and 2 are disabled globally. Collection excludes these inputs before
testing and publication, including JSON profiles containing a Hysteria outbound
or transport. Independent entries in the same subscription remain eligible.

Ordinary TUIC and supported WireGuard inputs use the pinned
sing-box 1.14.4 driver. Native schemas have separate exports; they are not sent to
V2RayNG's Xray import. WireGuard uses the userspace endpoint schema. An Xray
WireGuard FinalMask that sing-box cannot represent retains its Xray path. Arbitrary
multi-outbound native chains and unknown active extensions are not silently
flattened or discarded. Each unsupported input retains an explicit diagnostic.

HTTPS destinations run in a pool of two. After both succeed, application-site,
DNS/UDP/QUIC and payload checks run concurrently in a pool of three. Payload
upload and download run together; the post-load check waits for both. All run
through the same exact candidate and sandbox. Limits, public-endpoint allowlists,
TLS verification, core pins, shared memory permits and CPU admission remain.
A failed destination receives one bounded retry; another site cannot silently
replace a failed required destination. HTTPS alone is insufficient: healthy
publication requires the transport evidence and full 2 MiB download/1 MiB upload.

A successful receipt can be shared only with an owned, current preparation whose
candidate SHA-256, format and pipeline version are identical. The tested timestamp
and expiry are copied unchanged and the original tested raw hash is recorded as
provenance. Changed credentials, routing or template bytes require a new test.
Concurrent jobs for the same prepared bytes are coalesced. Leased jobs are never
overwritten by background preparation or receipt reuse.

## Exports

`GET /api/prepared/export` accepts:

| Parameter | Meaning |
|---|---|
| `source` | Optional source ID; omission includes all eligible sources |
| `engine` | `xray` (default) or `sing-box` |
| `single=1` | One JSON object, rotating independently by source/engine/group |
| `healthy=1` | Compatibility parameter; fresh exact-byte health proof is always required |
| `id` | Optional canonical config ID |

Xray group exports are JSON arrays. Native group exports are JSONL; single
exports are JSON objects. The `X-Verification-Scope`, `X-Config-Engine` and
`X-Config-Count` headers identify the result. Public links cannot publish unverified preparation. Existing healthy Xray links keep their format.
Disabled, deleted, expired or excluded members cannot enter prepared exports.
Ownership and health are rechecked under the writer before publication.

Schema44 adds expiring exact-candidate receipts, FIFO scheduling and rotation cycle counters.
Existing Residential evidence pins the unchanged Xray envelope contract separately
from ordinary preparation policy; this queue update does not reset that evidence.
Datacenter/CDN classification remains an independent background pipeline.

## Complete accounting and fair scheduling

Every current source input has exactly one exclusive coverage state: ready,
queued, running, structural, connection_failed, environment, expired, paused or
withheld. Their sum equals the source inventory, including safety-gated inputs.
Paused/withheld members list their canonical IDs and reason without bypassing
Residential or deletion guards. Network exports retain only eligible members. Tested and core_passed are separate progress counters.
Network groups show full received inventory separately from usable raw and tested
templates. Usable raw count equals Xray plus native template count; no second
candidate-hash deduplication can silently drop a distinct canonical identity.
`received.txt` preserves diagnostic inventory, including unverified items. Native
profiles use their own sing-box links. Residential counts use the same eligible
identity set for raw and tested templates, preserving all existing guards.

First-time probes use persistent FIFO age and three of every four claim priority
turns; the fourth prioritizes due retests. Source churn cannot repeatedly let new
low hashes bypass older work. A bounded cache survives ordinary response churn
only for byte-identical tested candidates. Original proof timestamps and expiry
never extend. Explicit deletion forgets unowned receipts; a newer failed/partial
probe invalidates older equivalent proof. Leases and membership checks remain.

## IPv6 and parallel transport probes

IPv6 endpoints use a scoped, unprivileged TCP/UDP byte relay through the host's
existing IPv6 route. Exact endpoint allowlists, namespace DNAT, per-veth rules,
bounded sessions and cleanup isolate it from other projects. It does not terminate
TLS or change template credentials, routing or bytes. Global forwarding is not
changed. Unsupported endpoint ranges fail explicitly rather than bypass isolation.
The five independent DNS/QUIC transport checks run concurrently. Authenticated
HTTP/3 can independently prove QUIC when version negotiation is filtered, while
DNS, required HTTPS destinations and upload/download remain mandatory. A failed
QUIC negotiation alone is never relabelled as a successful probe.

## Bounded recovery and renewal fairness

Ordinary probes publish a short-lived memory demand when small jobs keep taking
the available shared permits. Smaller new admissions briefly defer; running jobs,
collection's bounded control reserve and the host memory floor remain intact.
Residential initial/follow-up slots are interleaved even under partial admission.
Every third follow-up turn gives the oldest due expired accepted proof a chance
before repeatedly urgent work. Expired proof stays unpublished; no evidence TTL
is extended. The panel separates due, running, scheduled and paused renewals.

Full 2MiB download, acknowledged 1MiB upload and post-load HTTPS remain mandatory.
Only a transient failed leg receives one fresh HTTP/1.1 retry with a bounded
30–45s transfer budget; successful legs are not repeated. TLS rejection is never
relaxed. A closed/reset proxy session receives one new exact-config session,
with fresh endpoint resolution, before recording the final failure. Authentication
failures do not trigger guessed credentials. Immediately verified same-core syntax
is reused within that one job; actual connection proof is always measured.

Absent HTTP-camouflage Host values are omitted from candidates, preserving explicit
hosts and immutable raw data. The fixed-destination compatibility driver preserves
TCP Fragment on supported TCP transports, including its original settings. Unknown
masks, UDP carrier masks and destination overrides still require a suitable driver.
Core/app import checks and real connectivity decide whether the result is usable.

Residential lease renewal and completion look up the claimed hash directly in
the authoritative inventory view. They do not materialize the historical set on
each heartbeat; ownership, exclusions, Iran guards, revision and lease expiry are
still checked under the writer reservation. Public raw/template downloads rebuild
a concurrently revoked snapshot once before publishing any bytes. Repeated churn
returns a retryable error instead of stale proof or a partially written response.
Network template exports reuse the canonical conversions already selected by the
network query, avoiding a second full conversion ranking for the same group.
