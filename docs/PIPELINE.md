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

Ordinary Hysteria 1/2, TUIC and supported WireGuard inputs use the pinned
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
| `single=1` | One JSON object, rotating independently by source/engine/health mode |
| `healthy=1` | Require fresh health proof for the exact prepared bytes |
| `id` | Optional canonical config ID |

Xray group exports are JSON arrays. Native group exports are JSONL; single
exports are JSON objects. The `X-Verification-Scope`, `X-Config-Engine` and
`X-Config-Count` headers identify the result. Prepared-only links are explicitly
labelled unverified in the panel. Existing healthy Xray links keep their format.
Disabled, deleted, expired or excluded members cannot enter prepared exports.
Ownership and health are rechecked under the writer before publication.

Schema43 adds only preparation references and an independent rotation cursor.
Existing Residential evidence pins the unchanged Xray envelope contract separately
from ordinary preparation policy; this queue update does not reset that evidence.
Datacenter/CDN classification remains an independent background pipeline.
