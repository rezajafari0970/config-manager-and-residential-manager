# Validation

The following checks completed for the initial release on 17 November 2026:

- Complete Go test suite: passed.
- `go vet ./...`: passed.
- Focused race checks for retired-feature migration and admission: passed.
- Python suites for ordinary probing, compatibility, payload receipts, Residential classification, country providers, health and delivery: passed.
- JavaScript suites for API requests, polling, settings isolation, source state and Residential scheduling: passed.
- Real Chromium panel test at mobile and desktop widths, including restart persistence: passed.
- Schema 40 → 41 migration rehearsed twice against a private copy of the operational database: 38 retained tables matched by content hashes; SQLite integrity and foreign-key checks passed.
- Deployment on the existing Ubuntu 26.04 amd64 server: panel, ordinary worker and Residential worker healthy; retired routes return 404 and the retired unit is absent.
- Fresh Ubuntu 24.04 amd64 installation in an isolated systemd/cgroup-v2 test environment: passed, including pinned downloads, sandbox preflight, build and service startup.

Installer upgrade and repeated same-version installation both passed. Existing encryption key, login credentials and schema were preserved; same-version rerun skipped rebuilding and creating another backup. HTTPS authentication, subscription isolation, database integrity, both country providers, shared resource-budget permissions and the native sing-box sandbox passed. Debian 12/13 are accepted by prerequisite checks but have not yet been installation-tested. ARM and Windows are unsupported. Live Android/mobile-operator testing was not performed for this removal and installer change.

The independent public repository was published through a repository-scoped SSH deploy key. Anonymous downloads of `install.sh` and the GitHub source archive passed; all 341 archive files matched the prepared release at commit `aada71b7eabcc5ce83bb4c22a14dcead88e0c43d`. Private runtime data and the original project's Git history are excluded.

The exact README one-command bootstrap was then run on another fresh Ubuntu 24.04 amd64 systemd/cgroup-v2 environment, limited to one CPU and 2 GiB RAM. It downloaded the public source and dependencies, built the application and completed with exit code 0 in 183.77 seconds. All three services were active and enabled; authenticated panel pages returned 200, anonymous access returned 401, retired Smart routes returned 404, and invalid subscription tokens returned 404. Schema 41, SQLite integrity, both country providers, resource-budget permissions and the native sing-box sandbox passed. The isolated test instance was removed after collecting sanitized results. Installation duration depends on the server and network.

Download recovery was verified with a real local HTTPS fault server: successful pinned downloads, truncated responses, HTTP failures with alternate sources, the total deadline, recovery from a 20-second idle transfer, checksum rejection, size limits, TLS certificate rejection and the dependency-download entrypoint passed. Existing destination files survived failed downloads and temporary partial files were removed.

The updated public installer at `e8c0d76f1b92331ede0ff2dc589cd05c0cc56ed7` completed a fresh installation on Ubuntu 26.04 amd64 in 148.75 seconds, with installer CPU limited to one core and memory capped at 1800 MiB. An existing service occupied the default HTTPS port, so `CMRM_PORT` selected a free alternative. The existing listener and Nginx master retained their process IDs. Authenticated panel routes, all three enabled services, schema 41, database integrity, both country providers and the native sandbox passed. An external HTTPS request reached the authenticated panel with certificate verification enabled. The earlier zero-byte network stall was not reproduced during live diagnosis; both IPv4 and IPv6 worked, so no specific network root cause is asserted.

Datacenter/CDN grouping (2026-11-17): the complete Go suite, focused race checks and `go vet` passed on the target Linux server. The isolated browser harness passed both restart phases, including 18 group cards, 36 links and mobile/desktop overflow checks. Live attribution canaries passed for all 10 configured hosting providers and all five CDN feeds; Google Cloud uses its dedicated published service prefixes as well as Google origin ASNs. These are network attribution checks, not Android connectivity tests.

The additive schema42 migration was rehearsed twice against a current database copy and deployed under the shared lock with a matched backup. All 37 pre-existing tables and the Residential policy epoch were preserved. All three services were verified against their binary checksums; Nginx retained its process identity. The initial deployment took 24.793 seconds from service stop to panel readiness. A subsequent raw-export concurrency refinement restarted only the panel, becoming ready in 2.082 seconds; other binaries were unchanged.

Production verification checked all 36 scoped links with HEAD and decrypted the original stored bodies in memory to verify raw membership across 14 populated groups. Every group with an available healthy candidate returned its exact stored template bytes. Raw exports admit new arrivals on the next request, while actual member revocation or reclassification may return a retryable 503. The live mobile/desktop page and inline raw/single-template link navigation passed without JavaScript errors. Initial classification runs asynchronously; pending and expired entries remain in Unknown until fresh evidence is available.

Independent preparation and native drivers (2026-11-17): the complete Go suite,
`go vet`, focused race checks, 18 live-probe Python tests, four payload tests and
source-status/diagnostic JavaScript tests passed. The actual pinned sing-box core
accepted the Hysteria 1, Hysteria 2 and userspace WireGuard schema matrix. The
isolated worker integration completed all 13 samples, including six live samples;
all 13 passed their core checks and four passed full connection/payload checks.
One verified connection used the native driver. Invalid or inaccessible endpoints
remained rejected. The same harness verified recovery after killing a worker.
These are server-side checks; no Android or mobile-operator test is claimed.

Schema 42 to 43 was rehearsed twice on a private operational database copy. The
38 unaffected tables matched exactly; retained conversion rows were unchanged,
with only the existing expiry/ownership reconciliation applied. Integrity,
foreign keys and the Residential epoch passed. Deployment used a matched backup.
All three services were active and checked against their release checksums; the
Nginx process was preserved. Initial stop-to-ready time was 34.162 seconds. A
subsequent preparation batching refinement restarted only the panel in 2.234
seconds; ordinary and Residential workers retained their process identities.

A controlled single-run comparison on the same private database copy and the
same 128 raw input hashes measured preparation/persistence at 9691.618 ms before
batching and 275.947 ms after batching (97.153% less elapsed time for that stage).
Both runs used existing encrypted blobs; filesystem caches and shared-host load
were not independently controlled. This is not a whole-system, network-test or
99% end-to-end speed claim. A separate synthetic regression prepared 200 inputs
in 85.698 ms while verifying ownership and health isolation.

After the refinement, the live preparation backlog was zero for 1523 eligible
raw inputs: 1472 had templates (including five native templates), and 51 had
explicit structural diagnostics. Canonical deduplication produced 1405 Xray
profiles and five native profiles in the group exports at that snapshot. Both
group formats and both single-profile rotations returned valid JSON/JSONL with
HTTP 200. Health tests continue independently and prepared-only output is clearly
marked unverified. Counts change as sources refresh and memberships expire.
Live Chromium checks passed Input, Output and Datacenter pages at 390 and 1440
pixels without JavaScript errors or horizontal overflow; prepared single-profile
navigation also passed. Existing datacenter/CDN and Residential pipelines remain
separate from template preparation.

Coverage and exact-candidate receipts, P76 (2026-11-17): this release supersedes
P75's public prepared-only export policy. Public prepared links now require fresh
core and connection proof. Received diagnostic inventory remains separately visible.
The 17-input regression returned exactly 17 verified raw/templates, then 16 after
one connection failure, with all 17 inputs accounted for. Mixed Xray/native group
counts, FIFO fairness, cache reuse without expiry extension, failure revocation,
explicit deletion and non-consuming HEAD/prefetch checks passed.

The complete Go suite and vet passed on the target host, as did focused race
checks, 18 Python sandbox tests, four payload tests and the JavaScript source and
diagnostic suites. The isolated real worker test completed all 13 inputs including
six live samples and recovered from SIGKILL. Twelve passed core validation; four
reported connection success (three full verified payload results and one explicit
application-site-unavailable diagnostic). Other results were one native format
rejection, one DNS failure, six deliberately nonpublic fixtures and one incomplete
transport result. Failed results were not promoted into healthy output. Two-phase
Chromium acceptance passed, including mobile/desktop layout and restart persistence.

An actual isolated IPv6 sandbox control passed IPv6 HTTPS, IPv4 HTTPS and IPv6 UDP
DNS, denied unlisted and subsequently revoked destinations, and left host global
forwarding settings unchanged. This proves sandbox capability, not connectivity of
every IPv6 proxy. Schema43 to 44 was rehearsed twice on a private database copy;
39 existing table checks and the Residential epoch were preserved, with integrity
and foreign-key checks passing. No Android/mobile-operator run or 99% end-to-end
performance improvement is claimed. Existing P75 preparation timing above is a
stage-specific historical measurement, not a new whole-system benchmark.

The final source-inventory check also identified safety-gated members that were
omitted from the old eligible-only summary. Source coverage now includes paused
and withheld identities, with their reason and ID. A 17-input regression verifies
12 healthy + two paused + three safety-gated inputs, with no omission or overlap.
The complete Go suite, focused race and source-status checks passed again after
this accounting correction. Publication guards remain unchanged.
