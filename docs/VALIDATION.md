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
