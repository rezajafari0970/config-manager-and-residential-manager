# Operations

The public product name is Config manager and residential manager. Existing `config-repair` filesystem and service names are retained for upgrade compatibility.

## Paths and services

| Purpose | Path/service |
|---|---|
| Panel and collector | `config-repair.service` |
| Ordinary validation | `config-repair-prober.service` |
| Residential investigation | `config-repair-egress.service` |
| Country refresh | `config-repair-country-update.timer` |
| Releases and runtime cores | `/opt/config-repair/` |
| Encrypted SQLite data and blobs | `/var/lib/config-repair/` |
| Encryption key and origin | `/etc/config-repair/panel.json` |
| Fresh-install login | `/etc/config-repair/access.txt` |
| Nginx virtual host | `/etc/nginx/conf.d/config-manager-residential.conf` |

Back up the database, its WAL (if present), immutable blob directory, panel configuration including the encryption key, and the matching release together while all three application services are stopped. Keep this backup private. Losing the key makes encrypted state unreadable. Never upload these files to GitHub.

## Upgrade and recovery

The automatic installer owns only its marked installation. It will refuse an unmarked older deployment or architecture mismatch. Upgrade preparation downloads/verifies and builds the new release before stopping services. A stopped backup is made for a changed release; `panel.json`, existing password and key are preserved. A failed download/build leaves the current services untouched. After a failed cutover inspect systemd logs and preserve the current database: do not blindly restore an older snapshot over resumed collector writes.

For an unmarked historical deployment, use a planned migration: take the shared `/var/lock/config-repair-deploy.lock`, stop the panel and every old worker including `config-repair-smart`, back up key/data/blobs and old units together, validate the new binary against a copy, remove the retired Smart unit and its owned sandbox resources, install the new release, then start only the three services above. Do not run a schema-40 binary against schema 41. Preserve ordinary sources, exclusions, rotations, Residential evidence and revocation ledgers. Reclaim removed-feature blobs only after confirming that no retained table references their hash.

The schema-41 cleanup retains only migration references to the retired names. Those references are necessary to remove historical tables safely; they do not register an API, UI, worker or generator. Original user-provided raw configurations can still contain Xray balancing fields; the importer preserves their bytes and does not turn them into a Smart product feature.

## Network and TLS

The installer enables IPv4 forwarding in a dedicated sysctl file. Probe sandboxes use uniquely named nftables tables; no host firewall is flushed. Existing provider or host forwarding/firewall policies may need operator adjustment. Only open the configured HTTPS port to intended administrators. The internal panel port 18191 must remain loopback-only.

Self-signed TLS permits initial encrypted administration but subscription clients generally need a publicly trusted certificate. Replace `/etc/config-repair/tls.crt` and `tls.key` with the full chain/private key for the configured hostname, retain restrictive private-key permissions, and reload Nginx. Never solve certificate rejection by disabling verification in exported VPN configurations.

If hosted behind NAT, pass `CMRM_HOST` on first install. Changes to the public hostname or port require coordinated origin, certificate and Nginx changes; the installer rejects accidental changes on rerun.

If another application already listens on TCP 18443, choose a free port with `export CMRM_PORT=18444` before the first installation. Do not stop the other application to free its port. The internal loopback port 18191 must also be available.

The country updater preserves last-good datasets and retries daily. Inspect `/var/lib/config-repair/country/update-status.json` if the installer reports incomplete country data. No healthy/Residential result is manufactured when evidence is missing.


## A download shows zero bytes

The bootstrap prints the source URL and transport for each attempt. It downloads directly from GitHub codeload first, then tries the official archive URL if needed. Downloads abort after 20 seconds below one byte per second, use an eight-second connection timeout, and share a total retry budget (120 seconds for source; 300 seconds per pinned dependency). Automatic transport selection falls back to IPv4 with HTTP/1.1. Set `CMRM_IP_VERSION=4` or `6` before running the README command to select an address family explicitly. This does not change system DNS or IPv6 configuration. TLS verification and dependency checksums remain mandatory.

If the budget expires, the installer reports the failed URL and stops; fix DNS/HTTPS reachability and rerun the same command. The bootstrap download in the README also has connection, idle-transfer and total-attempt limits. A transient stall does not by itself establish an IPv6 or application fault. Compilation is announced separately with a `[build]` line and can legitimately take several minutes.
