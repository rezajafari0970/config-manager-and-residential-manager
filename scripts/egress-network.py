"""Classify only the public source observed on an authenticated Ads connection.

The snapshot builder owns origin and usage data. Workers open immutable snapshots
read-only and do indexed longest-prefix lookups without sending source IPs out.
"""
import hashlib
import importlib
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import stat
import time

VERSION = "ads-exit-network.v1"
SNAPSHOT = "/var/lib/config-repair/network/egress-network.sqlite"
MMDB_CONFIG = "/etc/config-repair/egress-access-mmdb.json"
PROOF_TTL_MS = 600_000
SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def unknown(reason, at):
    return {"version": VERSION, "kind": "unknown", "reason": reason, "checked_at": at}


def public_address(value):
    if not isinstance(value, str):
        return None
    try:
        ip = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    if not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, "scope_id", None):
        return None
    return ip


def authorized_origins(value):
    # Some providers can legitimately announce a usage block from several ASNs.
    # The observed BGP route must still have exactly one unambiguous origin.
    if type(value) is int:
        origins = [value]
    elif isinstance(value, str) and len(value) < 352:
        fields = value.split(",")
        if len(fields) > 32 or not all(re.fullmatch(r"[1-9][0-9]{0,9}", field) for field in fields):
            return ()
        origins = [int(field) for field in fields]
    else:
        return ()
    return origins if all(0 < asn <= 4294967295 for asn in origins) else ()


def prefix_lookup_query(table, fields, width):
    # Candidate-first preserves an indexed (family,length,start) lookup per
    # possible prefix length, independent of the number of routes in the DB.
    sql_values = ",".join("(?,?)" for _ in range(width + 1))
    return (
        f"WITH candidates(n,addr) AS (VALUES {sql_values}) SELECT {fields} "
        f"FROM candidates c CROSS JOIN {table} t "
        "WHERE t.family=? AND t.length=c.n AND t.start=c.addr "
        "ORDER BY c.n DESC LIMIT 1"
    )


USAGE_QUERIES = {
    family: prefix_lookup_query("usage", "t.length,t.kind,t.provider,t.asn,t.source,t.valid_until", width)
    for family, width in ((4, 32), (6, 128))
}
ORIGIN_QUERIES = {
    family: prefix_lookup_query("origins", "t.asn,t.length", width)
    for family, width in ((4, 32), (6, 128))
}


def hosting_coverage_until(db, now):
    # Read the same registry that built the immutable index. V45 snapshots
    # already retain each feed's last successful refresh and parsed row count.
    builder = importlib.import_module("egress-network-update")
    feeds = [feed for feed in builder.FEEDS if feed.kind == "hosting"]
    earliest = None
    for feed in feeds:
        row = db.execute("SELECT status,checked_at,records,sha256 FROM feed_status WHERE source=?",
                         (feed.source,)).fetchone()
        if row is None:
            return 0
        status, checked, count, digest = row
        if (status not in ("current", "last-good") or type(count) is not int or count < feed.minimum
                or type(checked) is not int or not now - builder.TTL < checked <= now + 2000
                or not isinstance(digest, str) or not DIGEST.fullmatch(digest)):
            return 0
        expires = checked + builder.TTL
        earliest = expires if earliest is None else min(earliest, expires)
    return earliest or 0


def public_origin(asn):
    return (type(asn) is int and 0 < asn < 4_200_000_000 and asn != 23456
            and not 64496 <= asn <= 65551)


def prefix_candidates(ip):
    value = int(ip)
    width = ip.max_prefixlen
    args = []
    for prefix_len in range(width, -1, -1):
        bits = width - prefix_len
        start = (value >> bits << bits).to_bytes(width // 8, "big")
        args.extend((prefix_len, start))
    args.append(ip.version)
    return args


class LicensedAccess:
    """Optional local usage driver. Origin corroboration remains in the registry."""

    def __init__(self, config):
        self.config = pathlib.Path(config)
        self.key = None
        self.readers = []
        self.files = []
        self.digest = ""
        self.until = 0
        self.retry_at = 0

    def close(self):
        for reader in self.readers:
            reader.close()
        self.readers.clear()
        self.files.clear()
        self.key = None
        self.until = 0
        self.digest = ""

    @staticmethod
    def trusted(st, max_size):
        return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and 0 < st.st_size <= max_size

    @staticmethod
    def generation(st):
        return st.st_dev, st.st_ino, st.st_ctime_ns, st.st_size

    def refresh(self, at):
        if time.monotonic() < self.retry_at:
            return
        try:
            st = self.config.lstat()
            if not self.trusted(st, 8192):
                raise ValueError("untrusted MMDB manifest")
            key = self.generation(st)
            if key == self.key and all(self.generation(p.stat()) == gen for p, gen in self.files):
                return
            self.close()
            import maxminddb  # Optional dependency, only for an enrolled host.
            with self.config.open("rb") as stream:
                if self.generation(os.fstat(stream.fileno())) != key:
                    raise ValueError("manifest replaced")
                manifest = json.loads(stream.read())
            digests = []
            untils = []
            for role, types in (("connection", ("GeoIP2-Connection-Type",)),
                                ("asn", ("GeoIP2-ISP", "GeoLite2-ASN"))):
                entry = manifest[role]
                path = pathlib.Path(entry["path"])
                if not path.is_absolute() or not DIGEST.fullmatch(entry["sha256"]):
                    raise ValueError("invalid MMDB manifest")
                with path.open("rb") as f:
                    st_file = os.fstat(f.fileno())
                    if not self.trusted(st_file, 512 * 1024 * 1024):
                        raise ValueError("untrusted MMDB file")
                    gen = self.generation(st_file)
                    if hashlib.file_digest(f, "sha256").hexdigest() != entry["sha256"]:
                        raise ValueError("MMDB checksum")
                    if self.generation(os.fstat(f.fileno())) != gen:
                        raise ValueError("MMDB changed while verifying")
                    reader = maxminddb.open_database("/proc/self/fd/" + str(f.fileno()))
                self.readers.append(reader)
                self.files.append((path, gen))
                metadata = reader.metadata()
                build = metadata.build_epoch * 1000
                if (metadata.database_type not in types or type(build) is not int
                        or build <= 0 or build > at + 2_000):
                    raise ValueError("invalid MMDB metadata")
                untils.append(build + 45 * 86_400_000)
                digests.append(entry["sha256"])
            self.until = min(untils)
            self.digest = hashlib.sha256("".join(digests).encode()).hexdigest()
            self.key = key
        except Exception:
            # Reader plugins raise version-specific exceptions on invalid data.
            # An unavailable optional dataset cannot abort the route/Iran probe.
            self.close()
            self.retry_at = time.monotonic() + 30

    def lookup(self, ip, at):
        self.refresh(at)
        if not self.readers or self.until <= at:
            return None
        try:
            usage, length = self.readers[0].get_with_prefix_len(str(ip))
            origin = self.readers[1].get(str(ip)) or {}
            asn = origin.get("autonomous_system_number")
            if (not usage or usage.get("connection_type") not in ("Cable/DSL", "Cellular")
                    or type(asn) is not int or not authorized_origins(asn)):
                return None
            return length, "access", "as" + str(asn), asn, "maxmind-connection-type", self.until
        except Exception:
            return None


class NetworkRegistry:
    def __init__(self, snapshot=SNAPSHOT, mmdb_config=MMDB_CONFIG):
        self.path = pathlib.Path(snapshot)
        self.licensed = LicensedAccess(mmdb_config)
        self.key = None
        self.db = None
        self.meta = {}

    def close(self):
        if self.db is not None:
            self.db.close()
        self.key = None
        self.db = None
        self.meta = {}
        self.licensed.close()

    def refresh(self):
        try:
            stat = self.path.stat()
            key = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            if key == self.key:
                return
            self.close()
            uri = self.path.resolve().as_uri() + "?mode=ro&immutable=1"
            self.db = sqlite3.connect(uri, uri=True)
            self.db.execute("PRAGMA query_only=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA cache_size=-256")
            meta = dict(self.db.execute("SELECT key,value FROM meta LIMIT 16"))
            if (meta.get("version") != VERSION or not DIGEST.fullmatch(meta.get("dataset", ""))
                    or not SLUG.fullmatch(meta.get("origin_source", ""))):
                raise ValueError("invalid network metadata")
            meta["origin_valid_until"] = int(meta["origin_valid_until"])
            # Incomplete coverage disables negative range evidence only. Positive
            # ownership remains independently usable for supported snapshots.
            try:
                meta["hosting_coverage_until"] = hosting_coverage_until(self.db, time.time_ns() // 1_000_000)
            except (ImportError, sqlite3.Error):
                meta["hosting_coverage_until"] = 0
            self.meta = meta
            self.key = key
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
            self.close()

    def lookup(self, ip, at):
        if self.db is None:
            return unknown("network_snapshot_unavailable", at)
        if self.meta["origin_valid_until"] <= at:
            return unknown("network_origin_expired", at)
        args = prefix_candidates(ip)
        dataset = self.meta["dataset"]
        try:
            usage = self.db.execute(USAGE_QUERIES[ip.version], args).fetchone()
            if usage is None:
                usage = self.licensed.lookup(ip, at)
                if usage is None:
                    return self.unclassified_origin(ip, args, at)
                dataset = hashlib.sha256((dataset + self.licensed.digest).encode()).hexdigest()
            prefix_len, kind, provider, expected_asn, usage_source, until = usage
            if kind not in ("hosting", "access"):
                return unknown("network_usage_conflict", at)
            if type(until) is not int or until <= at:
                return unknown("network_usage_expired", at)
            permitted = authorized_origins(expected_asn)
            if (not SLUG.fullmatch(provider) or not SLUG.fullmatch(usage_source)
                    or not permitted or usage_source == self.meta["origin_source"]
                    or not 0 < prefix_len <= ip.max_prefixlen):
                return unknown("network_usage_unverified", at)
            origin = self.db.execute(ORIGIN_QUERIES[ip.version], args).fetchone()
            if origin is None:
                return unknown("network_origin_unavailable", at)
            if type(origin[0]) is not int or origin[0] not in permitted:
                return unknown("network_origin_conflict", at)
            if kind == "access" and self.db.execute("SELECT 1 FROM hosting_asns WHERE asn=?", (origin[0],)).fetchone():
                return unknown("network_usage_conflict", at)
        except (sqlite3.Error, TypeError, ValueError):
            return unknown("network_snapshot_invalid", at)
        return {
            "version": VERSION,
            "kind": kind,
            "provider": provider,
            "family": ip.version,
            "prefix_len": prefix_len,
            "asn": origin[0],
            "usage_source": usage_source,
            "origin_source": self.meta["origin_source"],
            "dataset": dataset,
            "checked_at": at,
            "valid_until": min(at + PROOF_TTL_MS, until, self.meta["origin_valid_until"]),
        }

    def unclassified_origin(self, ip, args, at):
        result = unknown("network_usage_unverified", at)
        until = min(self.meta["origin_valid_until"], self.meta["hosting_coverage_until"], at + PROOF_TTL_MS)
        if until <= at or self.meta["origin_source"] != "ripe-ris":
            return result
        origin = self.db.execute(ORIGIN_QUERIES[ip.version], args).fetchone()
        if not origin:
            return result
        asn, length = origin
        if not public_origin(asn) or not 0 < length <= ip.max_prefixlen:
            return result
        if self.db.execute("SELECT 1 FROM hosting_asns WHERE asn=?", (asn,)).fetchone():
            return result
        # This only supports comparison to a previously observed hosting ASN on
        # the same Ads flow. A fresh, unmatched ASN does not identify an ISP.
        result.update(origin_outside_hosting=True, origin_source=self.meta["origin_source"],
                      asn=asn, family=ip.version, prefix_len=length,
                      dataset=self.meta["dataset"], valid_until=until)
        return result

    def attach(self, rows):
        observed = [row for row in rows if all(row.get(k) is True for k in
                    ("actual_ads", "echo", "same_stream", "tls", "response_complete"))]
        if not observed:
            return
        self.refresh()
        at = time.time_ns() // 1_000_000
        batch = {}
        for row in observed:
            ip = public_address(row.get("ip"))
            if ip is None or ip.version != row.get("family"):
                row["network"] = unknown("network_source_invalid", at)
                continue
            if ip not in batch:
                batch[ip] = self.lookup(ip, at)
            row["network"] = batch[ip]
