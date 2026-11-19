#!/usr/bin/env python3
"""Build the private, atomic Ads exit network index from independent public feeds."""
import argparse
import csv
import datetime
import email.utils
import fcntl
import gzip
import hashlib
import importlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
import unicodedata
from typing import NamedTuple
import urllib.parse
import urllib.request

VERSION = 'ads-exit-network.v1'
DAY = 86_400_000
TTL = 3 * DAY
MIB = 1024 * 1024
RIS = 'https://www.ris.ripe.net/dumps/riswhoisdump.IPv{}.gz'
DEFAULT_DIR = '/var/lib/config-repair/network'
DEFAULT_ALLOCATIONS = '/etc/config-repair/egress-network-allocations.json'
SLUG = r'[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?'
SERVICE_ASNS = {13335, 54113, 20940, 16625, 199524, 202306, 205718, 203020, 60068, 209242}


def download(url, limit):
    """Only verified TLS to this feed's hosts, and bounded wire bytes."""
    host = urllib.parse.urlsplit(url).hostname
    allowed = {host}
    if host in {'digitalocean.com', 'www.digitalocean.com'}:
        allowed.update({'digitalocean.com', 'www.digitalocean.com'})
    if host == 'www.ris.ripe.net':
        allowed.add('ris.ripe.net')

    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            nxt = urllib.parse.urlsplit(newurl)
            if nxt.scheme != 'https' or nxt.hostname not in allowed or nxt.port not in (None, 443) or nxt.username:
                raise ValueError('unexpected_redirect')
            return super().redirect_request(request, fp, code, message, headers, newurl)

    req = urllib.request.Request(url, headers={'User-Agent': 'ConfigManager-Egress-Network/1', 'Accept-Encoding': 'identity'})
    with urllib.request.build_opener(Redirect()).open(req, timeout=25) as response:
        if response.status != 200 or int(response.headers.get('Age', '0')) > TTL // 1000:
            raise ValueError('stale_or_incomplete_http')
        data = response.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError('feed_size')
        return data, response.headers


def published_csv(body):
    for row in csv.reader(io.StringIO(body.decode('utf-8-sig'))):
        if row and row[0].strip() and not row[0].lstrip().startswith('#'):
            yield row[0].strip()


def aws(body):
    obj = json.loads(body)
    for row in obj['prefixes'] + obj['ipv6_prefixes']:
        if row['service'] == 'EC2':
            yield row.get('ip_prefix') or row['ipv6_prefix']


def google(body):
    for row in json.loads(body)['prefixes']:
        if row.get('service') == 'Google Cloud':
            yield row.get('ipv4Prefix') or row['ipv6Prefix']


def oracle(body):
    for region in json.loads(body)['regions']:
        for row in region['cidrs']:
            if 'OCI' in row['tags']:
                yield row['cidr']


def azure(body):
    # The landing page has a dated vendor download link (not a stable data URL).
    candidates = re.findall(rb'https://download\.microsoft\.com/download/[A-Za-z0-9/-]+/ServiceTags_Public_(\d{8})\.json', body)
    if not candidates:
        raise ValueError('azure_download_link')
    latest = max(candidates)
    url = re.search(rb'https://download\.microsoft\.com/download/[A-Za-z0-9/-]+/ServiceTags_Public_' + latest + rb'\.json', body).group().decode()
    released = datetime.datetime.strptime(latest.decode(), '%Y%m%d').replace(tzinfo=datetime.timezone.utc)
    if not datetime.timedelta(0) <= datetime.datetime.now(datetime.timezone.utc) - released < datetime.timedelta(days=35):
        raise ValueError('azure_release_stale')
    raw, _ = download(url, 16 * MIB)
    for group in json.loads(raw)['values']:
        if group['name'] == 'AzureCloud':
            yield from group['properties']['addressPrefixes']


def docomo(body):
    # Only standalone published CIDRs in the sp-mode service page. Ignore links,
    # other products, Javascript, exclusions, and future planned changes.
    from html.parser import HTMLParser

    class Parser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.values = []
            self.spmode = self.access = self.active = False
            self.heading = None
            self.title = ''

        def handle_starttag(self, tag, attrs):
            if tag in ('h2', 'h3', 'h4'):
                self.heading, self.title = tag, ''

        def handle_endtag(self, tag):
            if tag == self.heading:
                self.heading = None
                if tag == 'h2':
                    self.spmode = self.title.strip() == 'spモードサーバのIPアドレス帯域'
                self.access = self.spmode and tag == 'h3' and self.title.strip() == 'インターネットアクセス時'
                self.active = self.access

        def handle_data(self, value):
            if self.heading:
                self.title += value.strip()
            elif self.access:
                for candidate in unicodedata.normalize('NFKC', value).split():
                    if '予定' in candidate or '完了' in candidate:
                        self.active = '追加完了' in candidate and '予定' not in candidate
                    candidate = candidate.removesuffix('(IPv6)')
                    if self.active and re.fullmatch(r'[0-9a-fA-F:.]+/[0-9]{1,3}', candidate):
                        self.values.append(candidate)

    for encoding in ('utf-8', 'cp932'):
        try:
            decoded = body.decode(encoding)
            break
        except UnicodeDecodeError:
            pass
    else:
        raise ValueError('docomo_encoding')
    parser = Parser()
    parser.feed(decoded)
    return parser.values


def kddi(body):
    return importlib.import_module('egress-network-kddi').prefixes(body)


def ripe_url(name):
    query = urllib.parse.urlencode({'source': 'ripe', 'query-string': name, 'type-filter': 'inetnum', 'flags': 'no-referenced'})
    return 'https://rest.db.ripe.net/search.json?' + query


def registry_pool(name, maintainers, description=''):
    """A reviewed specific use declaration, not all space owned by an ISP."""
    def parse(body):
        for obj in json.loads(body)['objects']['object']:
            if obj.get('type') != 'inetnum' or obj.get('source', {}).get('id', '').lower() != 'ripe':
                continue
            attrs = {}
            for item in obj['attributes']['attribute']:
                attrs.setdefault(item['name'], []).append(item['value'].strip())
            if name not in [v.upper() for v in attrs.get('netname', [])]:
                continue
            if not set(maintainers).intersection(s.upper() for s in attrs.get('mnt-by', [])):
                continue
            if description and description not in ' '.join(attrs.get('descr', [])).lower():
                continue
            for value in attrs['inetnum']:
                start, end = value.split(' - ')
                yield from ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end))
    return parse


class Feed(NamedTuple):
    source: str
    provider: str
    kind: str
    asns: tuple
    url: str
    parse: object
    minimum: int = 1


FEEDS = (
    Feed('vultr-geofeed', 'vultr', 'hosting', (20473,), 'https://geofeed.constant.com/', published_csv, 50),
    Feed('digitalocean-geofeed', 'digitalocean', 'hosting', (14061,), 'https://www.digitalocean.com/geo/google.csv', published_csv, 50),
    Feed('linode-geofeed', 'linode', 'hosting', (63949,), 'https://ipgeo.akamai.com/linode-geofeed.csv', published_csv, 50),
    Feed('aws-ec2', 'amazon', 'hosting', (8987, 14618, 16509), 'https://ip-ranges.amazonaws.com/ip-ranges.json', aws, 50),
    Feed('google-cloud', 'google', 'hosting', (15169, 19527, 139070, 396982), 'https://www.gstatic.com/ipranges/cloud.json', google, 50),
    Feed('oracle-oci', 'oracle', 'hosting', (31898,), 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', oracle, 40),
    Feed('azure-cloud', 'microsoft', 'hosting', (8075,), 'https://www.microsoft.com/en-us/download/details.aspx?id=56519', azure, 50),
    Feed('ovh-vps', 'ovh', 'hosting', (16276,), ripe_url('OVH-VPS'), registry_pool('OVH-VPS', ('OVH-MNT',))),
    Feed('scaleway-dedibox', 'scaleway', 'hosting', (12876,), ripe_url('SCALEWAY-DEDIBOX-IPFO'), registry_pool('SCALEWAY-DEDIBOX-IPFO', ('ONLINE-NET-MNT',))),
    Feed('hetzner-cloud-nbg', 'hetzner', 'hosting', (24940, 213230, 212317, 215859), ripe_url('CLOUD-NBG1'), registry_pool('CLOUD-NBG1', ('HOS-GUN',))),
    Feed('hetzner-cloud-hel', 'hetzner', 'hosting', (24940, 213230, 212317, 215859), ripe_url('CLOUD-HEL1'), registry_pool('CLOUD-HEL1', ('HOS-GUN',))),
    Feed('docomo-spmode', 'docomo', 'access', (9605,), 'https://www.docomo.ne.jp/service/developer/smart_phone/spmode/', docomo, 20),
    Feed('kddi-mobile', 'kddi', 'access', (2516,), 'https://www.au.com/mobile/charge/internet-connection/network/', kddi, 2),
    Feed('unitymedia-b2c', 'vodafone-de', 'access', (3209,), ripe_url('UNITYMEDIA-B2C-POOL-NET'), registry_pool('UNITYMEDIA-B2C-POOL-NET', ('UNITYMEDIA-MNT', 'KABELBW-MNT', 'ISH-MNT', 'UMKBW-MNT'), 'dynamic dhcp b2c customer pool')),
)


def create_schema(db):
    db.executescript("""
        PRAGMA page_size=8192;
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-8192;
        CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE origins(family INTEGER,length INTEGER,start BLOB,asn INTEGER NOT NULL,PRIMARY KEY(family,length,start)) WITHOUT ROWID;
        CREATE TABLE usage(family INTEGER,length INTEGER,start BLOB,kind TEXT,provider TEXT,asn,source TEXT,valid_until INTEGER,PRIMARY KEY(family,length,start)) WITHOUT ROWID;
        CREATE TABLE records(source TEXT,family INTEGER,length INTEGER,start BLOB,kind TEXT,provider TEXT,asn,valid_until INTEGER,
                             PRIMARY KEY(source,family,length,start)) WITHOUT ROWID;
        CREATE TABLE hosting_asns(asn INTEGER PRIMARY KEY);
        CREATE TABLE operator_evidence(source TEXT,family INTEGER,length INTEGER,start BLOB,url TEXT,
                                       PRIMARY KEY(source,family,length,start)) WITHOUT ROWID;
        CREATE TABLE feed_status(source TEXT PRIMARY KEY,url TEXT,sha256 TEXT,checked_at INTEGER,records INTEGER,status TEXT) WITHOUT ROWID;
    """)


def insert_origins(db, family, compressed, minimum):
    sql = """INSERT INTO origins VALUES(?,?,?,?) ON CONFLICT(family,length,start) DO UPDATE SET asn=0 WHERE origins.asn!=excluded.asn"""
    batch = []
    count = expanded = 0
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        for line in stream:
            expanded += len(line)
            if len(line) > 65536 or expanded > 220 * MIB or count > 4_000_000:
                raise ValueError('origin_limits')
            if not line.strip() or line.lstrip().startswith((b'%', b'#')):
                continue
            fields = line.split()
            if len(fields) != 3 or not fields[2].isdigit():
                raise ValueError('origin_format')
            asn, prefix, peers = fields
            network = ipaddress.ip_network(prefix.decode('ascii'))
            if network.version != family:
                raise ValueError('origin_family')
            if network.prefixlen == 0:
                continue
            asn = asn.removeprefix(b'AS')
            # An explicit conflicting/poorly visible more-specific route masks its parent.
            n = int(asn) if asn.isdigit() and len(asn) <= 10 and int(peers) >= 3 else 0
            if not 0 < n < 4294967295:
                n = 0
            batch.append((family, network.prefixlen, network.network_address.packed, n))
            count += 1
            if len(batch) >= 4096:
                db.executemany(sql, batch)
                batch.clear()
    db.executemany(sql, batch)
    if db.execute('SELECT count(*) FROM origins WHERE family=?', (family,)).fetchone()[0] < minimum:
        raise ValueError('origin_truncated')
    return count


def usage_row(prefix, kind, provider, asns, source, expires):
    net = ipaddress.ip_network(prefix)
    if net.prefixlen < (8 if net.version == 4 else 12) or not net.network_address.is_global or net.is_multicast:
        raise ValueError('nonpublic_allocation')
    allowed = sorted(set(asns))
    if not allowed or len(allowed) > 32 or any(type(a) != int or not 0 < a < 4294967295 for a in allowed):
        raise ValueError('invalid_source_asn')
    expected = allowed[0] if len(allowed) == 1 else ','.join(map(str, allowed))
    return (source, net.version, net.prefixlen, net.network_address.packed, kind, provider, expected, expires)


def parse_operator(path, now):
    if not path.exists():
        return []
    with path.open('rb') as config:
        info = os.fstat(config.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * MIB:
            raise ValueError('operator_file_size')
        if path == Path(DEFAULT_ALLOCATIONS) and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError('untrusted_operator_file')
        raw = config.read(8 * MIB + 1)
    if len(raw) > 8 * MIB:
        raise ValueError('operator_file_size')
    data = json.loads(raw)
    if data.get('version') != VERSION or not isinstance(data.get('allocations'), list) or len(data['allocations']) > 50000:
        raise ValueError('operator_schema')
    rows = []
    reserved = {'ripe-ris'} | {f.source for f in FEEDS}
    for item in data['allocations']:
        source, provider, kind = item['source'], item['provider'], item['kind']
        if source in reserved or not re.fullmatch(SLUG, source) or not re.fullmatch(SLUG, provider) or kind not in ('access', 'hosting'):
            raise ValueError('operator_source')
        url = urllib.parse.urlsplit(item['evidence_url'])
        expiry = item['valid_until']
        if url.scheme != 'https' or not url.hostname or url.username or type(expiry) != int or expiry > now + 30 * DAY:
            raise ValueError('operator_provenance')
        if expiry > now:
            row = usage_row(item['prefix'], kind, provider, (item['asn'],), source, expiry)
            rows.append((row, item['evidence_url']))
    return rows


def feed_rows(feed, raw, now):
    rows = {usage_row(p, feed.kind, feed.provider, feed.asns, feed.source, now + TTL) for p in feed.parse(raw)}
    if not feed.minimum <= len(rows) <= 100000:
        raise ValueError('feed_incomplete')
    return sorted(rows)


def load_usage(db, feed, now, previous, fetch):
    try:
        raw, _ = fetch(feed.url, 16 * MIB)
        rows = feed_rows(feed, raw, now)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, ImportError, EOFError) as error:
        if previous:
            db.execute('INSERT INTO records SELECT * FROM old.records WHERE source=? AND valid_until>?', (feed.source, now))
            db.execute("INSERT INTO feed_status SELECT source,url,sha256,checked_at,records,'last-good' FROM old.feed_status WHERE source=? AND checked_at>?", (feed.source, now-TTL))
        db.execute('INSERT OR IGNORE INTO feed_status VALUES(?,?,?,?,?,?)', (feed.source, feed.url, '', 0, 0, 'unavailable'))
        return type(error).__name__
    db.executemany('INSERT INTO records VALUES(?,?,?,?,?,?,?,?)', rows)
    # Use canonical data actually parsed (also covers a dated Azure child download).
    digest = hashlib.sha256()
    for row in rows:
        digest.update(repr(row[:-1]).encode())
    db.execute('INSERT INTO feed_status VALUES(?,?,?,?,?,?)', (feed.source, feed.url, digest.hexdigest(), now, len(rows), 'current'))
    return None


def merge(db):
    # Equally specific contradictory declarations are explicit blockers. A
    # consensus here is still subject to longest-prefix origin at lookup time.
    db.execute("""INSERT INTO usage
        SELECT family,length,start,
            CASE WHEN count(DISTINCT kind||':'||provider||':'||asn)=1 THEN min(kind) ELSE 'unknown' END,
            min(provider),min(asn),min(source),min(valid_until)
        FROM records GROUP BY family,length,start""")
    asns = {n for f in FEEDS if f.kind == 'hosting' for n in f.asns} | SERVICE_ASNS
    for (value,) in db.execute("SELECT DISTINCT asn FROM records WHERE kind='hosting'"):
        asns.update(int(n) for n in str(value).split(','))
    db.executemany('INSERT INTO hosting_asns VALUES(?)', ((n,) for n in sorted(asns)))


def update(directory, allocations, fetch=download, minimums=(400000, 50000)):
    directory.mkdir(mode=0o700, exist_ok=True, parents=True)
    destination = directory / 'egress-network.sqlite'
    with (directory / 'update.lock').open('a') as lock, tempfile.TemporaryDirectory(prefix='build-', dir=directory) as work:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output = Path(work) / destination.name
        db = sqlite3.connect(output.resolve().as_uri(), uri=True)
        try:
            create_schema(db)
            previous = destination.is_file()
            if previous:
                db.execute('ATTACH DATABASE ? AS old', (destination.resolve().as_uri() + '?mode=ro&immutable=1',))
            now = int(time.time() * 1000)
            digest = hashlib.sha256(VERSION.encode())
            expiry = now + TTL
            for family, minimum in zip((4, 6), minimums):
                raw, headers = fetch(RIS.format(family), 48 * MIB)
                fetched = now
                if headers.get('Last-Modified'):
                    fetched = int(email.utils.parsedate_to_datetime(headers['Last-Modified']).timestamp() * 1000)
                if not now - TTL < fetched <= now + 300000:
                    raise ValueError('origin_source_expired')
                expiry = min(expiry, fetched + TTL)
                print(json.dumps({'origin_family': family, 'rows': insert_origins(db, family, raw, minimum)}), flush=True)
                digest.update(hashlib.sha256(raw).digest())
                del raw
            failures = {}
            for feed in FEEDS:
                error = load_usage(db, feed, now, previous, fetch)
                if error:
                    failures[feed.source] = error
            custom = parse_operator(allocations, now)
            for row, evidence_url in sorted(custom):
                db.execute('INSERT INTO records VALUES(?,?,?,?,?,?,?,?)', row)
                db.execute('INSERT INTO operator_evidence VALUES(?,?,?,?,?)', (*row[:4], evidence_url))
                digest.update(repr((row, evidence_url)).encode())
            for row in db.execute('SELECT source,sha256,checked_at FROM feed_status ORDER BY source'):
                digest.update(repr(row).encode())
            if not db.execute('SELECT 1 FROM records LIMIT 1').fetchone():
                raise ValueError('no_usable_allocation_sources')
            merge(db)
            meta = {'version': VERSION, 'dataset': digest.hexdigest(), 'origin_source': 'ripe-ris', 'origin_valid_until': str(expiry)}
            db.executemany('INSERT INTO meta VALUES(?,?)', meta.items())
            counts = dict(db.execute('SELECT kind,count(*) FROM usage GROUP BY kind'))
            sources = list(db.execute('SELECT source,records,status FROM feed_status ORDER BY source'))
            db.commit()
            if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('snapshot_integrity')
        finally:
            db.close()
        with output.open('rb') as stream:
            os.fsync(stream.fileno())
        os.replace(output, destination)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        print(json.dumps({'status': 'partial' if failures else 'updated', 'revision': meta['dataset'],
                          'prefixes': counts, 'sources': sources, 'failures': failures}, sort_keys=True), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=Path(DEFAULT_DIR))
    parser.add_argument('--allocations', type=Path, default=Path(DEFAULT_ALLOCATIONS))
    args = parser.parse_args()
    os.umask(0o077)
    update(args.directory, args.allocations)
