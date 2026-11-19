#!/usr/bin/env python3
import contextlib
import gzip
import importlib
import io
import ipaddress
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

build = importlib.import_module('egress-network-update')
worker = importlib.import_module('egress-network')
HOST = build.Feed('vultr-geofeed', 'vultr', 'hosting', (20473,), 'https://vultr.example/feed', build.published_csv)
ACCESS = build.Feed('docomo-spmode', 'docomo', 'access', (9605,), 'https://docomo.example/pools', build.docomo)
DOCUMENT = '<h2>spモードサーバのIPアドレス帯域</h2><h3>メール受信時</h3><li>8.1.1.0/24</li><h3>インターネットアクセス時</h3><ul><li>1.66.96.0/21</li><li>＜2027年1月追加予定＞</li><li>27.230.0.0/19</li></ul><h2>Other</h2><li>8.8.8.0/24</li>'
V4 = b'% RIS test fixture\n20473\t45.76.112.0/20\t200\n9605\t1.66.96.0/21\t20\n9605\t1.66.98.0/24\t30\n5555\t1.66.98.0/24\t4\n9605\t1.66.99.0/24\t1\n'
V6 = b'20473\t2001:19f0::/32\t30\n'

def fixture(url, limit):
    mapping = {build.RIS.format(4): gzip.compress(V4), build.RIS.format(6): gzip.compress(V6),
               HOST.url: b'# Vultr geofeed\n45.76.114.0/23,AU,,\n2001:19f0::/32,US,,\n', ACCESS.url: DOCUMENT.encode()}
    return mapping[url], {}

class NetworkUpdate(unittest.TestCase):
    def test_built_snapshot_with_conflicts_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(build, 'FEEDS', (HOST, ACCESS)), contextlib.redirect_stdout(io.StringIO()):
            directory = Path(tmp)
            allocations = directory / 'missing.json'
            build.update(directory, allocations, fixture, minimums=(4, 1))
            p = directory / 'egress-network.sqlite'
            registry = worker.NetworkRegistry(p, directory/'missing-mmdb')
            try:
                at = int(time.time() * 1000)
                registry.refresh()
                self.assertEqual(registry.lookup(ipaddress.ip_address('45.76.115.243'), at)['kind'], 'hosting')
                self.assertEqual(registry.lookup(ipaddress.ip_address('1.66.96.9'), at)['kind'], 'access')
                self.assertEqual(registry.lookup(ipaddress.ip_address('1.66.98.9'), at)['kind'], 'unknown')
                self.assertEqual(registry.lookup(ipaddress.ip_address('1.66.99.9'), at)['kind'], 'unknown')
                self.assertEqual(registry.lookup(ipaddress.ip_address('2001:19f0::a'), at)['provider'], 'vultr')
            finally:
                registry.close()
            revision = p.read_bytes()
            def broken_ris(url, limit):
                if url == build.RIS.format(6):
                    return gzip.compress(b'foo bar'), {}
                return fixture(url, limit)
            with self.assertRaises(ValueError):
                build.update(directory, allocations, broken_ris, minimums=(4, 1))
            self.assertEqual(revision, p.read_bytes())
            def missing_vultr(url, limit):
                if url == HOST.url:
                    raise OSError('offline')
                return fixture(url, limit)
            db = sqlite3.connect(p)
            before = db.execute("SELECT checked_at FROM feed_status WHERE source='vultr-geofeed'").fetchone()[0]
            db.close()
            build.update(directory, allocations, missing_vultr, minimums=(4, 1))
            db = sqlite3.connect(p)
            self.assertEqual((before, 'last-good'), db.execute("SELECT checked_at,status FROM feed_status WHERE source='vultr-geofeed'").fetchone())
            self.assertEqual((before + build.TTL,), db.execute("SELECT min(valid_until) FROM usage WHERE provider='vultr'").fetchone())
            db.close()

    def test_operator_conflict_stays_unknown_and_expiries(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(build, 'FEEDS', (HOST, ACCESS)), contextlib.redirect_stdout(io.StringIO()):
            base = Path(tmp)
            path = base / 'allocations.json'
            now = int(time.time()*1000)
            entry = dict(prefix='45.76.114.0/23', kind='access', provider='new-isp', asn=20473, source='isp-list',
                         evidence_url='https://isp.example/list', valid_until=now+build.DAY)
            path.write_text(json.dumps({'version':build.VERSION, 'allocations':[entry]}))
            build.update(base, path, fixture, minimums=(4, 1))
            db = sqlite3.connect(base/'egress-network.sqlite')
            self.assertEqual(('unknown',), db.execute('SELECT kind FROM usage WHERE start=?', (ipaddress.ip_address('45.76.114.0').packed,)).fetchone())
            db.close()
            for item in [dict(entry, prefix='10.0.0.0/8'), dict(entry, source='ripe-ris'), dict(entry, valid_until=now+60*build.DAY)]:
                path.write_text(json.dumps({'version':build.VERSION, 'allocations':[item]}))
                with self.assertRaises(ValueError):
                    build.parse_operator(path, now)

    def test_ripe_pool_requires_explicit_purpose_and_signature(self):
        obj = dict(type='inetnum', source={'id':'ripe'}, attributes={'attribute':[
            {'name':key, 'value':value} for key, value in [('netname','UNITYMEDIA-B2C-POOL-NET'), ('mnt-by','UNITYMEDIA-MNT'),
            ('descr','Unitymedia dynamic DHCP B2C customer pool'), ('inetnum','84.118.0.0 - 84.118.255.255')]]})
        parse = build.registry_pool('UNITYMEDIA-B2C-POOL-NET', ('UNITYMEDIA-MNT',), 'dynamic dhcp b2c customer pool')
        def run():
            return list(parse(json.dumps({'objects':{'object':[obj]}}).encode()))
        self.assertEqual(build.docomo(DOCUMENT.encode()), ['1.66.96.0/21'])
        self.assertEqual(run(), [ipaddress.ip_network('84.118.0.0/16')])
        obj['attributes']['attribute'][2]['value']='Corporate transit'
        self.assertFalse(run())

if __name__ == '__main__':
    unittest.main()
