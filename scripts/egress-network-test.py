#!/usr/bin/env python3
"""Offline tests of TLS-bound exit enrichment, snapshot replacement and privacy."""
import hashlib
import importlib
import importlib.util
import ipaddress
import json
import pathlib
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe", HERE / "egress-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
network = probe.exit_network
builder = importlib.import_module("egress-network-update")


class ExitNetworkTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = pathlib.Path(temp.name) / "network.sqlite"
        self.at = time.time_ns() // 1_000_000
        self.until = self.at + 3_600_000
        self.usage = [
            ("45.76.114.0/23", "hosting", "vultr", 20473, "vultr-official", self.until),
            ("84.60.0.0/16", "access", "sample-access", 1234, "sample-subscriber-pool", self.until),
            ("2606:4700:10::/48", "access", "sample-v6", 1234, "sample-subscriber-pool", self.until),
        ]
        self.origins = [("45.76.112.0/20", 20473), ("84.60.0.0/16", 1234), ("2606:4700::/32", 1234)]
        self.origin_source = "routeviews"
        self.feeds = {f.source: ("current", self.at, f.minimum, "f" * 64)
                      for f in builder.FEEDS if f.kind == "hosting"}
        self.manifest = self.path.with_suffix(".json")
        self.registry = network.NetworkRegistry(self.path, self.manifest)
        self.addCleanup(self.registry.close)

    def snapshot(self, revision="a", origin_until=None):
        stage = self.path.with_suffix(".new")
        size = self.until if origin_until is None else origin_until
        with sqlite3.connect(stage) as db:
            db.executescript("""
                CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE origins(family INTEGER, length INTEGER, start BLOB, asn INTEGER,
                    PRIMARY KEY(family,length,start)) WITHOUT ROWID;
                CREATE TABLE usage(family INTEGER,length INTEGER,start BLOB,kind TEXT,provider TEXT,
                    asn INTEGER,source TEXT,valid_until INTEGER,PRIMARY KEY(family,length,start)) WITHOUT ROWID;
                CREATE TABLE hosting_asns(asn INTEGER PRIMARY KEY);
                INSERT INTO hosting_asns VALUES(20473);
                CREATE TABLE feed_status(source TEXT PRIMARY KEY,status TEXT,checked_at INTEGER,records INTEGER,sha256 TEXT);
            """)
            db.executemany("INSERT INTO meta VALUES(?,?)", {
                "version": network.VERSION, "origin_valid_until": str(size),
                "origin_source": self.origin_source, "dataset": hashlib.sha256(revision.encode()).hexdigest(),
            }.items())
            db.executemany("INSERT INTO feed_status VALUES(?,?,?,?,?)", ((key, *v) for key, v in self.feeds.items()))
            for table, records in (("origins", self.origins), ("usage", self.usage)):
                for prefix, *values in records:
                    block = ipaddress.ip_network(prefix)
                    row = (block.version, block.prefixlen, block.network_address.packed, *values)
                    db.execute("INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in row) + ")", row)
        db.close()
        stage.replace(self.path)
        self.registry.refresh()

    @staticmethod
    def row(ip, **changes):
        row = dict(ip=ip, family=ipaddress.ip_address(ip).version, echo=True, actual_ads=True,
                   same_stream=True, tls=True, response_complete=True)
        return {**row, **changes}

    def lookup(self, ip):
        return self.registry.lookup(ipaddress.ip_address(ip), self.at)

    def test_vultr_both_variants_share_one_lookup_and_a_bound_private_source(self):
        self.snapshot()
        address = "45.76.115.243"
        rows = [self.row(address, variant="raw"), self.row(address, variant="template"),
                self.row(address, actual_ads=False), self.row(address, tls=False),
                self.row(address, response_complete=False), self.row(address, same_stream=False)]
        with patch.object(self.registry, "lookup", wraps=self.registry.lookup) as counted:
            self.registry.attach(rows)
            self.assertEqual(counted.call_count, 1)
        probe.private_sources(rows, b"a" * 32)
        self.assertTrue(all("network" not in row for row in rows[2:]))
        for row in rows[:2]:
            verdict = row["network"]
            self.assertEqual((verdict["kind"], verdict["provider"], verdict["asn"]), ("hosting", "vultr", 20473))
            self.assertEqual((verdict["family"], verdict["prefix_len"]), (4, 23))
            self.assertEqual(verdict["source"], row["source"])
            self.assertLessEqual(verdict["valid_until"] - verdict["checked_at"], network.PROOF_TTL_MS)
        self.assertEqual(rows[0]["network"], rows[1]["network"])
        self.assertNotIn(address, json.dumps(rows))

    def test_verified_subscriber_prefixes_and_family_binding(self):
        self.snapshot()
        self.assertEqual(self.lookup("84.60.7.3")["kind"], "access")
        self.assertEqual(self.lookup("2606:4700:10::b")["family"], 6)
        rows = [self.row("84.60.7.3", family=6), self.row("127.0.0.1")]
        self.registry.attach(rows)
        self.assertEqual([r["network"]["reason"] for r in rows], ["network_source_invalid"] * 2)

    def test_more_specific_route_conflict_or_usage_exception_never_inherits(self):
        self.origins.extend([("84.60.1.0/24", 0), ("84.60.2.0/24", 20473)])
        self.usage.extend([
            ("84.60.3.0/24", "unknown", "", 0, "", self.until),
            ("84.60.4.0/24", "access", "sample-access", 1234, "sample-subscriber-pool", self.at - 1),
        ])
        self.snapshot()
        for host in ("84.60.1.2", "84.60.2.2", "84.60.3.2", "84.60.4.2", "8.8.8.8"):
            self.assertEqual(self.lookup(host)["kind"], "unknown")
        self.assertEqual(self.lookup("84.60.0.2")["kind"], "access")

    def test_missing_stale_and_replaced_snapshots(self):
        self.registry.refresh()
        self.assertEqual(self.lookup("45.76.115.243")["reason"], "network_snapshot_unavailable")
        self.snapshot(origin_until=self.at)
        self.assertEqual(self.lookup("45.76.115.243")["reason"], "network_origin_expired")
        self.snapshot("refreshed")
        self.assertEqual(self.lookup("45.76.115.243")["kind"], "hosting")
        self.usage.clear()
        self.snapshot("reviewed")
        self.assertEqual(self.lookup("45.76.115.243")["reason"], "network_usage_unverified")
        invalid = self.path.with_suffix(".bad")
        invalid.write_text("invalid")
        invalid.replace(self.path)
        self.registry.refresh()
        self.assertEqual(self.lookup("45.76.115.243")["kind"], "unknown")

    def test_same_lineage_does_not_corroborate_and_origin_expiry_caps_proof(self):
        self.usage.append(("84.60.3.0/24", "access", "sample", 1234, "routeviews", self.until))
        self.snapshot(origin_until=self.at + 15_000)
        self.assertEqual(self.lookup("84.60.3.1")["kind"], "unknown")
        self.assertEqual(self.lookup("84.60.4.1")["valid_until"], self.at + 15_000)

    def test_only_the_single_observed_origin_is_returned_for_multi_as_provider(self):
        self.usage.append(("84.60.1.0/24", "hosting", "sample-host", "1234,64496", "provider-published", self.until))
        self.usage.append(("84.60.2.0/24", "access", "sample-access", "1234,bad", "provider-published", self.until))
        self.snapshot()
        hit = self.lookup("84.60.1.1")
        self.assertEqual((hit["kind"], hit["asn"]), ("hosting", 1234))
        self.assertEqual(self.lookup("84.60.2.1")["kind"], "unknown")

    def test_licensed_fallback_requires_valid_pins_access_type_and_independent_noncloud_origin(self):
        files = {}
        for role in ("asn", "connection"):
            path = self.path.with_suffix("." + role)
            path.write_bytes(role.encode())
            files[role] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.manifest.write_text(json.dumps(files))
        self.usage.clear()
        self.snapshot()
        records = {"connection": "Cellular", "asn": 1234}

        def fake_reader(path):
            role = pathlib.Path(path).read_bytes().decode()
            return types.SimpleNamespace(
                metadata=lambda: types.SimpleNamespace(
                    database_type="GeoIP2-ISP" if role == "asn" else "GeoIP2-Connection-Type",
                    build_epoch=self.at // 1000,
                ),
                get_with_prefix_len=lambda _: ({"connection_type": records["connection"]}, 24),
                get=lambda _: {"autonomous_system_number": records["asn"]},
                close=lambda: None,
            )

        with patch.dict(sys.modules, {"maxminddb": types.SimpleNamespace(open_database=fake_reader)}), \
                patch.object(self.registry.licensed, "trusted", return_value=True):
            good = self.lookup("84.60.1.1")
            self.assertEqual((good["kind"], good["provider"], good["usage_source"]), ("access", "as1234", "maxmind-connection-type"))
            records["connection"] = "Corporate"
            self.assertEqual(self.lookup("84.60.1.1")["kind"], "unknown")
            records.update(connection="Cable/DSL", asn=5678)
            self.assertEqual(self.lookup("84.60.1.1")["reason"], "network_origin_conflict")
            records["asn"] = 20473
            self.assertEqual(self.lookup("45.76.115.243")["reason"], "network_usage_conflict")
            records["asn"] = 1234
            pathlib.Path(files["connection"]["path"]).write_text("no-longer-pinned")
            self.assertEqual(self.lookup("84.60.1.1")["kind"], "unknown")

    def test_licensed_fallback_cannot_overrule_an_expired_or_conflicting_official_record(self):
        self.usage.append(("84.60.1.0/24", "unknown", "", 0, "", self.until))
        self.snapshot()
        with patch.object(self.registry.licensed, "lookup", side_effect=AssertionError("must not fall back")):
            self.assertEqual(self.lookup("84.60.1.1")["kind"], "unknown")

    def test_specific_claim_of_access_on_a_known_hosting_asn_is_withheld(self):
        self.usage.append(("45.76.115.0/24", "access", "sample-access", 20473, "reviewed-pool", self.until))
        self.snapshot()
        self.assertEqual(self.lookup("45.76.115.243")["reason"], "network_usage_conflict")

    def test_unclassified_origin_proves_only_an_observed_change_for_prior_holds(self):
        self.origin_source = "ripe-ris"
        host = "84.61.7.8"
        self.origins.extend([("84.61.0.0/16", 3243), ("84.61.7.0/24", 1234)])
        self.feeds["vultr-geofeed"] = ("last-good", self.at - builder.TTL + 20_000, 52, "e" * 64)
        self.snapshot()
        for address, asn, family, length in [(host, 1234, 4, 24), ("2606:4700:100::b", 1234, 6, 32)]:
            fact = self.lookup(address)
            self.assertEqual((fact["kind"], fact["reason"]), ("unknown", "network_usage_unverified"))
            self.assertTrue(fact["origin_outside_hosting"])
            self.assertEqual((fact["asn"], fact["family"], fact["prefix_len"]), (asn, family, length))
            self.assertEqual((fact["origin_source"], fact["valid_until"]), ("ripe-ris", self.at + 20_000))
            self.assertNotIn("provider", fact)
            self.assertNotIn("usage_source", fact)
        rows = [self.row(host), self.row(host, actual_ads=False)]
        self.registry.attach(rows)
        probe.private_sources(rows, b"a" * 32)
        self.assertEqual(rows[0]["network"]["source"], rows[0]["source"])
        self.assertNotIn("network", rows[1])
        self.assertNotIn(host, json.dumps(rows))
        self.assertNotIn("origin_outside_hosting", self.registry.lookup(ipaddress.ip_address(host), self.at + 20_001))

    def test_unclassified_origin_requires_unambiguous_public_origin_and_no_usage(self):
        self.origin_source = "ripe-ris"
        self.origins.extend([("84.61.0.0/16", 1234), ("84.61.1.0/24", 0), ("84.61.2.0/24", 20473),
                             ("84.61.3.0/24", 64512), ("84.61.4.0/24", 23456), ("84.61.5.0/24", 65535)])
        self.usage.extend([("84.61.7.0/24", "hosting", "stale", 1234, "stale-host", self.at - 1),
                           ("84.61.8.0/24", "unknown", "conflict", 1234, "allocations", self.until)])
        self.snapshot()
        for addr in ("84.61.1.2", "84.61.2.2", "84.61.3.2", "84.61.4.2", "84.61.5.2", "84.61.7.2",
                     "84.61.8.2", "45.76.115.243", "84.60.2.2", "8.8.8.8"):
            with self.subTest(addr=addr):
                self.assertNotIn("origin_outside_hosting", self.lookup(addr))

    def test_unclassified_origin_requires_current_hosting_inventory(self):
        self.origin_source = "ripe-ris"
        self.origins.append(("84.61.0.0/16", 1234))
        for row in [("unavailable", self.at, 0, ""), ("last-good", self.at - builder.TTL, 52, "e" * 64),
                    ("current", self.at, 1, "e" * 64), ("current", self.at, 52, "bad"),
                    ("current", self.at + 120_000, 52, "e" * 64), None]:
            with self.subTest(row=row):
                if row is None:
                    del self.feeds["vultr-geofeed"]
                else:
                    self.feeds["vultr-geofeed"] = row
                self.snapshot()
                self.assertNotIn("origin_outside_hosting", self.lookup("84.61.0.2"))
                self.assertEqual(self.lookup("45.76.115.243")["kind"], "hosting")
        self.feeds["vultr-geofeed"] = ("current", self.at, 52, "e" * 64)
        self.snapshot(origin_until=self.at)
        self.assertNotIn("origin_outside_hosting", self.lookup("84.61.0.2"))
        self.origin_source = "routeviews"
        self.snapshot()
        self.assertNotIn("origin_outside_hosting", self.lookup("84.61.0.2"))


if __name__ == "__main__":
    unittest.main()
