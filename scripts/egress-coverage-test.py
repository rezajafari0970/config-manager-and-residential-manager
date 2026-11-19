#!/usr/bin/env python3
"""Exercise read-only coverage against fixed memberships, receipts and renewal events."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("egress-coverage.py")


class Coverage(unittest.TestCase):
    def test_overlaps_and_conclusive_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "panel.db")
            now = time.time_ns() // 1_000_000
            with sqlite3.connect(path) as db:
                db.executescript("""
                    PRAGMA user_version=47;
                    CREATE TABLE sources(id,generation,receipt_at,receipt_unique,
                      received_count,invalid_count,unknown_count,suppressed_count);
                    CREATE TABLE memberships(source_id,artifact_id);
                    CREATE TABLE egress_unique(identity,hash);
                    CREATE TABLE egress_jobs(hash,state,token,lease_until,tested,paused,ever_accepted,first_completed);
                    CREATE VIEW egress_inventory AS SELECT * FROM egress_jobs;
                    CREATE TABLE egress_network_results(identity,held);
                    CREATE TABLE egress_iran_guard(identity,state);
                    CREATE TABLE input_exclusions(identity);
                    CREATE TABLE config_controls(id,action,expires);
                    CREATE TABLE egress_export_eligible(hash);
                    CREATE TABLE egress_eligible(hash);
                    CREATE TABLE staged(source_id,identity);
                    CREATE TABLE egress_first_backlog(source_id,hash);
                    CREATE TABLE egress_events(hash,at,definitive);
                    CREATE TABLE egress_settlements(hash,at);
                    INSERT INTO sources VALUES('srcA',4,0,5,7,1,0,0),('srcB',2,0,2,2,0,0,0);
                    INSERT INTO memberships VALUES('srcA','one'),('srcA','two'),('srcA','three'),
                      ('srcA','four'),('srcA','five'),('srcB','one'),('srcB','six');
                    INSERT INTO egress_unique VALUES('one','h1'),('two','h2'),('six','h6'),
                      ('three','h3'),('gone','h7');
                    INSERT INTO egress_jobs VALUES('h1','RESIDENTIAL','',0,1,0,1,1),
                      ('h2','QUARANTINED','',0,1,0,1,1),('h3','NO_SPLIT','',0,1,0,0,1),
                      ('h6','PENDING','',0,0,0,0,0),('h7','PENDING','',0,0,0,0,0);
                    INSERT INTO egress_network_results VALUES('two',1);
                    INSERT INTO egress_export_eligible VALUES('h1');
                    INSERT INTO input_exclusions VALUES('four');
                    INSERT INTO staged VALUES ('srcA','stage'),('srcB','stage');
                    INSERT INTO egress_first_backlog VALUES ('srcA','h7'),('srcB','h7');
                """)
                db.executemany("INSERT INTO egress_events VALUES(?,?,?)", [
                    ("h1", now-1800, 1), ("h1", now-1000, 1),
                    ("h2", now-1400, 0), ("h3", now-1300, 1),
                    ("hOld", now-310000, 1), ("hFuture", now+100000, 1)])
                db.executemany("INSERT INTO egress_settlements VALUES(?,?)", [
                    ("h1", now-500000), ("h3", now-1300)])
            before = path.read_bytes()
            def report(*args):
                result = subprocess.run([sys.executable, str(SCRIPT), "--database", str(path),
                                         *args], check=True, capture_output=True, text=True)
                return json.loads(result.stdout)
            all_sources = report()
            totals = all_sources["global"]
            self.assertEqual(totals["current_unique"], 6)
            self.assertEqual(totals["staged_unique"], 1)
            self.assertEqual(totals["withdrawn_awaiting_first"], 1)
            self.assertEqual(totals["current"], dict.fromkeys(
                ["confirmed_no_split", "missing_job", "published", "network_held",
                 "excluded", "awaiting_first"], 1))
            self.assertEqual(all_sources["sources"]["srcA"]["current_unique"], 5)
            filtered = report("--source-id", "srcB")
            self.assertEqual(filtered["sources"]["srcB"]["current_unique"], 2)
            self.assertEqual(filtered["global"]["current_unique"], 2)
            self.assertEqual(filtered["throughput_300s"]["scope"], "all_committed_worker_completions")
            perf = all_sources["throughput_300s"]
            self.assertEqual([perf[k] for k in (
                "attempts", "unique_representatives_assessed", "definitive_attempts",
                "unique_definitive", "first_settled_in_window", "already_settled_before_window",
                "settlement_provenance_unknown", "inconclusive_only")], [4, 3, 3, 2, 1, 1, 0, 1])
            self.assertEqual(path.read_bytes(), before)
            with sqlite3.connect(path) as db:
                db.executescript("DROP TABLE egress_first_backlog; PRAGMA user_version=46;")
            previous = report()
            self.assertFalse(previous["withdrawn_first_backlog_available"])
            self.assertIsNone(previous["global"]["withdrawn_awaiting_first"])
            self.assertIsNone(previous["sources"]["srcA"]["withdrawn_awaiting_first"])
            self.assertEqual(previous["global"]["current"], totals["current"])


if __name__ == "__main__":
    unittest.main()
