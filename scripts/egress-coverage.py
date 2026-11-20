#!/usr/bin/env python3
"""Report committed collector membership and measured egress throughput without running probes."""
import argparse
import json
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path


WINDOW_MS = 300_000
CURRENT = """
WITH members AS MATERIALIZED (
  SELECT source_id, artifact_id AS identity FROM memberships {member_filter}
), qualified AS MATERIALIZED (
  SELECT hash FROM egress_network_eligible
), exported AS MATERIALIZED (
  SELECT hash FROM egress_export_eligible
), states AS MATERIALIZED (
  SELECT k.identity,u.hash IN qualified AS residential,u.hash IN exported AS published, CASE
    WHEN x.identity IS NOT NULL OR g.state='BLOCKED' OR c.action='deleted' OR j.state='DELETED'
      THEN 'excluded'
    {remembered_case}
    WHEN u.hash IS NULL OR j.hash IS NULL THEN 'missing_job'
    WHEN h.held=1 THEN 'network_held'
    {review_cases}
    WHEN j.paused<>0 OR c.action='disabled' THEN 'paused'
    WHEN u.hash IN exported THEN 'published'
    {fresh_case}
    WHEN j.token<>'' AND j.lease_until>:now THEN 'running'
    WHEN j.tested=0 AND j.first_completed=0 THEN 'awaiting_first'
    WHEN j.tested=0 THEN 'awaiting_recheck'
    WHEN j.state='NO_SPLIT' THEN 'confirmed_no_split'
    WHEN j.state='UNSUPPORTED' THEN 'unsupported'
    WHEN EXISTS(SELECT 1 FROM egress_eligible p WHERE p.hash=j.hash)
      THEN 'route_verified_unpublished'
    WHEN j.ever_accepted=1 THEN 'awaiting_renewal'
    ELSE 'assessed_other'
  END AS category
  FROM (SELECT DISTINCT identity FROM members) k
  LEFT JOIN egress_unique u ON u.identity=k.identity
  LEFT JOIN egress_jobs j ON j.hash=u.hash
  LEFT JOIN input_exclusions x ON x.identity=k.identity
  LEFT JOIN egress_iran_guard g ON g.identity=k.identity
  LEFT JOIN config_controls c ON c.id=k.identity AND c.expires>:now
  LEFT JOIN egress_network_results h ON h.identity=k.identity
  {review_join}
)
SELECT m.source_id, s.category, count(*),count(*) FILTER(WHERE residential),count(*) FILTER(WHERE published)
FROM members m JOIN states s USING(identity)
GROUP BY m.source_id, s.category
UNION ALL SELECT NULL, category, count(*),count(*) FILTER(WHERE residential),count(*) FILTER(WHERE published) FROM states GROUP BY category
"""

# Count a completed attempt once even if it is visible through several sources.
# A representative already settled before this window can be separated exactly.
# Receipts do not record whether a subsequent attempt was specifically a renewal.
THROUGHPUT = """
WITH recent AS MATERIALIZED (
  SELECT hash, at, definitive FROM egress_events WHERE at > :start AND at <= :now
), per_hash AS (
  SELECT hash, count(*) AS attempts, sum(definitive) AS definitive FROM recent GROUP BY hash
)
SELECT coalesce(sum(attempts),0), count(*), coalesce(sum(p.definitive),0),
       coalesce(sum(p.definitive>0),0),
       coalesce(sum(p.definitive>0 AND s.at>:start AND s.at<=:now),0),
       coalesce(sum(p.definitive>0 AND s.at<=:start),0)
FROM per_hash p LEFT JOIN egress_settlements s USING(hash)
"""


def empty_counts(has_first_backlog):
    return {"current_unique": 0, "residential": 0, "published": 0, "current": {}, "staged_unique": 0,
            "withdrawn_awaiting_first": 0 if has_first_backlog else None}


def collect(connection, source_id, timeout):
    deadline = time.monotonic() + timeout
    connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("BEGIN")
    query = connection.execute
    # Establish the WAL snapshot and its wall clock before reading any counter.
    now, schema = query("SELECT CAST(unixepoch('subsec')*1000 AS INTEGER), user_version "
                        "FROM pragma_user_version").fetchone()
    if now is None or schema < 46:
        raise ValueError("requires SQLite 3.42+ and database schema 46+")
    has_first_backlog = schema >= 47
    params = {"now": now, "start": now - WINDOW_MS, "source": source_id}
    source_filter = "WHERE id=:source" if source_id is not None else ""
    member_filter = "WHERE source_id=:source" if source_id is not None else ""
    sources = {}
    for key, generation, stamp, unique, received, invalid, unknown, suppressed in query(
        "SELECT id,generation,receipt_at,receipt_unique,received_count,invalid_count,"
        f"unknown_count,suppressed_count FROM sources {source_filter}", params
    ):
        sources[key] = {**empty_counts(has_first_backlog), "generation": generation,
                        "latest_receipt": {"at": stamp, "unique": None if unique < 0 else unique,
                                           "extracted": received, "invalid": invalid,
                                           "unknown": unknown, "suppressed": suppressed}}
    if source_id is not None and not sources:
        raise ValueError("unknown source ID")

    global_counts = empty_counts(has_first_backlog)
    # The final review lease is still pending until it finishes or expires.
    # Mirrors the panel's network-review projection. Schemas 46–48 have no review ledger.
    review_cases = """
      WHEN v.identity IS NOT NULL AND (v.attempts<2 OR (j.token<>'' AND j.lease_until>:now))
        THEN 'network_review_pending'
      WHEN v.identity IS NOT NULL THEN 'network_review_inconclusive'
    """ if schema >= 49 else ""
    review_join = "LEFT JOIN egress_network_review v ON v.identity=k.identity" if schema >= 49 else ""
    remembered_case = fresh_case = ""
    if schema >= 56:
        remembered_case = """WHEN (j.hash IS NULL OR (j.first_completed=0 AND j.tested=0))
          AND EXISTS(SELECT 1 FROM egress_first_verdicts f WHERE f.identity=k.identity)
          THEN 'previously_assessed'"""
        fresh_case = """WHEN j.first_completed=0 AND j.tested=0 AND NOT EXISTS(
          SELECT 1 FROM egress_inventory scope WHERE scope.hash=j.hash) THEN 'outside_first_queue'"""
        review_cases = """WHEN v.identity IS NOT NULL AND EXISTS(
          SELECT 1 FROM egress_work scope WHERE scope.hash=j.hash) THEN 'network_review_pending'
          WHEN v.identity IS NOT NULL THEN 'network_review_inconclusive'"""
    current_sql = CURRENT.format(member_filter=member_filter, review_cases=review_cases, review_join=review_join,
                                 remembered_case=remembered_case, fresh_case=fresh_case)
    for key, category, count, residential, published in query(current_sql, params):
        target = global_counts if key is None else sources[key]
        target["current"][category] = count
        target["current_unique"] += count
        target["residential"] += residential
        target["published"] += published

    # Staged identities may also exist in the current committed generation.
    # Withdrawn-but-pending representatives stay attributed to their source
    # even if another source still lists the identity.
    stages = f"SELECT DISTINCT source_id,identity FROM staged {member_filter}"
    backlog = """
      SELECT b.source_id,u.identity FROM egress_first_backlog b JOIN egress_unique u USING(hash)
      WHERE EXISTS(SELECT 1 FROM egress_inventory j WHERE j.hash=b.hash AND j.first_completed=0 AND j.tested=0)
      AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.source_id=b.source_id
                       AND m.artifact_id=u.identity)
    """ + (" AND b.source_id=:source" if source_id is not None else "")
    if schema >= 56:
        backlog += """ AND EXISTS(SELECT 1 FROM egress_first_arrivals a JOIN sources s ON s.id=a.source_id
          WHERE s.enabled=1 AND a.source_id=b.source_id AND a.identity=u.identity
          AND a.received_at>:now-(SELECT min(retention_seconds,86400)*1000 FROM settings WHERE id=1))"""
    datasets = [("staged_unique", stages)]
    if has_first_backlog:
        datasets.append(("withdrawn_awaiting_first", backlog))
    for field, dataset in datasets:
        counts_sql = f"""
          WITH items AS MATERIALIZED ({dataset})
          SELECT source_id,count(*) FROM items GROUP BY source_id
          UNION ALL SELECT NULL,count(DISTINCT identity) FROM items
        """
        for key, count in query(counts_sql, params):
            (global_counts if key is None else sources[key])[field] = count

    attempts, hashes, decisions, settled, first, previously = query(THROUGHPUT, params).fetchone()
    perf = {"scope": "all_committed_worker_completions", "start_exclusive_ms": params["start"],
            "end_inclusive_ms": now, "attempts": attempts, "unique_representatives_assessed": hashes,
            "definitive_attempts": decisions, "unique_definitive": settled,
            "first_settled_in_window": first, "already_settled_before_window": previously,
            "settlement_provenance_unknown": settled - first - previously,
            "inconclusive_only": hashes - settled, "repeated_attempts": attempts - hashes}
    return {"as_of_ms": now, "database_schema": schema,
            "withdrawn_first_backlog_available": has_first_backlog,
            "coverage_scope": "selected_source" if source_id is not None else "all_current_sources",
            "global": global_counts, "sources": sources, "throughput_300s": perf,
            "history_scope": "Current committed memberships, latest acquisition receipt, staging, "
                             "and first-assessment backlog only. Withdrawn completed generations "
                             "and inputs never persisted cannot be reconstructed from these tables. "
                             "Repeated settlements include renewals. Window completions may have "
                             "started earlier. This is not a timed cohort benchmark."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--source-id")
    parser.add_argument("--timeout-seconds", type=int, default=15, choices=range(1, 61),
                        metavar="1..60")
    args = parser.parse_args()
    try:
        uri = args.database.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=min(1, args.timeout_seconds))) as db:
            snapshot = collect(db, args.source_id, args.timeout_seconds)
    except (sqlite3.Error, OSError, ValueError) as err:
        # File paths and connection details must not leak through diagnostic JSON.
        status = str(err) if isinstance(err, ValueError) else "database_busy_or_unsupported"
        print(json.dumps({"error": status}), file=sys.stderr)
        return 1
    print(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
