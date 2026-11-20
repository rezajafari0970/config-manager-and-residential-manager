package panel

import (
	"context"
	"database/sql"
)

// A first test is authorized by a recent parsed source response. Natural
// rotation can finish recent work, but a long outage cannot replay the archive.
// The ordinary retention setting can shorten the one-day discovery window.
const egressArrivalWindow = "(SELECT min(retention_seconds,86400)*1000 FROM settings WHERE id=1)"
const egressArrivalClock = "CAST(unixepoch('subsec')*1000 AS INTEGER)"
const egressFreshOwner = `SELECT 1 FROM egress_first_arrivals a JOIN sources src ON src.id=a.source_id
 WHERE a.identity=u.identity AND src.enabled=1 AND NOT EXISTS(SELECT 1 FROM egress_first_verdicts f WHERE f.identity=u.identity) AND a.received_at>` + egressArrivalClock + `-` + egressArrivalWindow + `
 AND (EXISTS(SELECT 1 FROM memberships m WHERE m.source_id=a.source_id AND m.artifact_id=a.identity)
 OR EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.source_id=a.source_id AND b.hash=u.hash))`

const rememberFetchedEgress = `
 INSERT INTO egress_first_arrivals(source_id,identity,queued_at,received_at)
 SELECT new.source_id,new.artifact_id,` + egressArrivalClock + `,` + egressArrivalClock + ` FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 WHERE u.identity=new.artifact_id AND j.first_completed=0 AND j.tested=0 AND j.ever_accepted=0 AND j.state!='DELETED'
 AND NOT EXISTS(SELECT 1 FROM egress_first_verdicts f WHERE f.identity=u.identity)
 ON CONFLICT(source_id,identity) DO UPDATE SET queued_at=CASE WHEN received_at<=excluded.received_at-` + egressArrivalWindow + ` THEN excluded.queued_at ELSE queued_at END,received_at=excluded.received_at;`

// An outstanding first lease loses its source authority immediately when the
// last active owner changes URL, is disabled or is deleted. A later refetch or
// re-enable cannot make that old token usable again.
const fenceDepartingFirstSource = `UPDATE egress_jobs SET token='',lease_until=0,revision=revision+1
 WHERE token!='' AND first_completed=0 AND tested=0 AND ever_accepted=0
 AND EXISTS(SELECT 1 FROM egress_unique u JOIN egress_first_arrivals own ON own.identity=u.identity
 WHERE u.hash=egress_jobs.hash AND own.source_id=OLD.id
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='QUARANTINED')
 AND NOT EXISTS(` + egressFreshOwner + ` AND a.source_id!=OLD.id));`

func migrateFreshResidential(tx *sql.Tx) error {
	_, err := tx.Exec(`
 CREATE TABLE IF NOT EXISTS egress_first_verdicts(
 identity TEXT PRIMARY KEY, hash TEXT NOT NULL, tested INTEGER NOT NULL) WITHOUT ROWID;
 INSERT OR IGNORE INTO egress_first_verdicts SELECT u.identity,j.hash,j.tested FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 WHERE j.first_completed=1 OR j.tested>0;
 INSERT OR IGNORE INTO egress_first_verdicts SELECT o.identity,j.hash,j.tested FROM egress_jobs j JOIN egress_owners o ON o.hash=j.hash
 WHERE j.tested>0 ORDER BY j.tested,j.hash;
 CREATE TRIGGER IF NOT EXISTS egress_remember_first AFTER UPDATE OF first_completed,tested ON egress_jobs
 WHEN (OLD.first_completed=0 AND NEW.first_completed=1) OR (OLD.tested=0 AND NEW.tested>0) BEGIN
 INSERT OR IGNORE INTO egress_first_verdicts SELECT identity,NEW.hash,NEW.tested FROM egress_unique WHERE hash=NEW.hash;
 END;
 CREATE TRIGGER IF NOT EXISTS egress_remember_terminal AFTER INSERT ON egress_events
 WHEN NEW.first_result_scope!='' BEGIN
 INSERT OR IGNORE INTO egress_first_verdicts SELECT identity,NEW.hash,NEW.at FROM egress_unique WHERE hash=NEW.hash;
 END;
 CREATE TABLE IF NOT EXISTS egress_hosting_confirmations(
 hash TEXT PRIMARY KEY REFERENCES egress_jobs(hash) ON DELETE CASCADE,
 through_attempt INTEGER NOT NULL,expires INTEGER NOT NULL) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS egress_first_arrivals(source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
 identity TEXT NOT NULL,queued_at INTEGER NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(source_id,identity)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_arrival_identity ON egress_first_arrivals(identity,received_at);
 CREATE INDEX IF NOT EXISTS egress_arrival_clock ON egress_first_arrivals(received_at);
 DROP TRIGGER IF EXISTS egress_ingest;
 CREATE TRIGGER egress_ingest AFTER INSERT ON memberships BEGIN ` + registerEgressIdentitySQL + rememberFetchedEgress + ` END;
 DROP TRIGGER IF EXISTS egress_discover_input;
 CREATE TRIGGER egress_discover_input INSTEAD OF INSERT ON egress_discovery_inputs BEGIN ` + registerEgressIdentitySQL + rememberFetchedEgress + ` END;
 CREATE TRIGGER IF NOT EXISTS egress_arrival_finished AFTER UPDATE OF first_completed,state ON egress_jobs
 WHEN (OLD.first_completed=0 AND NEW.first_completed=1) OR (OLD.state!='DELETED' AND NEW.state='DELETED') BEGIN
 DELETE FROM egress_first_arrivals WHERE identity=(SELECT identity FROM egress_unique WHERE hash=NEW.hash);
 END;
 CREATE TRIGGER IF NOT EXISTS egress_arrival_source_fence BEFORE UPDATE OF url_hash,enabled ON sources
 WHEN OLD.url_hash!=NEW.url_hash OR (OLD.enabled=1 AND NEW.enabled=0) BEGIN ` + fenceDepartingFirstSource + ` END;
 CREATE TRIGGER IF NOT EXISTS egress_arrival_source_deleted BEFORE DELETE ON sources BEGIN ` + fenceDepartingFirstSource + ` END;
 CREATE TRIGGER IF NOT EXISTS egress_arrival_source_changed AFTER UPDATE OF url_hash ON sources WHEN OLD.url_hash!=NEW.url_hash BEGIN
 DELETE FROM egress_first_arrivals WHERE source_id=OLD.id;
 END;

 INSERT OR IGNORE INTO egress_first_arrivals(source_id,identity,queued_at,received_at)
 SELECT s.id,m.artifact_id,s.last_success,s.last_success FROM sources s JOIN memberships m ON m.source_id=s.id
 JOIN egress_unique u ON u.identity=m.artifact_id JOIN egress_jobs j ON j.hash=u.hash
 WHERE s.enabled=1 AND s.last_success>` + egressArrivalClock + `-` + egressArrivalWindow + `
 AND j.first_completed=0 AND j.tested=0 AND j.ever_accepted=0 AND j.state!='DELETED'
 AND NOT EXISTS(SELECT 1 FROM egress_first_verdicts f WHERE f.identity=u.identity);

 UPDATE egress_first_history SET phase='cancelled' WHERE phase NOT IN('completed','cancelled');
 DELETE FROM egress_first_backlog AS b WHERE NOT EXISTS(SELECT 1 FROM egress_unique u JOIN egress_first_arrivals a
 ON a.identity=u.identity AND a.source_id=b.source_id WHERE u.hash=b.hash);
 UPDATE egress_compatibility_receipts SET closed=1 WHERE closed=0;
 DELETE FROM egress_compatibility_queue;
 DELETE FROM egress_retirement_limits;
 DELETE FROM egress_retirements AS r WHERE r.reason='confirmed_ads_delivery_unhealthy' AND r.hits<3
 AND EXISTS(SELECT 1 FROM egress_jobs j WHERE j.hash=r.hash AND j.ever_accepted=0 AND j.state!='DELETED')
 AND NOT EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=r.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=r.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN egress_iran_guard g ON g.identity=o.identity WHERE o.hash=r.hash);

 INSERT OR IGNORE INTO egress_residential_history(hash) SELECT hash FROM egress_network_eligible;
 DROP VIEW egress_work;
 DROP VIEW egress_inventory;
 CREATE VIEW egress_inventory AS SELECT j.* FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 LEFT JOIN egress_iran_guard g ON g.identity=u.identity
 WHERE j.state!='DELETED' AND coalesce(g.state,'')!='BLOCKED'
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND (j.ever_accepted=1 OR g.state='QUARANTINED'
 OR ((j.first_completed=1 OR j.tested>0) AND EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity))
 OR (j.first_completed=0 AND j.tested=0 AND EXISTS(` + egressFreshOwner + `)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.action='deleted' AND c.expires>` + egressArrivalClock + `)));
 CREATE VIEW egress_work AS SELECT j.* FROM egress_inventory j JOIN egress_unique u ON u.hash=j.hash
 LEFT JOIN egress_iran_guard g ON g.identity=u.identity
 LEFT JOIN egress_network_results n ON n.identity=u.identity
 LEFT JOIN egress_network_review v ON v.identity=u.identity
 WHERE j.reason NOT IN ('initial_lease_interrupted','initial_lease_exhausted') AND (
 (j.first_completed=0 AND j.tested=0) OR g.state='QUARANTINED'
 OR (j.ever_accepted=1 AND g.identity IS NULL AND (
 (coalesce(n.held,0)=0 AND v.identity IS NULL)
 -- A new hold on a previously qualified route owns a finite confirmation
 -- window. Historical DC rejections have no grants and never re-arm.
 OR (n.held=1 AND EXISTS(SELECT 1 FROM egress_hosting_confirmations c WHERE c.hash=j.hash
 AND c.expires>` + egressArrivalClock + ` AND (j.attempts<c.through_attempt OR (j.attempts=c.through_attempt AND j.token!='' AND j.lease_until>` + egressArrivalClock + `)))
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>` + egressArrivalClock + `))
 OR (coalesce(n.held,0)=0 AND v.identity IS NOT NULL AND EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=j.hash) AND (v.attempts<2 OR j.token='')
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>` + egressArrivalClock + `))
 OR (coalesce(n.held,0)=0 AND j.retry_streak<3 AND EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash AND r.hits>0 AND r.first_at>` + egressArrivalClock + `-600000)))));
 UPDATE egress_jobs SET token='',lease_until=0,revision=revision+1 WHERE token!=''
 AND NOT EXISTS(SELECT 1 FROM egress_work w WHERE w.hash=egress_jobs.hash);
 UPDATE egress_run_members SET status='excluded',state='OUT_OF_SCOPE',completed_at=` + egressArrivalClock + `
 WHERE run=(SELECT max(id) FROM egress_runs) AND status='pending'
 AND NOT EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_run_members.hash);`)
	return err
}

// An HTTP unchanged response can reaffirm only the membership of its own
// verified cached generation. A malformed, aborted or empty response cannot.
func refreshUnchangedEgress(ctx context.Context, tx *sql.Tx, source string, stamp int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO egress_first_arrivals(source_id,identity,queued_at,received_at)
 SELECT m.source_id,u.identity,?2,?2 FROM memberships m CROSS JOIN egress_unique u ON u.identity=m.artifact_id
 CROSS JOIN egress_jobs j ON j.hash=u.hash WHERE m.source_id=?1 AND j.first_completed=0 AND j.tested=0 AND j.ever_accepted=0 AND j.state!='DELETED'
 AND NOT EXISTS(SELECT 1 FROM egress_first_verdicts f WHERE f.identity=u.identity)
 ON CONFLICT(source_id,identity) DO UPDATE SET queued_at=CASE WHEN received_at<=excluded.received_at-`+egressArrivalWindow+` THEN excluded.queued_at ELSE queued_at END,received_at=excluded.received_at`, source, stamp)
	return err
}
