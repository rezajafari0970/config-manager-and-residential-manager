package panel

import (
	"context"
	"database/sql"
)

const sideNow = "CAST(unixepoch('subsec')*1000 AS INTEGER)"

// Only a successful source acquisition, or a validated current snapshot on
// upgrade, enters this table. The immutable identity verdict survives ordinary
// retention. Raw and template bytes have a separate, finite lifetime.
func migrateSide(tx *sql.Tx) error {
	_, err := tx.Exec(`
 CREATE TABLE IF NOT EXISTS side_jobs(
 identity TEXT PRIMARY KEY,raw_hash TEXT NOT NULL,kind TEXT NOT NULL,size INTEGER NOT NULL,
 admitted INTEGER NOT NULL,expires INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','accepted','rejected','inconclusive','expired')),
 token TEXT NOT NULL DEFAULT '',lease_until INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,
 repairs INTEGER NOT NULL DEFAULT 0 CHECK(repairs IN(0,1)),next_run INTEGER NOT NULL DEFAULT 0,finished INTEGER NOT NULL DEFAULT 0,code TEXT NOT NULL DEFAULT '',
 evidence TEXT NOT NULL DEFAULT '{}',candidate_hash TEXT NOT NULL DEFAULT '',engine TEXT NOT NULL DEFAULT '',last_token TEXT NOT NULL DEFAULT ''
 ) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS side_metrics(id INTEGER PRIMARY KEY CHECK(id=1),identities INTEGER NOT NULL,last_measured INTEGER NOT NULL DEFAULT 0);
 INSERT OR IGNORE INTO side_metrics(id,identities) SELECT 1,count(*) FROM side_jobs;
 CREATE TRIGGER IF NOT EXISTS side_metric_add AFTER INSERT ON side_jobs BEGIN UPDATE side_metrics SET identities=identities+1 WHERE id=1; END;
 CREATE TRIGGER IF NOT EXISTS side_metric_drop AFTER DELETE ON side_jobs BEGIN UPDATE side_metrics SET identities=identities-1 WHERE id=1; END;
 CREATE INDEX IF NOT EXISTS side_expiry ON side_jobs(expires);
 CREATE INDEX IF NOT EXISTS side_recent ON side_jobs(finished DESC,identity) WHERE finished>0;
 CREATE INDEX IF NOT EXISTS side_due ON side_jobs(next_run,admitted,identity) WHERE state='pending';
 CREATE INDEX IF NOT EXISTS side_active ON side_jobs(lease_until) WHERE token!='';
 CREATE INDEX IF NOT EXISTS side_state_expiry ON side_jobs(state,expires);
 CREATE INDEX IF NOT EXISTS side_pending_blob ON side_jobs(raw_hash,expires) WHERE state IN('pending','accepted');
 CREATE INDEX IF NOT EXISTS side_candidate_blob ON side_jobs(candidate_hash,expires) WHERE state='accepted';
 CREATE TABLE IF NOT EXISTS side_sources(
 source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
 identity TEXT NOT NULL REFERENCES side_jobs(identity) ON DELETE CASCADE,expires INTEGER NOT NULL,
 PRIMARY KEY(source_id,identity)
 ) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS side_identity_sources ON side_sources(identity,source_id);
 CREATE INDEX IF NOT EXISTS side_source_expiry ON side_sources(expires);
 CREATE VIEW IF NOT EXISTS side_receipts(source_id,identity,raw_hash,kind,size,admitted,expires,fresh_payload)
 AS SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL WHERE 0;
 CREATE TRIGGER IF NOT EXISTS side_receipt INSTEAD OF INSERT ON side_receipts
 WHEN new.expires>` + sideNow + ` AND EXISTS(SELECT 1 FROM sources WHERE id=new.source_id AND enabled=1)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=new.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard WHERE identity=new.identity AND state='BLOCKED')
 AND NOT EXISTS(SELECT 1 FROM config_controls WHERE id=new.identity AND expires>` + sideNow + `) BEGIN
 -- A real response and a subsequent healthy worker measurement authorize
 -- one final grant for an input which never received a measured verdict.
 -- A 304, restart, ordinary reappearance, or changed worker flag cannot.
 UPDATE side_jobs SET state='pending',repairs=1,attempts=2,raw_hash=new.raw_hash,kind=new.kind,size=new.size,
 expires=min(expires,new.expires),next_run=` + sideNow + `,finished=0,code='infrastructure_recovery'
 WHERE identity=new.identity AND state='inconclusive' AND repairs=0 AND new.fresh_payload=1 AND expires>` + sideNow + `
 AND finished<(SELECT last_measured FROM side_metrics WHERE id=1);
 INSERT INTO side_jobs(identity,raw_hash,kind,size,admitted,expires,next_run)
 VALUES(new.identity,new.raw_hash,new.kind,new.size,new.admitted,new.expires,new.admitted)
 ON CONFLICT(identity) DO UPDATE SET admitted=excluded.admitted,expires=excluded.expires,
 raw_hash=excluded.raw_hash,kind=excluded.kind,size=excluded.size,state='pending',code='',token='',lease_until=0,next_run=excluded.admitted
 WHERE side_jobs.state IN('pending','expired') AND side_jobs.expires<=` + sideNow + `;
 INSERT OR IGNORE INTO side_sources SELECT new.source_id,j.identity,j.expires FROM side_jobs j
 WHERE j.identity=new.identity AND j.state IN('pending','accepted') AND j.expires>` + sideNow + `;
 END;
 CREATE TRIGGER IF NOT EXISTS side_member AFTER INSERT ON memberships BEGIN
 INSERT INTO side_receipts SELECT new.source_id,new.artifact_id,new.raw_hash,new.kind,new.size,a.created,a.expires,1
 FROM artifacts a WHERE a.id=new.artifact_id;
 END;
 CREATE TRIGGER IF NOT EXISTS side_source_replaced AFTER UPDATE OF url_hash ON sources
 WHEN old.url_hash!=new.url_hash BEGIN DELETE FROM side_sources WHERE source_id=new.id; END;
 CREATE TRIGGER IF NOT EXISTS side_retention AFTER UPDATE OF retention_seconds ON settings
 WHEN new.retention_seconds<old.retention_seconds BEGIN
 UPDATE side_jobs SET expires=min(expires,admitted+new.retention_seconds*1000)
 WHERE expires>` + sideNow + `; END;
 CREATE TRIGGER IF NOT EXISTS side_source_disabled AFTER UPDATE OF enabled ON sources WHEN new.enabled=0 AND old.enabled=1 BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE token!='' AND identity IN(SELECT identity FROM side_sources WHERE source_id=new.id)
 AND NOT EXISTS(SELECT 1 FROM side_sources o JOIN sources s ON s.id=o.source_id WHERE o.identity=side_jobs.identity AND s.enabled=1); END;
 CREATE TRIGGER IF NOT EXISTS side_last_owner AFTER DELETE ON side_sources BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE identity=old.identity AND token!=''
 AND NOT EXISTS(SELECT 1 FROM side_sources o JOIN sources s ON s.id=o.source_id WHERE o.identity=old.identity AND s.enabled=1); END;
 CREATE TRIGGER IF NOT EXISTS side_measured AFTER UPDATE OF state ON side_jobs
 WHEN new.state IN('rejected','accepted') AND new.evidence->>'$.side_version'='side_v1'
 AND new.evidence->>'$.google'='passed' AND new.evidence->>'$.facebook'='passed' AND new.evidence->>'$.instagram'='passed'
 AND new.evidence->>'$.twitter'='passed' AND new.evidence->>'$.telegram'='passed' AND new.evidence->>'$.cloudflare'='passed'
 AND new.evidence->>'$.warp_mode' IN('on','plus','off') BEGIN
 UPDATE side_metrics SET last_measured=max(last_measured,new.finished) WHERE id=1; END;
 CREATE TRIGGER IF NOT EXISTS side_owner_expiry AFTER UPDATE OF expires ON side_jobs WHEN new.expires!=old.expires BEGIN
 UPDATE side_sources SET expires=new.expires WHERE identity=new.identity; END;
 CREATE TRIGGER IF NOT EXISTS side_finish_owners AFTER UPDATE OF state ON side_jobs WHEN new.state IN('rejected','inconclusive','expired') BEGIN
 DELETE FROM side_sources WHERE identity=new.identity; END;
 CREATE TRIGGER IF NOT EXISTS side_control_grant AFTER INSERT ON config_controls BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE identity=new.id AND token!=''; END;
 CREATE TRIGGER IF NOT EXISTS side_exclusion_grant AFTER INSERT ON input_exclusions BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE identity=new.identity AND token!='';
 DELETE FROM side_sources WHERE identity=new.identity; END;
 CREATE TRIGGER IF NOT EXISTS side_guard_grant AFTER INSERT ON egress_iran_guard WHEN new.state='BLOCKED' BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE identity=new.identity AND token!=''; END;
 CREATE TRIGGER IF NOT EXISTS side_guard_block_grant AFTER UPDATE OF state ON egress_iran_guard WHEN new.state='BLOCKED' BEGIN
 UPDATE side_jobs SET token='',lease_until=0 WHERE identity=new.identity AND token!=''; END;
 CREATE VIEW IF NOT EXISTS side_work AS SELECT j.* FROM side_jobs j WHERE j.state='pending'
 AND j.expires>` + sideNow + `
 AND EXISTS(SELECT 1 FROM side_sources o JOIN sources s ON s.id=o.source_id WHERE o.identity=j.identity AND s.enabled=1)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=j.identity AND c.expires>` + sideNow + `)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=j.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=j.identity AND g.state='BLOCKED');
 CREATE VIEW IF NOT EXISTS side_export_inputs(identity,raw_hash,candidate_hash,engine) AS
 SELECT j.identity,j.raw_hash,j.candidate_hash,j.engine FROM side_jobs j JOIN artifacts a ON a.id=j.identity
 WHERE j.state='accepted' AND j.expires>` + sideNow + ` AND a.expires>` + sideNow + `
 AND EXISTS(SELECT 1 FROM memberships m JOIN sources s ON s.id=m.source_id WHERE m.artifact_id=a.id AND s.enabled=1)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=a.id AND c.expires>` + sideNow + `)
 AND j.raw_hash NOT IN (SELECT hash FROM input_blocked) AND j.identity NOT IN (SELECT identity FROM input_blocked_identities);
 INSERT INTO side_receipts SELECT m.source_id,m.artifact_id,m.raw_hash,m.kind,m.size,a.created,a.expires,0
 FROM memberships m JOIN sources s ON s.id=m.source_id JOIN artifacts a ON a.id=m.artifact_id
 WHERE s.enabled=1 AND m.generation=s.generation AND a.expires>` + sideNow + `
 AND s.last_success>` + sideNow + `-(SELECT retention_seconds*1000 FROM settings WHERE id=1)
 ORDER BY m.artifact_id,m.source_id;`)
	return err
}

// A validated response held for source cardinality still deserves its initial
// check. It acquires no publication authority before ordinary membership.
func rememberHeldSide(ctx context.Context, tx *sql.Tx, records string, stamp int64, args ...any) error {
	params := []any{stamp, stamp}
	params = append(params, args...)
	_, err := tx.ExecContext(ctx, `INSERT INTO side_receipts
 SELECT i.source_id,i.identity,i.hash,i.kind,i.size,?,?+(SELECT retention_seconds*1000 FROM settings WHERE id=1),1
 FROM (`+records+`) i`, params...)
	return err
}

// GC uses indexed hashes before looking up the small set of active owners.
// The first decision remains for deduplication after its blobs are released.
const sideReferenced = `SELECT 1 FROM side_jobs j WHERE raw_hash=? AND state IN('pending','accepted') AND expires>` + sideNow + `
 AND EXISTS(SELECT 1 FROM side_sources o WHERE o.identity=j.identity)
 UNION ALL SELECT 1 FROM side_jobs j WHERE candidate_hash=? AND state='accepted' AND expires>` + sideNow + `
 AND EXISTS(SELECT 1 FROM side_sources o WHERE o.identity=j.identity)`

// A successful 304 confirms ownership of the live generation. It can be the
// first genuine observation following upgrade for a rarely refreshed source.
func rememberUnchangedSide(ctx context.Context, tx *sql.Tx, source string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO side_receipts SELECT m.source_id,m.artifact_id,m.raw_hash,m.kind,m.size,a.created,a.expires,0
 FROM memberships m JOIN artifacts a ON a.id=m.artifact_id JOIN sources s ON s.id=m.source_id
 WHERE m.source_id=? AND m.generation=s.generation AND a.expires>`+sideNow+`
 AND NOT EXISTS(SELECT 1 FROM side_sources o WHERE o.source_id=m.source_id AND o.identity=m.artifact_id)
 AND NOT EXISTS(SELECT 1 FROM side_jobs j WHERE j.identity=m.artifact_id AND j.state IN('rejected','inconclusive'))`, source)
	return err
}
