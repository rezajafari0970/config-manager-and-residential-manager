package panel

import (
	"context"
	"database/sql"
)

// A collector identity needs one initial ordinary assessment. Keep its actual
// tested raw digest for provenance. Publication remains bound to exact, current
// source membership and the existing template/connection receipts.
const ordinaryAssessment = `tested>0 AND version!='' AND (
 core='failed' OR (core='passed' AND connection IN ('passed','partial','failed'))
 OR (core='not_run' AND rule='preparation' AND code!='' AND code NOT IN
 ('original_blob_unavailable','candidate_blob_unavailable','probe_preparation_failed','preparation_recovered','probe_infrastructure_error','probe_job_timeout','probe_resource_or_signal_failure','missing_runtime_asset')))`

func (s *Store) migrateV51() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 51 {
		return err
	}
	_, err = tx.Exec(`
 CREATE INDEX IF NOT EXISTS conversion_membership_raw_source ON memberships(raw_hash,source_id);
 CREATE INDEX IF NOT EXISTS conversion_active_leases ON conversion_jobs(lease_until,hash) WHERE token!='';
 CREATE TABLE IF NOT EXISTS conversion_first_turns(
 source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,started INTEGER NOT NULL
 ) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS conversion_first_assessed(
 identity TEXT PRIMARY KEY,hash TEXT NOT NULL,version TEXT NOT NULL,tested INTEGER NOT NULL
 ) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS conversion_first_backlog(
 source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,identity TEXT NOT NULL,
 hash TEXT NOT NULL REFERENCES egress_jobs(hash) ON DELETE CASCADE,
 PRIMARY KEY(source_id,identity)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS conversion_first_backlog_identity ON conversion_first_backlog(identity);
 CREATE INDEX IF NOT EXISTS conversion_first_backlog_hash ON conversion_first_backlog(hash);
 CREATE TRIGGER IF NOT EXISTS conversion_first_source_changed AFTER UPDATE OF url_hash ON sources WHEN NEW.url_hash!=OLD.url_hash BEGIN
 DELETE FROM conversion_first_backlog WHERE source_id=NEW.id; END;
 INSERT OR IGNORE INTO conversion_first_assessed(identity,hash,version,tested)
 SELECT o.identity,r.hash,r.version,r.tested FROM conversion_results r JOIN egress_owners o ON o.hash=r.hash
 WHERE ` + ordinaryAssessment + ` ORDER BY r.tested,r.hash;
 CREATE VIEW IF NOT EXISTS conversion_first_inputs AS
 SELECT hash,kind,size FROM (
 SELECT b.hash,e.kind,e.size,row_number() OVER(PARTITION BY b.identity ORDER BY
 CASE WHEN j.token!='' AND j.lease_until>CAST(unixepoch('subsec')*1000 AS INTEGER) THEN 0 ELSE 1 END,b.hash) AS representative
 FROM conversion_first_backlog b JOIN sources s ON s.id=b.source_id AND s.enabled=1
 JOIN egress_jobs e ON e.hash=b.hash AND e.state!='DELETED' AND e.paused=0
 LEFT JOIN conversion_jobs j ON j.hash=b.hash
 WHERE NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=b.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))
 AND NOT EXISTS(SELECT 1 FROM input_blocked i WHERE i.hash=b.hash)
 AND NOT EXISTS(SELECT 1 FROM input_blocked_identities i WHERE i.identity=b.identity)
 AND (j.token!='' AND j.lease_until>CAST(unixepoch('subsec')*1000 AS INTEGER) OR NOT EXISTS(
 SELECT 1 FROM memberships m JOIN sources ms ON ms.id=m.source_id AND ms.enabled=1 JOIN artifacts a ON a.id=m.artifact_id
 WHERE m.artifact_id=b.identity AND a.expires>CAST(unixepoch('subsec')*1000 AS INTEGER)))
 ) WHERE representative=1;
 CREATE VIEW IF NOT EXISTS conversion_work_inputs AS SELECT hash,kind,size FROM conversion_inputs
 UNION ALL SELECT f.hash,f.kind,f.size FROM conversion_first_inputs f
 WHERE NOT EXISTS(SELECT 1 FROM conversion_inputs i WHERE i.hash=f.hash);`)
	if err != nil {
		return err
	}
	for _, action := range []string{"INSERT", "UPDATE"} {
		// This includes fresh, byte-identical receipt reuse. Neither admission
		// nor a worker's infrastructure failure is a first assessment.
		_, err = tx.Exec("CREATE TRIGGER IF NOT EXISTS conversion_first_result_" + action + " AFTER " + action + ` ON conversion_results WHEN
 EXISTS(SELECT 1 FROM conversion_results WHERE hash=NEW.hash AND ` + ordinaryAssessment + `)
 BEGIN
 INSERT OR IGNORE INTO conversion_first_assessed(identity,hash,version,tested)
 SELECT DISTINCT identity,NEW.hash,NEW.version,NEW.tested FROM egress_owners WHERE hash=NEW.hash
 ON CONFLICT(identity) DO NOTHING;
 DELETE FROM conversion_first_backlog WHERE identity IN (SELECT identity FROM egress_owners WHERE hash=NEW.hash);
 END;`)
		if err != nil {
			return err
		}
	}
	// Only a saved first-assessment owner demonstrates that an old withdrawal
	// was natural. A historical raw blob by itself cannot establish permission.
	if err = rememberOrdinaryFirst(context.Background(), tx, `SELECT b.source_id,u.identity,b.hash,j.kind,j.size FROM egress_first_backlog b JOIN egress_unique u ON u.hash=b.hash JOIN egress_jobs j ON j.hash=b.hash`); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=51"); err != nil {
		return err
	}
	return tx.Commit()
}

// records is a trusted SELECT of source_id, identity, hash, kind and size. The
// tested representative remains stable across cosmetic aliases; an already
// leased exact source raw can finish its first assessment after withdrawal.
func rememberOrdinaryFirst(ctx context.Context, tx *sql.Tx, records string, args ...any) error {
	_, err := tx.ExecContext(ctx, `WITH received AS (`+records+`) INSERT OR IGNORE INTO conversion_first_backlog(source_id,identity,hash)
 SELECT r.source_id,r.identity,CASE WHEN j.token!='' AND j.lease_until>CAST(unixepoch('subsec')*1000 AS INTEGER) THEN r.hash ELSE u.hash END
 FROM received r JOIN egress_unique u ON u.identity=r.identity JOIN sources s ON s.id=r.source_id AND s.enabled=1
 LEFT JOIN conversion_jobs j ON j.hash=r.hash
 WHERE NOT EXISTS(SELECT 1 FROM conversion_first_assessed a WHERE a.identity=r.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=r.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=r.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=r.identity AND c.action='deleted' AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))`, args...)
	return err
}

// Charge a shared first observation to each owning source. Ranking uses the
// least recently served owner before FIFO within the existing first-test lane.
const conversionFirstSources = `SELECT source_id FROM memberships WHERE raw_hash=i.hash
 UNION SELECT source_id FROM conversion_first_backlog WHERE hash=i.hash`

const conversionFirstSourceOrder = `coalesce((SELECT min(coalesce(t.started,0)) FROM (` + conversionFirstSources + `) own
 JOIN sources s ON s.id=own.source_id AND s.enabled=1 LEFT JOIN conversion_first_turns t ON t.source_id=own.source_id),0)`

func recordFirstProbeTurn(ctx context.Context, tx *sql.Tx, hash string, now int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO conversion_first_turns(source_id,started)
 SELECT s.id,? FROM sources s WHERE s.enabled=1 AND s.id IN (
 SELECT source_id FROM memberships WHERE raw_hash=? UNION SELECT source_id FROM conversion_first_backlog WHERE hash=?)
 ON CONFLICT(source_id) DO UPDATE SET started=excluded.started`, now, hash, hash)
	return err
}

// Prepared templates have their own byte-level lease guard. Before preparation,
// also serialize probes of raw aliases belonging to a currently leased identity.
const ordinaryLeasedAliases = `WITH busy_aliases(hash) AS MATERIALIZED (
 SELECT DISTINCT alias.hash FROM conversion_jobs busy CROSS JOIN egress_owners owner ON owner.hash=busy.hash
 CROSS JOIN egress_owners alias ON alias.identity=owner.identity WHERE busy.token!='' AND busy.lease_until>?
) `
