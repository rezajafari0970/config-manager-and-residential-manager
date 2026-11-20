package panel

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
)

// A committed generation may disappear while its first assessment is still
// waiting or leased. Preserve just those representatives and their source.
// Staging, administrative deletion and previously assessed archives do not
// generate work. Historical withdrawals have no trustworthy deletion cause.
func (s *Store) migrateV47() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 47 {
		return err
	}
	_, err = tx.Exec(`
 CREATE TABLE IF NOT EXISTS egress_first_backlog(
 source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
 hash TEXT NOT NULL REFERENCES egress_unique(hash) ON DELETE CASCADE,
 PRIMARY KEY(source_id,hash)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_first_backlog_hash ON egress_first_backlog(hash);
 CREATE TRIGGER IF NOT EXISTS egress_first_finished AFTER UPDATE OF first_completed,state ON egress_jobs
 WHEN (OLD.first_completed=0 AND NEW.first_completed!=0) OR (OLD.state!='DELETED' AND NEW.state='DELETED')
 BEGIN DELETE FROM egress_first_backlog WHERE hash=NEW.hash; END;
 CREATE TRIGGER IF NOT EXISTS egress_first_source_replaced AFTER UPDATE OF url_hash ON sources WHEN NEW.url_hash!=OLD.url_hash
 BEGIN DELETE FROM egress_first_backlog WHERE source_id=NEW.id; END;
 DROP VIEW egress_inventory;
 CREATE VIEW egress_inventory AS SELECT j.* FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 WHERE j.state!='DELETED' AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='BLOCKED')
 AND (EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity) OR j.ever_accepted=1
 OR EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='QUARANTINED')
 OR (j.first_completed=0 AND j.tested=0 AND EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.action='deleted' AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))));
 PRAGMA user_version=47;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Drive both paths from the affected memberships. Starting with tested=0
// would visit every archived unassessed job on every source completion.
const egressRememberPending = `INSERT OR IGNORE INTO egress_first_backlog(source_id,hash)
 SELECT m.source_id,u.hash FROM memberships m CROSS JOIN egress_unique u ON u.identity=m.artifact_id
 CROSS JOIN egress_jobs j ON j.hash=u.hash
 WHERE j.tested=0 AND j.first_completed=0 AND j.state!='DELETED'
 AND EXISTS(SELECT 1 FROM egress_first_arrivals a WHERE a.source_id=m.source_id AND a.identity=m.artifact_id AND a.received_at>` + egressArrivalClock + `-` + egressArrivalWindow + `)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='BLOCKED')
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.action='deleted' AND c.expires>?) AND `

func rememberExpiredEgress(ctx context.Context, tx *sql.Tx, stamp int64) error {
	if err := rememberOrdinaryFirst(ctx, tx, `SELECT m.source_id,m.artifact_id AS identity,m.raw_hash AS hash,m.kind,m.size FROM memberships m
 WHERE m.artifact_id IN(SELECT id FROM artifacts WHERE expires<=?)`, stamp); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, egressRememberPending+`m.artifact_id IN (SELECT id FROM artifacts WHERE expires<=?)`, stamp, stamp)
	return err
}

func rememberReplacedEgress(ctx context.Context, tx *sql.Tx, result collect.Result, source, token string, stamp int64) error {
	candidates := "SELECT identity FROM staged WHERE token=?"
	renamed := "SELECT 1 FROM staged t WHERE t.token=? AND t.identity=m.artifact_id AND t.hash!=m.raw_hash"
	arg := token
	if !result.Staged {
		byIdentity := make(map[string]string, len(result.Items))
		for _, item := range result.Items {
			byIdentity[item.Identity] = item.Hash
		}
		encoded, err := json.Marshal(byIdentity)
		if err != nil {
			return err
		}
		candidates, arg = "SELECT key FROM json_each(?)", string(encoded)
		renamed = "SELECT 1 FROM json_each(?) t WHERE t.key=m.artifact_id AND t.value!=m.raw_hash"
	}
	// A cosmetic replacement still owns the same identity, but the worker
	// must finish the exact raw it already leased. Consider only active jobs
	// in this extra branch; unleased renames need no new private pin.
	if err := rememberOrdinaryFirst(ctx, tx, `SELECT m.source_id,m.artifact_id AS identity,m.raw_hash AS hash,m.kind,m.size FROM memberships m
 WHERE m.source_id=? AND m.artifact_id NOT IN (`+candidates+`)
 UNION ALL SELECT m.source_id,m.artifact_id,m.raw_hash,m.kind,m.size FROM conversion_jobs j CROSS JOIN memberships m ON m.raw_hash=j.hash
 WHERE j.token!='' AND j.lease_until>? AND m.source_id=? AND EXISTS (`+renamed+")", source, arg, stamp, source, arg); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, egressRememberPending+"m.source_id=? AND m.artifact_id NOT IN ("+candidates+")", stamp, source, arg)
	return err
}
