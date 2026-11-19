package panel

import (
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// This ledger retains the original no-observation receipt, including after
// the new driver measures the config. Only its small source queue grants work.
const compatibilitySchema = `
 CREATE TABLE IF NOT EXISTS egress_compatibility_receipts(
 hash TEXT PRIMARY KEY REFERENCES egress_jobs(hash) ON DELETE CASCADE,
 identity TEXT NOT NULL,tested INTEGER NOT NULL,report TEXT NOT NULL,decision TEXT NOT NULL,closed INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_compatibility_pending ON egress_compatibility_receipts(identity,hash) WHERE closed=0;
 CREATE TABLE IF NOT EXISTS egress_compatibility_queue(
 hash TEXT NOT NULL REFERENCES egress_compatibility_receipts(hash) ON DELETE CASCADE,
 source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,PRIMARY KEY(hash,source_id)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_compatibility_source ON egress_compatibility_queue(source_id,hash);
 CREATE VIEW IF NOT EXISTS egress_compatibility_work AS SELECT DISTINCT p.hash FROM egress_compatibility_queue p
 CROSS JOIN sources s ON s.id=p.source_id CROSS JOIN egress_jobs j ON j.hash=p.hash
 CROSS JOIN egress_unique u ON u.hash=p.hash CROSS JOIN egress_compatibility_receipts r ON r.hash=p.hash
 WHERE s.enabled=1 AND r.closed=0 AND r.identity=u.identity AND j.first_completed=1 AND j.tested=r.tested AND j.ever_accepted=0 AND j.paused=0 AND j.state!='DELETED'
 AND (j.attempts<3 OR (j.attempts=3 AND j.token!='' AND j.lease_until>CAST(unixepoch('subsec')*1000 AS INTEGER)))
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity);
 CREATE TRIGGER IF NOT EXISTS egress_compatibility_settled AFTER UPDATE OF tested ON egress_jobs
 WHEN NEW.first_completed=1 AND (NEW.tested!=OLD.tested OR (OLD.token!='' AND NEW.token='')) BEGIN
 UPDATE egress_compatibility_receipts SET closed=1 WHERE hash=NEW.hash AND closed=0;
 DELETE FROM egress_compatibility_queue WHERE hash=NEW.hash; END;
 CREATE TRIGGER IF NOT EXISTS egress_compatibility_spent AFTER UPDATE OF state,token ON egress_jobs
 WHEN NEW.state='DELETED' OR (OLD.token!='' AND NEW.token='' AND NEW.attempts>=3) BEGIN
 UPDATE egress_compatibility_receipts SET closed=1 WHERE hash=NEW.hash AND closed=0;
 DELETE FROM egress_compatibility_queue WHERE hash=NEW.hash; END;
 CREATE TRIGGER IF NOT EXISTS egress_compatibility_replaced AFTER UPDATE OF url_hash ON sources WHEN NEW.url_hash!=OLD.url_hash BEGIN
 DELETE FROM egress_compatibility_queue WHERE source_id=OLD.id; END;
 CREATE TRIGGER IF NOT EXISTS egress_compatibility_return AFTER INSERT ON memberships
 WHEN EXISTS(SELECT 1 FROM egress_compatibility_receipts r WHERE r.identity=NEW.artifact_id AND r.closed=0) BEGIN
 INSERT OR IGNORE INTO egress_compatibility_queue(hash,source_id)
 SELECT r.hash,NEW.source_id FROM egress_compatibility_receipts r JOIN egress_unique u ON u.identity=r.identity AND u.hash=r.hash
 JOIN egress_jobs j ON j.hash=r.hash JOIN sources s ON s.id=NEW.source_id AND s.enabled=1
 WHERE r.identity=NEW.artifact_id AND r.closed=0 AND j.first_completed=1 AND j.tested=r.tested AND j.attempts<3
 AND j.state!='DELETED' AND j.paused=0 AND j.ever_accepted=0
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER));
 UPDATE egress_jobs SET next_run=0 WHERE hash IN(SELECT r.hash FROM egress_compatibility_receipts r
 JOIN egress_compatibility_queue p ON p.hash=r.hash AND p.source_id=NEW.source_id WHERE r.identity=NEW.artifact_id AND r.closed=0)
 AND attempts=1 AND token=''; END;
 CREATE TRIGGER IF NOT EXISTS egress_compatibility_representative AFTER DELETE ON egress_unique BEGIN
 DELETE FROM egress_compatibility_queue WHERE hash=OLD.hash; END;`

// Source membership or an existing exact-byte withdrawal pin establishes
// custody. Historical sightings and staging cannot authorize a new worker.
const compatibilityOwners = `SELECT u.hash,m.source_id FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id
 UNION SELECT hash,source_id FROM egress_first_backlog
 UNION SELECT b.hash,b.source_id FROM conversion_first_backlog b JOIN egress_unique u ON u.identity=b.identity AND u.hash=b.hash`

func (s *Store) recoverCompatibleReceipts(tx *sql.Tx) error {
	if _, err := tx.Exec(compatibilitySchema + strings.NewReplacer("egress_retirement_fence_", "egress_compatibility_fence_", "egress_retirement_sources", "egress_compatibility_queue").Replace(retirementFences)); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT j.hash FROM egress_jobs j CROSS JOIN egress_unique u ON u.hash=j.hash
 WHERE j.first_completed=1 AND j.attempts=1 AND j.ever_accepted=0 AND j.paused=0 AND j.token=''
 AND j.state='UNSUPPORTED' AND j.reason='driver_unavailable' AND j.tested>0 AND j.claimed_at>0
 AND j.valid_until=0 AND j.candidate_hash='' AND j.deep_completed=0
 AND NOT EXISTS(SELECT 1 FROM egress_compatibility_receipts r WHERE r.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_settlements t WHERE t.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results n WHERE n.identity=u.identity AND n.held=1)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_owners a JOIN input_exclusions x ON x.identity=a.identity WHERE a.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners a JOIN egress_iran_guard g ON g.identity=a.identity WHERE a.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners a JOIN config_controls c ON c.id=a.identity WHERE a.hash=j.hash AND c.expires>?)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>?)`, egress.Now(), egress.Now())
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		var b, d []byte
		var tested, claimed int64
		if err = tx.QueryRow("SELECT report,decision,tested,claimed_at FROM egress_jobs WHERE hash=?", hash).Scan(&b, &d, &tested, &claimed); err != nil {
			return err
		}
		var r egress.Report
		var prior egress.Decision
		if json.Unmarshal(b, &r) != nil || !egress.ValidReportShape(r, hash) || r.Code != "driver_unavailable" ||
			r.Core != "" || r.CoreSHA != "" || r.Waves != 0 || r.Infrastructure || r.ResourcePressure ||
			r.Started <= 0 || r.Finished <= 0 || r.Started < claimed-2000 || r.Finished < r.Started || r.Finished > tested+2000 ||
			len(r.Attempts)+len(r.Checks)+len(r.Samples)+len(r.Health)+len(r.Delivery)+len(r.Evidence) != 0 ||
			json.Unmarshal(d, &prior) != nil || prior.State != "UNSUPPORTED" || prior.Reason != "driver_unavailable" ||
			prior.Eligible || prior.Negative || prior.CountryConflict || prior.Network.BlocksResidential() {
			continue
		}
		plan, ok := s.receiptPlan(hash)
		if !ok || !plan.Complete || len(plan.Variants) != 2 {
			continue
		}
		if _, err = tx.Exec("INSERT INTO egress_compatibility_receipts(hash,identity,tested,report,decision) SELECT hash,identity,?,?,? FROM egress_unique WHERE hash=?", tested, string(b), string(d), hash); err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO egress_compatibility_queue(hash,source_id)
 SELECT own.hash,own.source_id FROM (`+compatibilityOwners+`) own JOIN sources s ON s.id=own.source_id
 WHERE own.hash=? AND s.enabled=1`, hash); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?1 AND EXISTS(SELECT 1 FROM egress_compatibility_queue p WHERE p.hash=?1)", hash); err != nil {
			return err
		}
	}
	return nil
}
