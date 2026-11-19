package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

// A review belongs to the tested identity. Only this small ledger extends
// the normal discovery scope to archived inputs. Two leases are available;
// an interrupted final lease can never re-arm itself through source polling.
func (s *Store) migrateV49() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 49 {
		return err
	}
	_, err = tx.Exec(`
 CREATE TABLE IF NOT EXISTS egress_residential_history(
 hash TEXT PRIMARY KEY REFERENCES egress_jobs(hash) ON DELETE CASCADE
 ) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS egress_network_review(
 identity TEXT PRIMARY KEY REFERENCES egress_unique(identity) ON DELETE CASCADE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 2)
 ) WITHOUT ROWID;
 DROP VIEW egress_inventory;
 CREATE VIEW egress_inventory AS SELECT j.* FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 WHERE j.state!='DELETED' AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='BLOCKED')
 AND (EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity) OR j.ever_accepted=1
 OR EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='QUARANTINED')
 OR ((EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity)
 OR (j.first_completed=0 AND j.tested=0 AND EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.hash=u.hash)))
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.action='deleted' AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER))));
 DROP VIEW egress_network_eligible;
 CREATE VIEW egress_network_eligible AS SELECT e.*,e.valid_until AS network_valid_until FROM egress_eligible e
 JOIN egress_unique u ON u.hash=e.hash
 WHERE NOT EXISTS(SELECT 1 FROM egress_network_results n WHERE n.identity=u.identity AND n.held=1)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity);
 DROP VIEW egress_work;
 CREATE VIEW egress_work AS SELECT j.* FROM egress_inventory j JOIN egress_unique u ON u.hash=j.hash
 LEFT JOIN egress_iran_guard g ON g.identity=u.identity
 LEFT JOIN egress_network_results n ON n.identity=u.identity
 LEFT JOIN egress_network_review v ON v.identity=u.identity
 WHERE j.reason NOT IN ('initial_lease_interrupted','initial_lease_exhausted') AND (
 (j.tested=0 AND j.first_completed=0)
 OR (g.identity IS NULL AND n.held=1 AND n.clean_rounds=1 AND n.hash=j.hash AND n.candidate_hash=j.candidate_hash
 AND n.policy=(SELECT value FROM metadata WHERE key='ads-exit-network-policy') AND n.clean_until>CAST(unixepoch('subsec')*1000 AS INTEGER))
 OR (g.state='QUARANTINED')
 OR (g.identity IS NULL AND coalesce(n.held,0)=0 AND v.identity IS NULL AND j.ever_accepted=1)
 OR (g.identity IS NULL AND v.identity IS NOT NULL AND (v.attempts<2 OR
 (j.ever_accepted=1 AND j.token='' AND EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=j.hash))) AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity AND c.expires>CAST(unixepoch('subsec')*1000 AS INTEGER)))
 OR (g.identity IS NULL AND j.retry_streak<3 AND EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash AND r.hits>0 AND r.first_at>CAST(unixepoch('subsec')*1000 AS INTEGER)-600000)));
 CREATE TRIGGER IF NOT EXISTS egress_review_deleted AFTER UPDATE OF state ON egress_jobs WHEN NEW.state='DELETED' BEGIN
 DELETE FROM egress_network_review WHERE identity=(SELECT identity FROM egress_unique WHERE hash=NEW.hash);
 DELETE FROM egress_residential_history WHERE hash=NEW.hash;
 END;`)
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT u.hash FROM egress_network_results n JOIN egress_unique u ON u.identity=n.identity JOIN egress_jobs j ON j.hash=u.hash WHERE n.held=1 AND j.state!='DELETED'`)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, hash)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		if err = s.reconcileLegacyNetwork(tx, hash); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO egress_residential_history(hash)
 SELECT j.hash FROM egress_jobs j JOIN egress_unique u ON u.hash=j.hash
 JOIN egress_network_results n ON n.identity=u.identity AND n.held=0 AND n.hash=j.hash AND n.candidate_hash=j.candidate_hash AND n.checked_at=j.tested
 JOIN egress_health h ON h.hash=j.hash AND h.checked_at=j.tested AND h.status='healthy' AND h.valid_until>j.tested
 JOIN egress_geo_results g ON g.hash=j.hash AND g.checked_at=j.tested AND g.complete=1 AND g.valid_until>j.tested
 WHERE j.ever_accepted=1 AND j.state!='DELETED' AND j.valid_until>j.tested AND j.candidate_hash!=''
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard i WHERE i.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash)`); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=49"); err != nil {
		return err
	}
	return tx.Commit()
}

// Replay at the ORIGINAL receipt clock. This evaluates what was observed at
// that time; the old route, health and country expiration clocks never advance.
func (s *Store) reconcileLegacyNetwork(tx *sql.Tx, hash string) error {
	var identity, checkedHash, candidate, persistedCandidate string
	var checked, tested, finished int64
	var original, storedDecision, lastAdverse, storedNetwork []byte
	if err := tx.QueryRow(`SELECT u.identity,n.hash,n.checked_at,n.last_finished,n.candidate_hash,j.tested,j.candidate_hash,j.report,j.decision,n.last_adverse,n.summary
 FROM egress_unique u JOIN egress_network_results n ON n.identity=u.identity JOIN egress_jobs j ON j.hash=u.hash WHERE u.hash=?`, hash).Scan(&identity, &checkedHash, &checked, &finished, &candidate, &tested, &persistedCandidate, &original, &storedDecision, &lastAdverse, &storedNetwork); err != nil {
		return err
	}
	var measured egress.Report
	var before egress.Decision
	bound := hash == checkedHash && checked > 0 && tested == checked && candidate == persistedCandidate && json.Unmarshal(original, &measured) == nil && measured.Hash == hash && measured.Finished == finished && json.Unmarshal(storedDecision, &before) == nil
	var d egress.Decision
	if bound {
		r, err := s.vault.Open(hash)
		if err == nil {
			raw, readErr := io.ReadAll(io.LimitReader(r, repair.MaxBytes+1))
			r.Close()
			if readErr == nil && len(raw) <= repair.MaxBytes && egress.Hash(raw) == hash {
				plan := egress.Prepare(raw)
				if len(plan.Variants) == 2 && plan.Complete && (candidate == "" || candidate == plan.Variants[1].Hash) {
					d = egress.Evaluate(measured, plan, hash, checked)
				}
			}
		}
	}
	n := d.Network
	if n.Policy == "" {
		n = egress.NetworkVerdict{Version: egress.NetworkVersion, Policy: egress.NetworkPolicyVersion, State: "unknown", Reason: "legacy_network_receipt_unbound"}
	}
	summary, err := json.Marshal(n)
	if err != nil {
		return err
	}
	// Only a corroborated veto under the current rule crosses the boundary.
	// Retain the old adverse JSON as an audit record until fresh evidence exists.
	_, err = tx.Exec(`UPDATE egress_network_results SET held=?,policy=?,state=?,reason=?,summary=?,valid_until=?,clean_rounds=0,clean_until=0,
 last_adverse=CASE WHEN ? THEN ? ELSE last_adverse END WHERE identity=?`, n.BlocksResidential(), egress.NetworkPolicyVersion, n.State, n.Reason, string(summary), n.Until, n.BlocksResidential(), string(summary), identity)
	if err != nil {
		return err
	}
	if n.BlocksResidential() {
		return nil
	}
	// A later unknown or clean receipt is not the observation that created
	// a sticky hold. The old reducer could also have merged several receipts.
	// Only settle locally if this receipt accounts for the entire adverse record.
	var previous, atReceipt egress.NetworkVerdict
	originalAdverse := json.Unmarshal(lastAdverse, &previous) == nil && json.Unmarshal(storedNetwork, &atReceipt) == nil &&
		atReceipt.BlocksResidential() && (reflect.DeepEqual(previous, atReceipt) ||
		reflect.DeepEqual(previous, mergeHostingFlows(atReceipt, egress.NetworkVerdict{})))
	if originalAdverse && d.Negative && !before.Eligible {
		return nil
	}
	if originalAdverse && d.Negative {
		// Reclassification may remove eligibility but cannot renew any clock.
		_, err = tx.Exec("UPDATE egress_jobs SET valid_until=0,next_run=0 WHERE hash=?", hash)
		return err
	}
	// Identical qualifying profiles retain their existing route and geography.
	// A restricted subset must obtain fresh country evidence scoped to that subset.
	if originalAdverse && d.Eligible && before.Eligible && !d.CountryConflict && slices.Equal(d.QualifiedProfiles, before.QualifiedProfiles) && slices.Equal(d.QualifiedDomains, before.QualifiedDomains) && candidate != "" {
		_, err = tx.Exec(`UPDATE egress_jobs SET next_run=min(next_run,CAST(unixepoch('subsec')*1000 AS INTEGER)) WHERE hash=? AND ever_accepted=1`, hash)
		return err
	}
	if _, err = tx.Exec("INSERT OR IGNORE INTO egress_network_review(identity) VALUES(?)", identity); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE egress_jobs SET next_run=CASE WHEN ever_accepted=1 THEN 0 ELSE CAST(unixepoch('subsec')*1000 AS INTEGER) END WHERE hash=?`, hash)
	return err
}

func finishNetworkReview(ctx context.Context, tx *sql.Tx, hash string, d egress.Decision) (bool, error) {
	if d.Network.BlocksResidential() || d.Eligible || d.Negative {
		_, err := tx.ExecContext(ctx, "DELETE FROM egress_network_review WHERE identity=(SELECT identity FROM egress_unique WHERE hash=?)", hash)
		return false, err
	}
	if d.Reason == "ads_hosting_route_unresolved" {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO egress_network_review(identity,attempts) SELECT identity,1 FROM egress_unique WHERE hash=?", hash); err != nil {
			return false, err
		}
	}
	var attempts int
	err := tx.QueryRowContext(ctx, `SELECT v.attempts FROM egress_unique u JOIN egress_network_review v ON v.identity=u.identity WHERE u.hash=?`, hash).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return attempts < 2, err
}
