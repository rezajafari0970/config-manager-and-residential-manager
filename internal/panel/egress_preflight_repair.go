package panel

import (
	"bytes"
	"database/sql"
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// The v54 compatibility ledger authenticates the original, empty first
// receipt. Preserve any subsequent structural receipt separately. Neither
// entry supplies evidence about connectivity, hosting, residential or health.
func (s *Store) migrateV55() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 55 {
		return err
	}
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS egress_compatibility_preflight(
 hash TEXT PRIMARY KEY REFERENCES egress_compatibility_receipts(hash) ON DELETE CASCADE,
 tested INTEGER NOT NULL,report TEXT NOT NULL,decision TEXT NOT NULL) WITHOUT ROWID`); err != nil {
		return err
	}
	// The sparse ledger is the driving table; ordinary historical negatives
	// and reports produced outside this compatibility review are out of scope.
	rows, err := tx.Query(`SELECT c.hash FROM egress_compatibility_receipts c
 CROSS JOIN egress_unique u ON u.hash=c.hash AND u.identity=c.identity
 CROSS JOIN egress_jobs j ON j.hash=c.hash WHERE j.first_completed=1 AND j.paused=0 AND j.ever_accepted=0
 AND j.attempts BETWEEN 1 AND 3 AND j.state IN ('UNSUPPORTED','UNKNOWN','PENDING') AND j.claimed_at>0
 AND j.valid_until=0 AND j.candidate_hash='' AND j.tested>=c.tested AND c.tested>0
 AND (j.token='' OR (c.closed=0 AND j.tested=c.tested AND EXISTS(SELECT 1 FROM egress_compatibility_queue p WHERE p.hash=c.hash)))
 AND NOT EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_settlements t WHERE t.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_retirements t WHERE t.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results n WHERE n.identity=c.identity AND n.held=1)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=c.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=c.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=c.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls a WHERE a.id=c.identity AND a.expires>?1)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN egress_iran_guard g ON g.identity=o.identity WHERE o.hash=c.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN config_controls a ON a.id=o.identity WHERE o.hash=c.hash AND a.expires>?1)`, egress.Now())
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
		if err = s.correctAmbiguousPreflight(tx, hash); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("PRAGMA user_version=55"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) correctAmbiguousPreflight(tx *sql.Tx, hash string) error {
	var initialReport, initialDecision, report, decision []byte
	var initialAt, tested, claimed int64
	var closed bool
	var reason string
	err := tx.QueryRow(`SELECT c.tested,c.report,c.decision,c.closed,j.tested,j.claimed_at,j.reason,j.report,j.decision
 FROM egress_compatibility_receipts c JOIN egress_jobs j ON j.hash=c.hash WHERE c.hash=?`, hash).
		Scan(&initialAt, &initialReport, &initialDecision, &closed, &tested, &claimed, &reason, &report, &decision)
	if err != nil {
		return err
	}
	var first, current egress.Report
	var prior egress.Decision
	if json.Unmarshal(initialReport, &first) != nil || !emptyCompatibilityReport(first, hash) ||
		first.Started <= 0 || first.Finished < first.Started || first.Finished > initialAt+2000 ||
		json.Unmarshal(initialDecision, &prior) != nil || !emptyCompatibilityDecision(prior) ||
		json.Unmarshal(report, &current) != nil || !egress.ValidReportShape(current, hash) {
		return nil
	}
	original := tested == initialAt && bytes.Equal(report, initialReport) && bytes.Equal(decision, initialDecision) && reason == "driver_unavailable"
	if !original {
		if current.Started <= 0 || current.Started < claimed-2000 || current.Finished < current.Started {
			return nil
		}
		// Structural tests commit their own tested clock. A failed host-side
		// retry can instead retain the initial clock and complete no test.
		structural := tested > initialAt && current.Finished <= tested+2000 && len(current.Evidence) == 0 &&
			(reason == "exact_variants_incomplete" || reason == "probe_socks_contract_missing") &&
			egress.StructuralPreflightReason(current) == "probe_socks_contract_missing"
		localFailure := tested == initialAt && !closed && unmeasuredFirstReason(current, reason) != ""
		if !structural && !localFailure {
			return nil
		}
	}
	p, ok := s.receiptPlan(hash)
	if !ok || p.Code != egress.AmbiguousVMessTransport || len(p.Variants) != 0 {
		return nil
	}
	d := egress.Evaluate(current, p, hash, tested)
	if d.State != "UNSUPPORTED" || d.Reason != egress.AmbiguousVMessTransport || d.Eligible || d.Negative {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if !original {
		if _, err = tx.Exec("INSERT OR IGNORE INTO egress_compatibility_preflight(hash,tested,report,decision) VALUES(?,?,?,?)", hash, tested, string(report), string(decision)); err != nil {
			return err
		}
	}
	// Fence any old worker before closing its source custody. First credits,
	// timestamps, observations and events retain their original attribution.
	if _, err = tx.Exec(`UPDATE egress_jobs SET state='UNSUPPORTED',reason=?,decision=?,revision=revision+1,token='',lease_until=0 WHERE hash=?`, d.Reason, string(b), hash); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE egress_compatibility_receipts SET closed=1 WHERE hash=?", hash); err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM egress_compatibility_queue WHERE hash=?", hash)
	return err
}
