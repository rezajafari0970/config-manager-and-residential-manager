package panel

import (
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// Recover only when a host-side failure prevented the experiment. A failed
// target request, incompatible core or deliberately unsupported route is still
// a real first assessment. An observation from an alternate core counts too.
func unmeasuredFirstReason(r egress.Report, reason string) string {
	if len(r.Samples)+len(r.Delivery)+len(r.Health) != 0 {
		return ""
	}
	ownPressure := r.Code == "local_resource_pressure" && r.ResourcePressure
	for _, part := range r.Evidence {
		if ownPressure && part.ResourcePressure {
			continue
		}
		if len(part.Samples)+len(part.Health)+len(part.Delivery) != 0 {
			return ""
		}
	}
	// The driver withholds the selected measurements when its own slot hit an
	// OOM. A previous incompatible core does not settle the interrupted run.
	if ownPressure {
		return r.Code
	}
	if reason == "input_unavailable" && (r.Code == "driver_unavailable" || r.Code == "input_unavailable") {
		return reason
	}
	for _, a := range r.Attempts {
		if !initialInfrastructureCode(a.Code) {
			return ""
		}
	}
	if initialInfrastructureCode(r.Code) {
		return r.Code
	}
	if r.ResourcePressure && (r.Code == "measured" || r.Code == "local_resource_pressure") {
		return "local_resource_pressure"
	}
	return ""
}

func initialInfrastructureCode(code string) bool {
	switch code {
	case "input_unavailable", "driver_session_failed", "driver_subprocess_timeout", "driver_subprocess_failed",
		"driver_infrastructure_error", "missing_runtime_asset", "core_pin_mismatch", "local_resource_pressure":
		return true
	}
	return false
}

func initialRecoveryDelay(hash string, streak int) int64 {
	return egressRetryDelay(hash, "PENDING", "unknown", false, streak, 0, true)
}

func (s *Store) migrateV50() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 50 {
		return err
	}
	var scopeColumn bool
	if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_table_info('egress_events') WHERE name='first_result_scope')").Scan(&scopeColumn); err != nil {
		return err
	}
	if !scopeColumn {
		if _, err = tx.Exec("ALTER TABLE egress_events ADD COLUMN first_result_scope TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`DROP TRIGGER IF EXISTS egress_recover_interrupted;
 INSERT OR IGNORE INTO metadata(key,value) VALUES('egress-first-results-since',CAST(CAST(unixepoch('subsec')*1000 AS INTEGER) AS TEXT));
 UPDATE egress_jobs SET state='PENDING',reason='initial_lease_recovery',next_run=0 WHERE first_completed=0 AND tested=0
 AND reason IN ('initial_lease_interrupted','initial_lease_exhausted');
 UPDATE egress_run_members SET status='pending',state='',completed_at=0 WHERE run=(SELECT max(id) FROM egress_runs)
 AND status='excluded' AND state='UNMEASURED' AND hash IN(SELECT hash FROM egress_work WHERE reason='initial_lease_recovery');`); err != nil {
		return err
	}
	// Infer historical first failures only from a sole exact leased report.
	// A later inconclusive follow-up cannot overturn an earlier measurement.
	rows, err := tx.Query(`SELECT j.hash,j.reason,j.report,j.tested,j.claimed_at FROM egress_jobs j
 WHERE j.state IN ('UNKNOWN','PENDING','UNSUPPORTED') AND j.first_completed=1 AND j.attempts=1 AND j.ever_accepted=0 AND j.tested>0 AND j.token=''
 AND j.reason IN ('input_unavailable','driver_session_failed','driver_subprocess_timeout','driver_subprocess_failed','driver_infrastructure_error','missing_runtime_asset',
 'local_resource_pressure','exact_variants_incomplete','driver_receipt_invalid','variant_binding_failed')
 AND EXISTS(SELECT 1 FROM egress_unique u WHERE u.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_settlements t WHERE t.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results n JOIN egress_unique u ON u.identity=n.identity WHERE u.hash=j.hash AND n.held=1)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v JOIN egress_unique u ON u.identity=v.identity WHERE u.hash=j.hash)`)
	if err != nil {
		return err
	}
	type failedFirst struct {
		hash, reason string
		tested       int64
	}
	var failed []failedFirst
	for rows.Next() {
		var f failedFirst
		var raw []byte
		var claimed int64
		if err := rows.Scan(&f.hash, &f.reason, &raw, &f.tested, &claimed); err != nil {
			rows.Close()
			return err
		}
		var r egress.Report
		if json.Unmarshal(raw, &r) == nil && r.Version == egress.Version && r.Hash == f.hash && claimed > 0 && r.Started >= claimed-2000 &&
			r.Finished >= r.Started && r.Finished <= f.tested+2000 {
			if f.reason = unmeasuredFirstReason(r, f.reason); f.reason != "" {
				failed = append(failed, f)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, f := range failed {
		// A representative was selected only at a committed membership. A sole
		// historical owner and unchanged job/source revisions prove a natural
		// withdrawal. Ambiguous ownership must await actual renewed membership.
		if _, err = tx.Exec(`INSERT OR IGNORE INTO egress_first_backlog(source_id,hash)
 SELECT s.id,u.hash FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
 JOIN egress_owners o ON o.hash=u.hash AND o.identity=u.identity JOIN sources s ON s.id=o.source
 WHERE j.hash=? AND j.revision=1 AND s.revision=1
 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_owners x WHERE x.hash=u.hash AND x.source!=o.source)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)`, f.hash); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE egress_jobs SET state='PENDING',reason=?,first_completed=0,tested=0,next_run=0,valid_until=0 WHERE hash=?", f.reason, f.hash); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE egress_metrics SET first_assessments=max(0,first_assessments-1),completed=max(0,completed-1) WHERE since<=?", f.tested); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE egress_run_members SET status='pending',state='',completed_at=0,duration_ms=0
 WHERE hash=? AND run=(SELECT max(id) FROM egress_runs) AND status='completed' AND completed_at=? AND settled_at=0
 AND EXISTS(SELECT 1 FROM egress_inventory i WHERE i.hash=egress_run_members.hash)`, f.hash, f.tested); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(egressDiscoveryRegistrationDDL); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=50"); err != nil {
		return err
	}
	return tx.Commit()
}
