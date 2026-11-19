package panel

import (
	"context"
	"database/sql"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func (s *Store) migrateV33() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= 33 {
		return nil
	}
	_, err = tx.Exec(`
 CREATE TABLE egress_runs(id INTEGER PRIMARY KEY,started INTEGER NOT NULL);
 CREATE TABLE egress_run_members(run INTEGER NOT NULL REFERENCES egress_runs(id),hash TEXT NOT NULL,accepted INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',completed_at INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT '',definitive INTEGER NOT NULL DEFAULT 0,duration_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(run,hash));
 CREATE INDEX egress_run_pending ON egress_run_members(run,status,hash);
 CREATE TRIGGER egress_run_deleted AFTER UPDATE OF state ON egress_jobs WHEN NEW.state='DELETED' AND OLD.state!='DELETED' BEGIN
 UPDATE egress_run_members SET status='excluded',completed_at=CAST(unixepoch('subsec')*1000 AS INTEGER),state='DELETED' WHERE run=(SELECT max(id) FROM egress_runs) AND hash=NEW.hash AND status='pending';
 END;

 CREATE TRIGGER egress_excluded_alias_insert AFTER INSERT ON input_exclusions BEGIN
 UPDATE egress_jobs SET state='DELETED',reason='identity_excluded',revision=revision+1,token='',lease_until=0,valid_until=0
 WHERE state!='DELETED' AND hash!=NEW.hash AND hash IN(SELECT hash FROM egress_owners WHERE identity=NEW.identity);
 END;
 CREATE TRIGGER egress_excluded_alias_update AFTER UPDATE ON input_exclusions BEGIN
 UPDATE egress_jobs SET state='DELETED',reason='identity_excluded',revision=revision+1,token='',lease_until=0,valid_until=0
 WHERE state!='DELETED' AND hash!=NEW.hash AND hash IN(SELECT hash FROM egress_owners WHERE identity=NEW.identity);
 END;
 UPDATE egress_jobs SET state='DELETED',reason='identity_excluded',revision=revision+1,token='',lease_until=0,valid_until=0
 WHERE state!='DELETED' AND EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=egress_jobs.hash AND x.hash!=egress_jobs.hash);
 PRAGMA user_version=33;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Start the finite audit from current inputs and retained work. The cold
// archive can hold many more rows with tested=0 than the active inventory.
const egressInventoryCandidates = `SELECT u.hash FROM (SELECT DISTINCT artifact_id FROM memberships) m CROSS JOIN egress_unique u ON u.identity=m.artifact_id
 UNION SELECT u.hash FROM egress_network_review v CROSS JOIN egress_unique u ON u.identity=v.identity
 UNION SELECT hash FROM egress_first_backlog
 UNION SELECT hash FROM egress_compatibility_queue
 UNION SELECT hash FROM egress_retirement_sources
 UNION SELECT hash FROM egress_first_history INDEXED BY egress_first_history_active_due WHERE phase='active'
 UNION SELECT hash FROM egress_jobs WHERE ever_accepted=1
 UNION SELECT u.hash FROM egress_iran_guard g CROSS JOIN egress_unique u ON u.identity=g.identity WHERE g.state='QUARANTINED'`

const insertEgressRunMembers = `WITH cohort_scope(hash) AS MATERIALIZED (` + egressInventoryCandidates + `)
 INSERT INTO egress_run_members(run,hash,accepted)
 SELECT ?,j.hash,0 FROM cohort_scope c CROSS JOIN egress_jobs j ON j.hash=c.hash
 WHERE EXISTS(SELECT 1 FROM egress_work w WHERE w.hash=j.hash) AND j.first_completed=0 AND j.tested=0 AND j.ever_accepted=0 AND j.paused=0
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN input_exclusions x ON x.identity=o.identity WHERE o.hash=j.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN egress_iran_guard g ON g.identity=o.identity WHERE o.hash=j.hash AND g.state='BLOCKED')`

// ResetEgress opens a finite audit cohort over outstanding first assessments.
// Workers retain their leases and schedules. A repeated request for an active
// cohort reuses it, and a completed cohort with no new inputs remains intact.
func (s *Store) ResetEgress(ctx context.Context, revision int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE egress_settings SET generation=generation WHERE id=1"); err != nil {
		return 0, err
	}
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT coalesce(max(id),0) FROM egress_runs").Scan(&current); err != nil {
		return 0, err
	}
	if current != revision {
		return 0, ErrConflict
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM egress_run_members WHERE run=? AND status='pending')", current).Scan(&pending); err != nil || pending {
		return current, err
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO egress_runs(started) VALUES(?)", egress.Now())
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	result, err = tx.ExecContext(ctx, insertEgressRunMembers, id)
	if err != nil {
		return 0, err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 {
		return current, err
	}
	return id, tx.Commit()
}

// Called only after current lease/revision and timestamps pass validation, in
// the same writer transaction as completion and permanent Iran revocation.
func recordEgressRun(ctx context.Context, tx *sql.Tx, hash, state string, definitive bool, finished, duration int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE egress_run_members SET status='completed',completed_at=?,state=?,definitive=?,duration_ms=?
 WHERE hash=? AND status!='completed' AND run=(SELECT max(id) FROM egress_runs)
 AND EXISTS(SELECT 1 FROM egress_runs r WHERE r.id=run AND r.started<=?)`, finished, state, definitive, duration, hash, finished)
	if err != nil {
		return err
	}
	if definitive {
		_, err = tx.ExecContext(ctx, `UPDATE egress_run_members SET settled_at=?,settled_state=? WHERE hash=? AND settled_at=0 AND status='completed' AND run=(SELECT max(id) FROM egress_runs) AND EXISTS(SELECT 1 FROM egress_runs r WHERE r.id=run AND r.started<=?)`, finished, state, hash, finished)
	}
	return err
}

func egressRunState(ctx context.Context, q databaseQuery) (map[string]any, error) {
	var id, started int64
	err := q.QueryRowContext(ctx, "SELECT id,started FROM egress_runs ORDER BY id DESC LIMIT 1").Scan(&id, &started)
	if err == sql.ErrNoRows {
		return map[string]any{"id": int64(0)}, nil
	}
	if err != nil {
		return nil, err
	}
	var total, pending, completed, excluded, definitive, accepted, acceptedDone, acceptedExcluded, at600 int
	var last int64
	err = q.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(status='pending'),0),coalesce(sum(status='completed'),0),coalesce(sum(status='excluded'),0),
 coalesce(sum(status='completed' AND definitive=1),0),coalesce(sum(accepted),0),coalesce(sum(accepted=1 AND status='completed'),0),
 coalesce(sum(accepted=1 AND status='excluded'),0),coalesce(max(completed_at),0),coalesce(sum(status='completed' AND completed_at<=?),0)
 FROM egress_run_members WHERE run=?`, started+600000, id).Scan(&total, &pending, &completed, &excluded, &definitive, &accepted, &acceptedDone, &acceptedExcluded, &last, &at600)
	if err != nil {
		return nil, err
	}
	var thousand int64
	err = q.QueryRowContext(ctx, "SELECT completed_at FROM egress_run_members WHERE run=? AND status='completed' ORDER BY completed_at,hash LIMIT 1 OFFSET 999", id).Scan(&thousand)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	elapsed := max(int64(0), readStamp(ctx)-started)
	if pending == 0 {
		elapsed = max(int64(0), last-started)
	}
	var paused int
	if err = q.QueryRowContext(ctx, "SELECT count(*) FROM egress_run_members m JOIN egress_jobs j ON j.hash=m.hash WHERE m.run=? AND m.status='pending' AND j.paused!=0", id).Scan(&paused); err != nil {
		return nil, err
	}

	var twoThousand, defThousand, defTwoThousand int64
	for _, measure := range []struct {
		offset    int
		clock     string
		predicate string
		dest      *int64
	}{{1999, "completed_at", "", &twoThousand}, {999, "settled_at", " AND settled_at>0", &defThousand}, {1999, "settled_at", " AND settled_at>0", &defTwoThousand}} {
		err = q.QueryRowContext(ctx, "SELECT "+measure.clock+" FROM egress_run_members WHERE run=? AND status='completed'"+measure.predicate+" ORDER BY "+measure.clock+",hash LIMIT 1 OFFSET ?", id, measure.offset).Scan(measure.dest)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}
	var at900, def600, def900, settled int
	if err = q.QueryRowContext(ctx, "SELECT coalesce(sum(completed_at<=?),0),coalesce(sum(settled_at>0 AND settled_at<=?),0),coalesce(sum(settled_at>0 AND settled_at<=?),0),coalesce(sum(settled_at>0),0) FROM egress_run_members WHERE run=? AND status='completed'", started+900000, started+600000, started+900000, id).Scan(&at900, &def600, &def900, &settled); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "started": started, "total": total, "pending": pending, "completed": completed, "excluded": excluded, "definitive": definitive, "settled": settled,
		"accepted": accepted, "accepted_completed": acceptedDone, "accepted_excluded": acceptedExcluded, "paused_pending": paused,
		"elapsed_ms": elapsed, "first_1000_ms": max(int64(0), thousand-started), "assessed_at_600s": at600,
		"first_2000_ms": max(int64(0), twoThousand-started), "first_1000_definitive_ms": max(int64(0), defThousand-started), "first_2000_definitive_ms": max(int64(0), defTwoThousand-started), "assessed_at_900s": at900, "definitive_at_600s": def600, "definitive_at_900s": def900, "target_900s_met": twoThousand > 0 && twoThousand-started <= 900000, "definitive_target_600s_met": defThousand > 0 && defThousand-started <= 600000, "definitive_target_900s_met": defTwoThousand > 0 && defTwoThousand-started <= 900000,
		"target_600s_met": thousand > 0 && thousand-started <= 600000, "finished": pending == 0, "unit": "collector_identity"}, nil
}
