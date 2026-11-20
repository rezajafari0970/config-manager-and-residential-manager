package panel

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

const sideBootstrapKey = "side-first-snapshot-clock"
const sideTurnKey = "side-last-fresh-grant"
const sideDue = "next_run<=?1 AND lease_until<=?1 AND attempts<?2"

func sideReadyAt(ctx context.Context, q readQuerier, now int64) (bool, error) {
	var ready bool
	err := q.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM side_jobs WHERE token!='' AND lease_until>?1)<?3
 AND EXISTS(SELECT 1 FROM side_work WHERE `+sideDue+`)`, now, sideAttempts, side.MaxWorkers).Scan(&ready)
	return ready, err
}

// Workers advertise demand before requesting a shared sandbox slot. This read
// never consumes a turn, acquires a writer or changes the job's lease.
func (s *Store) SideReady(ctx context.Context) (bool, error) {
	return sideReadyAt(ctx, s.workerReader(), time.Now().UnixMilli())
}

// Bootstrap admission is one INSERT ... SELECT statement and SQLite freezes
// its 'now' clock for that entire statement. Record that cohort once on upgrade.
// An empty initial snapshot has boundary zero so the first later source input
// receives an arrival turn as well. Never recompute from a changing queue.
func ensureSideDispatch(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("CREATE INDEX IF NOT EXISTS side_source_first ON side_jobs(queued_at,identity) WHERE state='pending' AND attempts=0"); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO metadata(key,value)
 SELECT ?1,coalesce((SELECT min(queued_at) FROM side_jobs),0) WHERE NOT EXISTS(SELECT 1 FROM metadata WHERE key=?1)
 ON CONFLICT(key) DO NOTHING`, sideBootstrapKey); err != nil {
		return err
	}
	return tx.Commit()
}

const sideCandidateColumns = "SELECT identity,raw_hash,kind,size FROM side_work WHERE " + sideDue
const sideSourceCandidate = sideCandidateColumns + " AND attempts=0 AND code!='side_profile_completion' AND queued_at>?3 ORDER BY queued_at,identity LIMIT 1"
const sideBacklogCandidate = sideCandidateColumns + " AND (attempts>0 OR code='side_profile_completion' OR queued_at<=?3) ORDER BY next_run,admitted,identity LIMIT 1"

// Alternate between genuinely new source admissions and the initial snapshot
// plus retries. Waiting through an outage cannot move a source first behind
// the initial snapshot. Each side lends all unused turns to the other.
func selectSideGrant(ctx context.Context, tx *sql.Tx, now int64) (*SideJob, int64, bool, error) {
	var lastSource bool
	var boundary int64
	if err := tx.QueryRowContext(ctx, `SELECT coalesce((SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?1),0),
 (SELECT CAST(value AS INTEGER) FROM metadata WHERE key=?2)`, sideTurnKey, sideBootstrapKey).Scan(&lastSource, &boundary); err != nil {
		return nil, 0, false, err
	}
	for _, source := range []bool{!lastSource, lastSource} {
		q := sideBacklogCandidate
		if source {
			q = sideSourceCandidate
		}
		var j SideJob
		var size int64
		err := tx.QueryRowContext(ctx, q, now, sideAttempts, boundary).Scan(&j.Identity, &j.Hash, &j.Kind, &size)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, 0, false, err
		}
		return &j, size, source, nil
	}
	return nil, 0, false, nil
}

// The final interrupted attempt has no work remaining. Settle it during the
// normal sweeper even if no worker advertises network demand afterwards.
func settleSideLeases(ctx context.Context, tx *sql.Tx, now int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE side_jobs SET state='inconclusive',code='worker_lease_exhausted',finished=?,lease_until=0,token=''
 WHERE state='pending' AND lease_until<=? AND attempts>=?`, now, now, sideAttempts)
	return err
}
