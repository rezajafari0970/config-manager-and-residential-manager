package panel

import (
	"context"
	"database/sql"
)

// Quarantine work may be attached to an as-yet unmeasured representative.
// Its claim belongs to safety maintenance even when the old clock is zero.
const egressDiscovery = `(tested=0 AND first_completed=0 AND reason!='ads_iran_quarantined')`

// Positive values count consecutive discovery leases, negative values count
// maintenance. Two in either direction give the other queue its next chance.
// A near or missed deadline on a proven residential job can use a third
// maintenance grant. The fourth grant is reserved for any ready discovery.
// Absence is the initial state for existing and new installations.
const egressDispatchStreak = `coalesce((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='egress-dispatch-streak'),0)`

func recordEgressDispatch(ctx context.Context, tx *sql.Tx, streak int, discovery bool) error {
	next := max(-3, min(0, streak)-1)
	if discovery {
		next = min(2, max(0, streak)+1)
	}
	if next == streak {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('egress-dispatch-streak',?)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next)
	return err
}

// Give a sourced, unaccepted confirmation one maintenance opportunity after
// seven other maintenance leases. The counter saturates while there is no such
// work, survives restart, and discovery grants do not consume the opportunity.
const maxOtherMaintenance = 7
const maintenanceSinceConfirmation = `coalesce((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='egress-other-maintenance'),0)`

// next_run=0 means immediately runnable. The tested and claimed times keep
// a new import, recent observation or interrupted lease from jumping the
// waiting confirmed-failure cohort. Current safety gates and the immutable
// per-retirement grant ceiling remain authoritative.
const overdueConfirmation = `first_completed=1 AND ever_accepted=0 AND max(next_run,tested,claimed_at)<=:claim_now-600000
 AND EXISTS(SELECT 1 FROM egress_retirement_work p WHERE p.hash=egress_jobs.hash)`

func recordConfirmationDispatch(ctx context.Context, tx *sql.Tx, other int, overdue bool) error {
	next := min(maxOtherMaintenance, other+1)
	if overdue {
		next = 0
	}
	if other == next {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('egress-other-maintenance',?)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next)
	return err
}
