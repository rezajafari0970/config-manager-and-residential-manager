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
