package panel

import (
	"context"
	"database/sql"
)

const egressHistoryRoom = `coalesce((SELECT total FROM egress_first_history_counts WHERE phase='active'),0)<32`
const egressModernFirstStreak = `coalesce((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='egress-modern-first-grants'),0)`

// Recover an interrupted active row before opening another slot. Only the
// indexed head enters normal claim ranking, irrespective of the archive size.
const egressHistoryHead = `coalesce(
 (SELECT hash FROM egress_first_history WHERE phase='active' AND ready_at<=:claim_now ORDER BY ready_at,hash LIMIT 1),
 CASE WHEN ` + egressHistoryRoom + ` THEN
 (SELECT hash FROM egress_first_history WHERE phase IN ('waiting','active') AND ready_at<=:claim_now ORDER BY ready_at,hash LIMIT 1) END)`

func admitEgressHistory(ctx context.Context, tx *sql.Tx, hash string, now int64) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE egress_first_history SET phase='active'
 WHERE hash=? AND ready_at<=? AND (phase='active' OR (phase='waiting' AND `+egressHistoryRoom+`))`, hash, now)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Under sustained new arrivals, the tenth successful discovery grant goes
// to a ready archive entry. An empty class lends all of its slots.
func recordEgressHistoryTurn(ctx context.Context, tx *sql.Tx, modern int, historic bool) error {
	next := min(9, modern+1)
	if historic {
		next = 0
	}
	if next == modern {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('egress-modern-first-grants',?)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next)
	return err
}
