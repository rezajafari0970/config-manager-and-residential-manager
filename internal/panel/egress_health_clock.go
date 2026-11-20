package panel

import (
	"context"
	"database/sql"
)

// The route receipt and the configured maintenance period have independent
// deadlines. An early route/IR check never moves the maintenance clock.
func migrateResidentialHealthClock(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS egress_health_clock(
 hash TEXT PRIMARY KEY REFERENCES egress_jobs(hash) ON DELETE CASCADE,
 checked_at INTEGER NOT NULL, route_due INTEGER NOT NULL, grant_token TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL, general_status TEXT NOT NULL DEFAULT 'unknown') WITHOUT ROWID;
 INSERT OR IGNORE INTO egress_health_clock(hash,checked_at,route_due,status)
 SELECT j.hash,COALESCE(h.checked_at,j.tested),max(0,j.valid_until-120000),COALESCE(h.status,'unknown')
 FROM egress_jobs j LEFT JOIN egress_health h ON h.hash=j.hash WHERE j.ever_accepted=1 AND j.state!='DELETED';`)
	return err
}

func grantResidentialHealth(ctx context.Context, tx *sql.Tx, hash, token string, now int64) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE egress_health_clock SET grant_token=? WHERE hash=?
 AND checked_at+(SELECT health_minutes*60000 FROM egress_lifecycle WHERE id=1)<=?`, token, hash, now)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Grant ownership is checked against the leased token in storage. Route-only
// workers and replayed completions cannot defer scheduled diagnostics.
func recordResidentialHealth(ctx context.Context, tx *sql.Tx, hash, token, health, general string, now, routeDue, period int64) (int64, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO egress_health_clock(hash,checked_at,route_due,status,general_status)
 VALUES(?,?,?,?,?) ON CONFLICT(hash) DO UPDATE SET route_due=excluded.route_due`, hash, now, routeDue, health, general)
	if err != nil {
		return 0, err
	}
	if health != "unknown" {
		_, err = tx.ExecContext(ctx, `UPDATE egress_health_clock SET checked_at=?,status=?,general_status=?,grant_token=''
 WHERE hash=? AND grant_token=?`, now, health, general, hash, token)
		if err != nil {
			return 0, err
		}
	}
	var next int64
	err = tx.QueryRowContext(ctx, "SELECT checked_at+? FROM egress_health_clock WHERE hash=?", period, hash).Scan(&next)
	return next, err
}
