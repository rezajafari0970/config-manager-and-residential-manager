package panel

import (
	"context"
	"database/sql"
)

// The identity clock carries only scheduling history. Raw eligibility, leases,
// receipts and publication continue to come from the ordinary input views.
const createOrdinaryClock = `
 CREATE TABLE IF NOT EXISTS conversion_first_clock(
 identity TEXT PRIMARY KEY,admitted INTEGER NOT NULL,last_started INTEGER NOT NULL DEFAULT 0,
 retry_at INTEGER NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,version TEXT NOT NULL DEFAULT ''
 ) WITHOUT ROWID;
 CREATE VIEW IF NOT EXISTS conversion_first_raw_clock AS
 SELECT o.hash,c.* FROM egress_owners o JOIN conversion_first_clock c ON c.identity=o.identity;
 CREATE TRIGGER IF NOT EXISTS conversion_first_clock_assessed AFTER INSERT ON conversion_first_assessed BEGIN
 DELETE FROM conversion_first_clock WHERE identity=NEW.identity; END;
 CREATE TRIGGER IF NOT EXISTS conversion_first_clock_pin AFTER INSERT ON conversion_first_backlog BEGIN
 INSERT OR IGNORE INTO conversion_first_clock(identity,admitted)
 SELECT NEW.identity,CAST(unixepoch('subsec')*1000 AS INTEGER)
 WHERE NOT EXISTS(SELECT 1 FROM conversion_first_assessed a WHERE a.identity=NEW.identity); END;`

// Project the identity's place in line onto the exact raw row that the existing
// indexed FIFO understands. This only runs when a representative is created,
// migrated, or leased. Queue polling needs no additional identity-wide join.
const ordinaryClockSchedule = `UPDATE conversion_schedule SET (created,last_started)=(
 SELECT min(c.admitted),max(c.last_started) FROM conversion_first_raw_clock c WHERE c.hash=conversion_schedule.hash)
 WHERE EXISTS(SELECT 1 FROM conversion_first_raw_clock c WHERE c.hash=conversion_schedule.hash)`

const ordinaryClockRetry = `UPDATE conversion_jobs SET (next_run,failures,version)=(
 SELECT max(conversion_jobs.next_run,c.retry_at),max(conversion_jobs.failures,c.failures),c.version
 FROM conversion_first_raw_clock c WHERE c.hash=conversion_jobs.hash AND c.failures>0
 ORDER BY c.retry_at DESC,c.identity LIMIT 1)
 WHERE token='' AND EXISTS(SELECT 1 FROM conversion_first_raw_clock c WHERE c.hash=conversion_jobs.hash AND c.failures>0)`

const registerOrdinaryClock = `CREATE TRIGGER IF NOT EXISTS conversion_first_clock_schedule AFTER INSERT ON conversion_schedule BEGIN
 INSERT OR IGNORE INTO conversion_first_clock(identity,admitted,last_started)
 SELECT o.identity,coalesce(nullif(NEW.created,0),CAST(unixepoch('subsec')*1000 AS INTEGER)),NEW.last_started
 FROM egress_owners o WHERE o.hash=NEW.hash AND NOT EXISTS(SELECT 1 FROM conversion_first_assessed a WHERE a.identity=o.identity);
 ` + ordinaryClockSchedule + ` AND hash=NEW.hash;
 ` + ordinaryClockRetry + ` AND hash=NEW.hash; END;`

func (s *Store) migrateV53() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 53 {
		return err
	}
	// A Residential admission date cannot establish the age of an ordinary
	// test. Only existing ordinary inputs and saved first owners seed clocks.
	// For those identities find the oldest surviving ordinary raw schedule and
	// the latest attempted grant. A pin with no schedule starts now.
	_, err = tx.Exec(createOrdinaryClock + `
 WITH authority(identity) AS MATERIALIZED (
 SELECT identity FROM conversion_first_backlog UNION
 SELECT o.identity FROM (SELECT DISTINCT hash FROM conversion_work_inputs) i CROSS JOIN egress_owners o ON o.hash=i.hash
 ), samples AS (
 SELECT a.identity,f.created,f.last_started,j.next_run,j.failures,j.version,
 row_number() OVER (PARTITION BY a.identity ORDER BY CASE WHEN j.failures>0 THEN j.next_run ELSE 0 END DESC,o.hash) AS retry
 FROM authority a LEFT JOIN egress_owners o ON o.identity=a.identity LEFT JOIN conversion_schedule f ON f.hash=o.hash
 LEFT JOIN conversion_jobs j ON j.hash=f.hash
 WHERE NOT EXISTS(SELECT 1 FROM conversion_first_assessed done WHERE done.identity=a.identity))
 INSERT OR IGNORE INTO conversion_first_clock(identity,admitted,last_started,retry_at,failures,version)
 SELECT identity,coalesce(min(nullif(created,0)),CAST(unixepoch('subsec')*1000 AS INTEGER)),coalesce(max(last_started),0),
 max(CASE WHEN retry=1 AND failures>0 THEN next_run ELSE 0 END),
 max(CASE WHEN retry=1 AND failures>0 THEN failures ELSE 0 END),
 max(CASE WHEN retry=1 AND failures>0 THEN version ELSE '' END)
 FROM samples GROUP BY identity;
 ` + ordinaryClockSchedule + `; ` + ordinaryClockRetry + `; ` + registerOrdinaryClock + ` PRAGMA user_version=53;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

const ordinaryClockIdentities = `SELECT identity FROM egress_owners WHERE hash=?`
const ordinaryClockAliases = `SELECT a.hash FROM egress_owners a WHERE a.identity IN (` + ordinaryClockIdentities + `)`

func startOrdinaryClock(ctx context.Context, tx *sql.Tx, hash string, now int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE conversion_first_clock SET last_started=? WHERE identity IN (`+ordinaryClockIdentities+`)`, now, hash); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE conversion_schedule SET last_started=? WHERE hash IN (`+ordinaryClockAliases+`)`, now, hash)
	return err
}

func deferOrdinaryClock(ctx context.Context, tx *sql.Tx, hash, version string, retry int64, failures int) error {
	// A measured result has already cleared the clock via its receipt trigger.
	res, err := tx.ExecContext(ctx, `UPDATE conversion_first_clock SET retry_at=?,failures=?,version=? WHERE identity IN (`+ordinaryClockIdentities+`)`, retry, failures, version, hash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	_, err = tx.ExecContext(ctx, ordinaryClockRetry+` AND hash!=? AND hash IN (`+ordinaryClockAliases+`)`, hash, hash)
	return err
}

// Administrative removal ends a waiting identity's ordinary admission when
// its last current owner, saved withdrawal or retained eligible raw is gone.
func forgetUnownedOrdinaryClocks(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM conversion_first_clock
 WHERE NOT EXISTS(SELECT 1 FROM conversion_first_backlog b WHERE b.identity=conversion_first_clock.identity)
 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=conversion_first_clock.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_owners o JOIN conversion_jobs j ON j.hash=o.hash WHERE o.identity=conversion_first_clock.identity)`)
	return err
}
