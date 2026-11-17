package panel

import (
	"context"
	"database/sql"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
)

// Receipts belong to exact tested bytes, not to a transient source response.
// A refreshed label/encoding may reuse a still-fresh proof, never its lifetime.
func (s *Store) migrateV44() error {
	var version int
	if e := s.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version >= 44 {
		return nil
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var hasCycle int
	if e = tx.QueryRow("SELECT count(*) FROM pragma_table_info('prepared_rotation') WHERE name='cycle'").Scan(&hasCycle); e != nil {
		return e
	}
	if hasCycle == 0 {
		if _, e = tx.Exec("ALTER TABLE prepared_rotation ADD COLUMN cycle INTEGER NOT NULL DEFAULT 0"); e != nil {
			return e
		}
	}
	_, e = tx.Exec(`CREATE TABLE IF NOT EXISTS conversion_schedule(hash TEXT PRIMARY KEY REFERENCES conversion_jobs(hash) ON DELETE CASCADE,created INTEGER NOT NULL,last_started INTEGER NOT NULL DEFAULT 0);
 INSERT OR IGNORE INTO conversion_schedule(hash,created) SELECT hash,0 FROM conversion_jobs;
 CREATE INDEX IF NOT EXISTS conversion_schedule_fifo ON conversion_schedule(created,hash);
 CREATE TABLE IF NOT EXISTS conversion_receipts(candidate_hash TEXT NOT NULL,version TEXT NOT NULL,engine TEXT NOT NULL,hash TEXT NOT NULL,candidate_size INTEGER NOT NULL,rule TEXT NOT NULL,core TEXT NOT NULL,connection TEXT NOT NULL,code TEXT NOT NULL,tested INTEGER NOT NULL,valid_until INTEGER NOT NULL,runtime_hash TEXT NOT NULL,requires_connection INTEGER NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(candidate_hash,version,engine));
 CREATE INDEX IF NOT EXISTS conversion_receipt_expiry ON conversion_receipts(valid_until);
 INSERT OR IGNORE INTO conversion_receipts SELECT r.candidate_hash,r.version,coalesce(json_extract(e.metadata,'$.engine'),'xray'),r.hash,r.candidate_size,r.rule,r.core,r.connection,r.code,r.tested,r.valid_until,r.runtime_hash,r.requires_connection,e.metadata FROM conversion_results r JOIN conversion_evidence e ON e.hash=r.hash WHERE r.core='passed' AND r.connection='passed' AND r.code='https_payload_verified' AND r.candidate_hash=r.runtime_hash AND r.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER) ORDER BY r.tested DESC;
 PRAGMA user_version=44;`)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func retainConversionReceipt(ctx context.Context, tx *sql.Tx, hash, engine string) error {
	if engine == "" {
		engine = "xray"
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO conversion_receipts SELECT r.candidate_hash,r.version,?,r.hash,r.candidate_size,r.rule,r.core,r.connection,r.code,r.tested,r.valid_until,r.runtime_hash,r.requires_connection,e.metadata FROM conversion_results r JOIN conversion_evidence e ON e.hash=r.hash WHERE r.hash=? AND r.core='passed' AND r.connection='passed' AND r.code='https_payload_verified' AND r.candidate_hash=r.runtime_hash ON CONFLICT(candidate_hash,version,engine) DO UPDATE SET hash=excluded.hash,candidate_size=excluded.candidate_size,rule=excluded.rule,core=excluded.core,connection=excluded.connection,code=excluded.code,tested=excluded.tested,valid_until=excluded.valid_until,runtime_hash=excluded.runtime_hash,requires_connection=excluded.requires_connection,metadata=excluded.metadata WHERE excluded.tested>=conversion_receipts.tested`, engine, hash)
	return e
}

func reuseConversionReceipt(ctx context.Context, tx *sql.Tx, hash, candidate, engine, rule string, now int64) error {
	if candidate == "" {
		return nil
	}
	// The caller holds the writer and has checked current membership. Leased jobs
	// and newer results must not be overwritten by a background cache hit.
	res, e := tx.ExecContext(ctx, `INSERT INTO conversion_results SELECT ?,candidate_hash,candidate_size,?,core,connection,code,tested,valid_until,runtime_hash,version,requires_connection FROM conversion_receipts c WHERE c.candidate_hash=? AND c.version=? AND c.engine=? AND c.valid_until>? AND EXISTS(SELECT 1 FROM conversion_jobs j WHERE j.hash=? AND j.token='') ON CONFLICT(hash) DO UPDATE SET candidate_hash=excluded.candidate_hash,candidate_size=excluded.candidate_size,rule=excluded.rule,core=excluded.core,connection=excluded.connection,code=excluded.code,tested=excluded.tested,valid_until=excluded.valid_until,runtime_hash=excluded.runtime_hash,version=excluded.version,requires_connection=excluded.requires_connection WHERE excluded.tested>conversion_results.tested OR excluded.version!=conversion_results.version`, hash, rule, candidate, convert.Version, engine, now, hash)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil || n == 0 {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO conversion_evidence SELECT ?,json_set(metadata,'$.raw_sha256',?,'$.rule',?,'$.reused_from_raw_sha256',hash) FROM conversion_receipts WHERE candidate_hash=? AND version=? AND engine=? ON CONFLICT(hash) DO UPDATE SET metadata=excluded.metadata`, hash, hash, rule, candidate, convert.Version, engine)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE conversion_jobs SET state='converted',version=?,failures=0,next_run=(SELECT min(valid_until,tested+(SELECT retest_seconds*1000 FROM conversion_settings WHERE id=1)) FROM conversion_results WHERE hash=?) WHERE hash=? AND token=''`, convert.Version, hash, hash)
	return e
}

// Explicit user deletion forgets unowned cached proof. Ordinary response churn
// keeps its bounded, expiring receipt; it cannot restore excluded membership.
func forgetUnownedConversionReceipts(ctx context.Context, tx *sql.Tx) error {
	_, e := tx.ExecContext(ctx, `DELETE FROM conversion_receipts WHERE candidate_hash NOT IN(SELECT candidate_hash FROM conversion_results UNION SELECT candidate_hash FROM template_preparations)`)
	return e
}
