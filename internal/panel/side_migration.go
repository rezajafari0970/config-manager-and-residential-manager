package panel

// Freeze old first-test custody and establish the new ledgers together so no
// worker can issue a lease against only half of the new eligibility policy.
func (s *Store) migrateV56() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 56 {
		return err
	}
	if err := migrateFreshResidential(tx); err != nil {
		return err
	}
	if err := migrateResidentialHealthClock(tx); err != nil {
		return err
	}
	if err := migrateSide(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS side_worker (
		id INTEGER PRIMARY KEY CHECK(id=1), status TEXT NOT NULL DEFAULT 'waiting',
		code TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
		active INTEGER NOT NULL DEFAULT 0, heartbeat INTEGER NOT NULL DEFAULT 0);
		INSERT OR IGNORE INTO side_worker(id) VALUES(1);
		PRAGMA user_version=56`); err != nil {
		return err
	}
	return tx.Commit()
}
