package panel

import (
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
)

// Persisted SQL views carry the admission version. Changing Go constants alone
// leaves installed databases accepting old evidence and rejecting fresh results.
func (s *Store) migrateV19() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= 19 {
		return nil
	}
	// Fence old leases and wake validation without changing source settings,
	// immutable blobs, counters, rotation queues or the external deletion journal.
	if _, err = tx.Exec("UPDATE conversion_jobs SET token='',lease_until=0,state='queued',next_run=0 WHERE version!=?", convert.Version); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=19"); err != nil {
		return err
	}
	return tx.Commit()
}
