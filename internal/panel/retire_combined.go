package panel

import "strings"

// migrateV41 removes retired feature storage without changing ordinary sources,
// conversion receipts, Residential evidence, rotations or the revocation ledger.
func (s *Store) migrateV41() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= 41 {
		return nil
	}
	rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='view' AND (name GLOB 'smart_*' OR name GLOB 'splash_smart_*' OR name GLOB 'ads_smart_*')")
	if err != nil {
		return err
	}
	var views []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		views = append(views, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	quote := func(v string) string { return `"` + strings.ReplaceAll(v, `"`, `""`) + `"` }
	for _, name := range views {
		if _, err = tx.Exec("DROP VIEW " + quote(name)); err != nil {
			return err
		}
	}
	for _, prefix := range []string{"smart_", "splash_smart_", "ads_smart_"} {
		for _, suffix := range []string{"cache_members", "rotation_queue", "members", "evidence", "cache", "usage", "source_usage", "rotation_state", "worker", "settings", "heads"} {
			if _, err = tx.Exec("DROP TABLE IF EXISTS " + quote(prefix+suffix)); err != nil {
				return err
			}
		}
	}
	for _, column := range []string{"smart_excluded", "splash"} {
		var exists int
		if err = tx.QueryRow("SELECT count(*) FROM pragma_table_info('sources') WHERE name=?", column).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			if _, err = tx.Exec("DROP INDEX IF EXISTS " + quote("sources_"+column) + ";ALTER TABLE sources DROP COLUMN " + quote(column)); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec("PRAGMA user_version=41"); err != nil {
		return err
	}
	return tx.Commit()
}
