package panel

import (
	"strings"
)

// Require fresh payload qualification and new output bytes without changing raw
// records, ordinary candidate versions, Ads classifier proofs or user settings.
func (s *Store) migrateV26() error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var version int
	if e = tx.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version >= 26 {
		return nil
	}
	rows, e := tx.Query("SELECT name,sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL")
	if e != nil {
		return e
	}
	type view struct{ name, q string }
	views := []view{}
	for rows.Next() {
		var v view
		if e = rows.Scan(&v.name, &v.q); e != nil {
			rows.Close()
			return e
		}
		views = append(views, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	replace := strings.NewReplacer("https_multi_site_verified", "https_payload_verified")
	for _, v := range views {
		q := replace.Replace(v.q)
		if q != v.q {
			if _, e = tx.Exec("DROP VIEW " + v.name + ";" + q); e != nil {
				return e
			}
		}
	}
	// Old short-request receipts are retained for diagnostics, never promoted.
	if _, e = tx.Exec("UPDATE conversion_jobs SET token='',lease_until=0,state='queued',next_run=0 WHERE token!='' OR hash IN(SELECT hash FROM conversion_inputs)"); e != nil {
		return e
	}
	if _, e = tx.Exec("PRAGMA user_version=26"); e != nil {
		return e
	}
	return tx.Commit()
}
