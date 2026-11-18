package panel

// One-way retirement of the former DNS-family feature. Keep the underlying
// provider evidence, source ownership, raw blobs and exact-byte health proofs.
func (s *Store) removeRetiredIPFamilies() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE network_classifications SET evidence=json_extract(evidence,'$.addresses')
WHERE json_type(evidence)='object' AND json_extract(evidence,'$.version')=1
AND json_type(evidence,'$.addresses')='array' AND json_type(evidence,'$.ip_family')='object';
DELETE FROM network_rotation_state WHERE scope GLOB 'ip-family/*';
DELETE FROM prepared_rotation WHERE scope GLOB '*/ip-family/*';`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
