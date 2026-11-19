package panel

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/blob"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
)

// Existing subscriptions can share an encrypted body. Sanitize each distinct
// body once and retain each source's original expiry, ownership and membership.
func (s *Store) reconcileProtocolResponses() error {
	rows, err := s.db.Query("SELECT hash,max(size) FROM responses GROUP BY hash")
	if err != nil {
		return err
	}
	var originals []blob.Ref
	for rows.Next() {
		var ref blob.Ref
		if err := rows.Scan(&ref.Hash, &ref.Size); err != nil {
			rows.Close()
			return err
		}
		originals = append(originals, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, original := range originals {
		if err := s.reconcileProtocolResponse(original); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) reconcileProtocolResponse(original blob.Ref) error {
	replacement, changed, err := collect.SanitizeResponse(context.Background(), s.vault, original)
	if err != nil {
		// Distinguish an unreadable original from a spool or storage failure.
		// A good source archive must survive an unrelated I/O error.
		r, readErr := s.vault.Open(original.Hash)
		if readErr == nil {
			_, readErr = io.Copy(io.Discard, r)
			r.Close()
		}
		var filesystemError *os.PathError
		if readErr == nil || (errors.As(readErr, &filesystemError) && !errors.Is(readErr, os.ErrNotExist)) {
			return err
		}
		// The original is missing or failed authentication. Drop only its
		// cache reference so the next fetch can replace it.
		replacement, changed = blob.Ref{}, true
	}
	if !changed {
		return nil
	}
	if replacement.Hash != "" {
		defer s.vault.Release(replacement.Hash)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE source_admission SET raw_hash=? WHERE raw_hash=? AND source_id IN (SELECT source_id FROM responses WHERE hash=?)", replacement.Hash, original.Hash, original.Hash); err != nil {
		return err
	}
	if replacement.Hash == "" {
		if _, err = tx.Exec("UPDATE sources SET etag='',modified='' WHERE id IN (SELECT source_id FROM responses WHERE hash=?)", original.Hash); err != nil {
			return err
		}
		_, err = tx.Exec("DELETE FROM responses WHERE hash=?", original.Hash)
	} else {
		_, err = tx.Exec("UPDATE responses SET hash=?,size=? WHERE hash=?", replacement.Hash, replacement.Size, original.Hash)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
