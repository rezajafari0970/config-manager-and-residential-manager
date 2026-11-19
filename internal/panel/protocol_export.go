package panel

import "io"

// Steady-state exports use the vault directly. Recheck only an immutable blob
// that was unavailable during the startup inventory, before serving its bytes.
func (s *Store) openExportBlob(hash string) (io.ReadCloser, error) {
	if kind, unknown := s.unknownProtocolHashes.Load(hash); unknown {
		blocked, err := s.inspectProtocolBlob(hash, kind.(string))
		if err != nil {
			return nil, err
		}
		if blocked {
			s.retireDisabledProtocolHash(hash)
			return nil, ErrNotFound
		}
		s.unknownProtocolHashes.Delete(hash)
	}
	return s.vault.Open(hash)
}
