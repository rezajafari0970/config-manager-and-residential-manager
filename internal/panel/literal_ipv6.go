package panel

import (
	"context"
	"io"
	"sync"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

type literalIPv6Cache struct {
	mu     sync.Mutex
	values map[string]bool
}

// Raw hashes are immutable. Cache just the local syntax predicate, never probe
// results. Failed reads are not cached; a restored blob can be read next time.
func (s *Store) hasLiteralIPv6(ctx context.Context, hash string) bool {
	s.literalIPv6.mu.Lock()
	value, ok := s.literalIPv6.values[hash]
	s.literalIPv6.mu.Unlock()
	if ok || ctx.Err() != nil {
		return value
	}
	body, err := s.openExportBlob(hash)
	if err != nil {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
	body.Close()
	if err != nil || len(b) > repair.MaxBytes || repair.Digest(b) != hash {
		return false
	}
	value = networkclass.LiteralIPv6(b)
	s.literalIPv6.mu.Lock()
	if s.literalIPv6.values == nil || len(s.literalIPv6.values) >= 8192 {
		s.literalIPv6.values = make(map[string]bool)
	}
	s.literalIPv6.values[hash] = value
	s.literalIPv6.mu.Unlock()
	return value
}
