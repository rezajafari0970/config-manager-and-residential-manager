package panel

import (
	"io"
	"sync"
)

// Cache positive decisions only. A new, evicted, or previously unavailable
// immutable blob must pass the current protocol policy before anyone reads it.
type protocolHashCache struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
	order   []string
	next    int
}

func (c *protocolHashCache) contains(hash string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.allowed[hash]
	return ok
}

func (c *protocolHashCache) add(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.allowed[hash]; known {
		return
	}
	if c.allowed == nil {
		c.allowed = make(map[string]struct{})
	}
	const capacity = 8192
	if len(c.order) < capacity {
		c.order = append(c.order, hash)
	} else {
		delete(c.allowed, c.order[c.next])
		c.order[c.next] = hash
		c.next = (c.next + 1) % capacity
	}
	c.allowed[hash] = struct{}{}
}

func (s *Store) openExportBlob(hash string) (io.ReadCloser, error) {
	if !s.allowedProtocols.contains(hash) {
		blocked, err := s.inspectProtocolBlob(hash)
		if err != nil {
			return nil, err
		}
		if blocked {
			s.retireDisabledProtocolHash(hash)
			return nil, ErrNotFound
		}
		s.allowedProtocols.add(hash)
	}
	return s.vault.Open(hash)
}
