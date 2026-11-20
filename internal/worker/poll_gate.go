package worker

import (
	"context"
	"sync"
	"time"
)

// PollGate coalesces empty queue checks across slots. It is only an admission
// hint: it never caches jobs, evidence, leases or publication eligibility.
// Use a separate gate for each independently scheduled queue/lane.
type PollGate struct {
	mu   sync.Mutex
	busy bool
	next time.Time
	done chan struct{}
}

func (g *PollGate) Begin(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy || now.Before(g.next) {
		return false
	}
	g.busy = true
	g.done = make(chan struct{})
	return true
}

// Wait hands a successful claim straight to the next waiting slot. Contending
// slots wait for the in-progress RPC instead of sleeping a whole polling tick;
// only an actually empty/error response starts the shared idle delay.
func (g *PollGate) Wait(ctx context.Context) bool {
	for ctx.Err() == nil {
		g.mu.Lock()
		if time.Now().Before(g.next) {
			g.mu.Unlock()
			return false
		}
		if !g.busy {
			g.busy = true
			g.done = make(chan struct{})
			g.mu.Unlock()
			return true
		}
		done := g.done
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-done:
		}
	}
	return false
}

func (g *PollGate) Finish(now time.Time, hasWork bool) {
	var idle time.Duration
	if !hasWork {
		idle = time.Second
	}
	g.FinishAfter(now, idle)
}

// Resource contention is not evidence that the queue is empty. Keep the
// shared gate bounded while allowing a newly released permit to start work.
func (g *PollGate) FinishAfter(now time.Time, idle time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy {
		close(g.done)
	}
	g.busy = false
	g.next = time.Time{}
	if idle > 0 {
		g.next = now.Add(idle)
	}
}
