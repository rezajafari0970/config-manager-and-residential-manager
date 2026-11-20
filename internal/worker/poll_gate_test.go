package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollGateCoalescesEmptyChecksAndImmediatelyDrainsWork(t *testing.T) {
	var g PollGate
	now := time.Unix(100, 0)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 31; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Begin(now) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("concurrent database polls", wins.Load())
	}
	g.Finish(now, false)
	if g.Begin(now.Add(999 * time.Millisecond)) {
		t.Fatal("hot empty poll")
	}
	if !g.Begin(now.Add(time.Second)) {
		t.Fatal("empty hint did not expire")
	}
	g.Finish(now.Add(time.Second), true)
	if !g.Begin(now.Add(time.Second)) {
		t.Fatal("useful work delayed")
	}
}

func TestPollWaitDrainsSuccessAndCancelsBlockedWaiter(t *testing.T) {
	var g PollGate
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !g.Wait(ctx) {
		t.Fatal("first claim blocked")
	}
	blocked := make(chan bool, 1)
	go func() { blocked <- g.Wait(ctx) }()
	g.Finish(time.Now(), true)
	select {
	case ok := <-blocked:
		if !ok {
			t.Fatal("useful claim slept")
		}
	case <-time.After(time.Second):
		t.Fatal("handoff stalled")
	}
	go func() { blocked <- g.Wait(ctx) }()
	cancel()
	select {
	case ok := <-blocked:
		if ok {
			t.Fatal("cancelled request admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
	g.Finish(time.Now(), false)
}

func TestResourceContentionRetriesBeforeAnEmptyQueue(t *testing.T) {
	var gate PollGate
	now := time.Now()
	if !gate.Begin(now) {
		t.Fatal("fresh poll was rejected")
	}
	gate.FinishAfter(now, 150*time.Millisecond)
	if gate.Begin(now.Add(149*time.Millisecond)) || !gate.Begin(now.Add(150*time.Millisecond)) {
		t.Fatal("resource poll interval")
	}
	gate.Finish(now, false)
	if gate.Begin(now.Add(999 * time.Millisecond)) {
		t.Fatal("empty queue was hot-polled")
	}
}
