package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestExpiredFirstLeaseRotatesBehindWaitingPeersAfterRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, b := sourceURI(1560), sourceURI(1561)
	oldest, waiting := egress.Hash([]byte(a)), egress.Hash([]byte(b))
	newExportSource(t, s, "interrupted-fifo", a, b)
	if _, err := s.db.Exec("UPDATE egress_unique SET created=CASE hash WHEN ? THEN 100 ELSE 200 END", oldest); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || first == nil || first.Hash != oldest {
		t.Fatal("first grant", err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", oldest); err != nil {
		t.Fatal(err)
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || next == nil || next.Hash != waiting {
		t.Fatal("expired lease displaced an untouched peer", err)
	}
	recovery, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || recovery == nil || recovery.Hash != oldest || recovery.Token == first.Token {
		t.Fatal("interrupted work did not recover", err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *first, Report: syntheticEgress(*first)}); err != ErrConflict {
		t.Fatal("expired worker was allowed to commit", err)
	}
	for _, job := range []*egress.Job{next, recovery} {
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
			t.Fatal(err)
		}
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_jobs WHERE first_completed=1")
	pendingCount(t, s.db, 2, "SELECT first_assessments FROM egress_metrics")
}

func TestStaleRetirementHoldsYieldToDueRenewal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "retirement-priority", sourceURI(1562), sourceURI(1563), sourceURI(1564))
	var hashes []string
	for range 3 {
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil {
			t.Fatal("first grant", err)
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, job.Hash)
	}
	now := egress.Now()
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0,valid_until=CASE hash WHEN ? THEN ? ELSE 0 END", hashes[2], now+30000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO egress_retirements(hash,reason,hits,at,first_at) VALUES
 (?, 'confirmed_ads_route_lost',0,0,0),(?, 'confirmed_ads_route_lost',1,?,?)`, hashes[0], hashes[1], now-660000, now-660000); err != nil {
		t.Fatal(err)
	}
	next, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || next == nil || next.Hash != hashes[2] {
		t.Fatal("stale retirement hold displaced a due renewal", err)
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_retirements")
	seen := map[string]bool{next.Hash: true}
	for range 2 {
		next, err = s.ClaimEgressLane(ctx, "followup")
		if err != nil || next == nil || seen[next.Hash] {
			t.Fatal("retained route lost ordinary maintenance", err)
		}
		seen[next.Hash] = true
	}
}
