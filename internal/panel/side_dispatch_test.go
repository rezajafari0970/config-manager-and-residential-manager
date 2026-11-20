package panel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSideDispatchFreshAndOldestAcrossLargeSeedAndRestart(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	src, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	seed := fixtureResult(t, s, sourceURI(37)).Items[0]
	now := time.Now()
	// Exercise the deployed migration's receipt and index paths with 1,600
	// scheduling rows. Only two fresh inputs use the normal collector path;
	// no synthetic row is treated as a service measurement.
	_, err = s.db.Exec(`WITH RECURSIVE seed(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seed WHERE n<1600)
 INSERT INTO side_receipts SELECT ?,printf('seed-%04d',n),?,'vless',?,?,?,0 FROM seed`,
		src, seed.Hash, seed.Size, now.Add(-time.Hour).UnixMilli(), now.Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct an existing v56 installation which predates the fair scheduler.
	// A second startup must never recalculate the saved boundary.
	if _, err = s.db.Exec("UPDATE side_jobs SET queued_at=?", now.Add(-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM metadata WHERE key=?", sideBootstrapKey); err != nil {
		t.Fatal(err)
	}
	if err = ensureSideDispatch(s.db); err != nil {
		t.Fatal(err)
	}
	// A recurring source response must not promote an old waiting identity.
	_, err = s.db.Exec(`INSERT INTO side_receipts VALUES(?,'seed-1600',?,'vless',?,?,?,1)`, src, seed.Hash, seed.Size, now.UnixMilli(), now.Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	fillExportSource(t, s, src, sourceURI(52), sourceURI(53))
	// These genuine post-cutover arrivals have already waited 15 minutes.
	// A rolling freshness window would have demoted both behind all 1,600 seeds.
	if _, err = s.db.Exec("UPDATE side_jobs SET queued_at=? WHERE identity NOT LIKE 'seed-%'", now.Add(-15*time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ready, err := s.SideReady(ctx); err != nil || !ready {
			t.Fatal("lost demand", err)
		}
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM metadata WHERE key=?", sideTurnKey)
	first := sideClaim(t, s)
	if strings.HasPrefix(first.Identity, "seed-") {
		t.Fatal("fresh intake behind migration cohort")
	}
	// Emulate a service restart, not just a new goroutine.
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	s.Close()
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if j := sideClaim(t, s); j.Identity != "seed-0001" {
		t.Fatal("durable FIFO turn lost", j.Identity)
	}
	if j := sideClaim(t, s); strings.HasPrefix(j.Identity, "seed-") || j.Identity == first.Identity {
		t.Fatal("new inputs starved", j.Identity)
	}
	for _, expected := range []string{"seed-0002", "seed-0003", "seed-0004"} {
		if j := sideClaim(t, s); j.Identity != expected {
			t.Fatal("lost idle-lane capacity", j.Identity, expected)
		}
	}
	// A due retry belongs to the general FIFO; a reservation does not require
	// a fresh item, and non-due retries must never produce demand.
	if _, err = s.db.Exec("UPDATE side_jobs SET next_run=? WHERE token=''", now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.SideReady(ctx); err != nil || ready {
		t.Fatal("advertised future/in-flight work", err)
	}
	if _, err = s.db.Exec("UPDATE side_jobs SET attempts=1,next_run=1 WHERE identity='seed-0111'"); err != nil {
		t.Fatal(err)
	}
	if j := sideClaim(t, s); j.Identity != "seed-0111" {
		t.Fatal("due retry was stranded")
	}
	if _, err = s.db.Exec("UPDATE side_jobs SET next_run=0 WHERE identity='seed-0112'"); err != nil {
		t.Fatal(err)
	}
	sideClaim(t, s)
	if _, err = s.db.Exec("UPDATE side_jobs SET next_run=0 WHERE identity='seed-0113'"); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.SideReady(ctx); err != nil || ready {
		t.Fatal("advertised work above eight-grant cap", err)
	}
}

func TestSideReadinessDoesNotAdvertiseExhaustedAbandonedLease(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "exhausted-side", sourceURI(71))
	j := sideClaim(t, s)
	if _, err := s.db.Exec("UPDATE side_jobs SET attempts=?,lease_until=1 WHERE identity=?", sideAttempts, j.Identity); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.SideReady(ctx); err != nil || ready {
		t.Fatal("advertised unclaimable job", err)
	}
	if err := s.Expire(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM side_jobs WHERE state='inconclusive' AND code='worker_lease_exhausted'")
}
