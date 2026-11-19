package panel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestOrdinaryTemporaryFailureKeepsFirstLaneOverReturningAssessment(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	returned, fresh := sourceURI(41), sourceURI(42)
	id, _ := newExportSource(t, s, "returning", returned)
	commitProbeInputs(t, s, id, returned, fresh)
	j, err := s.ClaimProbe(ctx)
	if err != nil || j == nil || j.Hash != repair.Digest([]byte(fresh)) {
		t.Fatal("missing first attempt", err)
	}
	interrupted := conversionResult(*j, 0, true)
	interrupted.Core, interrupted.Connection, interrupted.Code = "blocked", "not_run", "probe_infrastructure_error"
	interrupted.Candidate = nil
	if err = s.CompleteProbe(ctx, interrupted); err != nil {
		t.Fatal(err)
	}
	// Reintroducing previously assessed bytes can recreate a job whose
	// scheduling clocks start at zero. A worker outage advances both clocks
	// for the outstanding first, although no assessment has been recorded.
	if _, err = s.db.Exec("UPDATE conversion_jobs SET next_run=CASE WHEN hash=? THEN 0 ELSE ? END", repair.Digest([]byte(returned)), time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	j, err = s.ClaimProbe(ctx)
	if err != nil || j == nil || j.Hash != repair.Digest([]byte(fresh)) {
		t.Fatal("a renewal displaced the unmeasured first", err)
	}
}

func TestOrdinaryCommittedTurnsSurviveRestarts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raws := []string{sourceURI(81), sourceURI(82)}
	id, _ := newExportSource(t, s, "two-renewals", raws...)
	renewals := map[string]bool{repair.Digest([]byte(raws[0])): true, repair.Digest([]byte(raws[1])): true}
	for i := 83; i < 90; i++ {
		raws = append(raws, sourceURI(i))
	}
	commitProbeInputs(t, s, id, raws...)
	if _, err := s.db.Exec("UPDATE conversion_jobs SET next_run=0; DELETE FROM metadata WHERE key='conversion-first-grants'"); err != nil {
		t.Fatal(err)
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	for grant := 1; grant <= 5; grant++ {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		s, err = Open(path, key)
		if err != nil {
			t.Fatal(err)
		}
		j, err := s.ClaimProbe(ctx)
		if err != nil || j == nil || renewals[j.Hash] != (grant == 4) {
			t.Fatalf("unexpected ordinary work class on grant %d: %v", grant, err)
		}
		if err = s.CompleteProbe(ctx, conversionResult(*j, 0, true)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
