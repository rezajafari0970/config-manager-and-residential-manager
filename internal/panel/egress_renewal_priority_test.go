package panel

import (
	"context"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestExpiredProofTurnSurvivesContinuousFreshUnacceptedFailures(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var raw []string
	for i := 0; i < 12; i++ {
		raw = append(raw, sourceURI(181+i))
	}
	newExportSource(t, s, "competing-first-failures", raw...)
	var expired string
	for i := range raw {
		j, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || j == nil {
			t.Fatal("first grant", err)
		}
		r := badDelivery(*j)
		if i == 0 {
			expired = j.Hash
			r = syntheticEgress(*j)
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE ever_accepted=0"); err != nil {
		t.Fatal(err)
	}
	// Start with an all-maintenance sequence. The source has no untested inputs.
	if j, err := s.ClaimEgressLane(ctx, "followup"); err != nil || j != nil {
		t.Fatal("settled failures entered maintenance", err)
	}
	now := egress.Now()
	if _, err := s.db.Exec("UPDATE egress_jobs SET valid_until=?,next_run=? WHERE hash=?", now-60000, now-180000, expired); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || j == nil || j.Hash != expired {
		t.Fatal("due renewal", err)
	}
	pendingCount(t, s.db, len(raw), "SELECT first_assessments FROM egress_metrics")
}

func TestExpiredProofTurnKeepsAcceptedSafetyAndCountryGuard(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "mixed-confirmations", sourceURI(193), sourceURI(194), sourceURI(195), sourceURI(196), sourceURI(197), sourceURI(198))
	var hashes []string
	for i := 0; i < 6; i++ {
		j, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || j == nil {
			t.Fatal(err)
		}
		hashes = append(hashes, j.Hash)
		r := syntheticEgress(*j)
		switch i {
		case 0:
			r = badDelivery(*j)
		case 1:
			r = iranFixture(*j)
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	guard, safety, expired, unproved, backoff := hashes[1], hashes[2], hashes[3], hashes[4], hashes[5]
	now := egress.Now()
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=CASE WHEN hash=? THEN 0 ELSE ? END", safety, now+3600000); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || j == nil || j.Hash != safety {
		t.Fatal("accepted follow-up", err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE egress_jobs SET next_run=CASE WHEN hash=?1 THEN ?2 ELSE 0 END;
 UPDATE egress_jobs SET valid_until=?3 WHERE hash IN(?1,?4,?5);
 DELETE FROM egress_residential_history WHERE hash=?5;
 UPDATE metadata SET value='-3' WHERE key='egress-dispatch-streak'`, backoff, now+300000, now-1000, expired, unproved); err != nil {
		t.Fatal(err)
	}
	// Inspect successive reserved opportunities as earlier winners are leased.
	// A zero history or future backoff is insufficient for promotion.
	for n, want := range []string{guard, safety, expired, unproved} {
		s.renewalTurn.Store(2)
		j, err = s.ClaimEgressLane(ctx, "followup")
		if err != nil || j == nil || j.Hash != want {
			t.Fatal("wrong reserved turn", n, err)
		}
	}
}
