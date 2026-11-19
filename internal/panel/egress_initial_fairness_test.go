package panel

import (
	"context"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// A completed datacenter result stays cached even after its proof expires.
func TestEgressHeldExpiryDoesNotDisplaceUntested(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "held", sourceURI(890))
	held, err := s.ClaimEgress(ctx)
	if err != nil || held == nil {
		t.Fatal(err)
	}
	r := syntheticEgress(*held)
	for i := range r.Samples {
		sample := &r.Samples[i]
		if sample.ActualAds {
			sample.Network.Kind, sample.Network.Provider, sample.Network.ASN = "hosting", "vultr", 20473
		}
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *held, Report: r}); err != nil {
		t.Fatal(err)
	}
	newExportSource(t, s, "fresh", sourceURI(891))
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0,valid_until=? WHERE hash=?", egress.Now()+60000, held.Hash); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || fresh == nil || fresh.Hash == held.Hash {
		t.Fatal("held expiry displaced fresh input", err)
	}
	ordinary, err := s.ClaimEgressLane(ctx, "followup")
	if err != nil || ordinary != nil {
		t.Fatal("held datacenter result re-entered the queue", ordinary, err)
	}
}

func TestEgressInitialTurnReservesFirstAssessmentUnderContinuousExpiry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "pressure", sourceURI(892), sourceURI(893), sourceURI(894), sourceURI(895), sourceURI(896))
	var fresh string
	if err := s.db.QueryRow("SELECT hash FROM egress_unique ORDER BY hash DESC LIMIT 1").Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	now := egress.Now()
	if _, err := s.db.Exec("UPDATE egress_jobs SET ever_accepted=1,first_completed=1,tested=?,valid_until=?,next_run=1 WHERE hash!=?", now, now+60000, fresh); err != nil {
		t.Fatal(err)
	}
	for turn := 1; turn <= 3; turn++ {
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil || (job.Hash == fresh) != (turn == 3) {
			t.Fatalf("turn %d fresh=%t err=%v", turn, job != nil && job.Hash == fresh, err)
		}
	}
}

func TestEgressReservedInitialTurnHonorsSafety(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "guard-before-initial", sourceURI(897), sourceURI(898), sourceURI(899))
	var iran, retirement string
	if err := s.db.QueryRow("SELECT min(hash),max(hash) FROM egress_unique").Scan(&iran, &retirement); err != nil {
		t.Fatal(err)
	}
	now := egress.Now()
	if _, err := s.db.Exec("UPDATE egress_jobs SET state='QUARANTINED',tested=?,first_completed=1,ever_accepted=1,next_run=0 WHERE hash IN(?,?)", now, iran, retirement); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET reason='ads_iran_quarantined' WHERE hash=?", iran); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO egress_retirements(hash,reason,hits,at) VALUES(?,'confirmed_ads_delivery_unhealthy',1,?)", retirement, now-60000); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{iran, retirement} {
		s.initialTurn.Store(2)
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil || job.Hash != expected {
			t.Fatal("first-turn reservation displaced a due safety confirmation", err)
		}
	}
}
