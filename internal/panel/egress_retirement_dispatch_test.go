package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestOverdueRetirementGetsBoundedMaintenanceShareAcrossRestart(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "late-confirmation", sourceURI(213), sourceURI(214), sourceURI(215))
	var retired, renewal, review string
	for i := 0; i < 3; i++ {
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal(err)
		}
		r := syntheticEgress(*j)
		switch i {
		case 0:
			r = badDelivery(*j)
			retired = j.Hash
		case 1:
			renewal = j.Hash
		case 2:
			review = j.Hash
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	old := egress.Now() - 7200000
	if _, err := s.db.Exec(`UPDATE egress_jobs SET claimed_at=?1,tested=?1,next_run=?1 WHERE hash=?2;
 UPDATE egress_retirements SET first_at=?1,at=?1 WHERE hash=?2`, old, retired); err != nil {
		t.Fatal(err)
	}
	// Simulate an indefinitely replenished immediately-due review and a healthy
	// route with an urgent renewable proof. Both normally beat the old receipt.
	for n := 1; n <= 8; n++ {
		if _, err := s.db.Exec(`UPDATE egress_jobs SET next_run=0,valid_until=CASE WHEN hash=?1 THEN ?2 ELSE 0 END WHERE hash IN (?1,?3)`, renewal, egress.Now()+30000, review); err != nil {
			t.Fatal(err)
		}
		j, err := s.ClaimEgressLane(ctx, "followup")
		if err != nil || j == nil {
			t.Fatal("maintenance grant", n, err)
		}
		if j.Hash == retired {
			if n != 8 {
				t.Fatal("displaced preferred maintenance before reservation", n)
			}
			if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", retired)
			pendingCount(t, s.db, 3, "SELECT first_assessments FROM egress_metrics")
			return
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
			t.Fatal(err)
		}
		if n == 4 {
			path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
		}
	}
	t.Fatal("all eight grants bypassed the overdue sourced confirmation")
}

func TestOwedConfirmationPreservesBorrowedDeadlineAndFirstAssessment(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "competing-deadline", sourceURI(216), sourceURI(217))
	var oldHash, urgentHash string
	for i := 0; i < 2; i++ {
		j, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || j == nil {
			t.Fatal(err)
		}
		r := syntheticEgress(*j)
		if i == 0 {
			oldHash = j.Hash
			r = badDelivery(*j)
		} else {
			urgentHash = j.Hash
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	raw := sourceURI(218)
	newExportSource(t, s, "waiting-first", raw)
	old := egress.Now() - 3600000
	if _, err := s.db.Exec(`UPDATE egress_jobs SET claimed_at=?1,tested=?1,next_run=?1 WHERE hash=?2;
 UPDATE egress_retirements SET first_at=?1,at=?1 WHERE hash=?2`, old, oldHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET valid_until=?,next_run=0 WHERE hash=?", egress.Now()+30000, urgentHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO metadata VALUES('egress-dispatch-streak','-2'),('egress-other-maintenance','7') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	for n, want := range []string{urgentHash, egress.Hash([]byte(raw)), oldHash} {
		got, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || got == nil || got.Hash != want {
			t.Fatal("unexpected protected grant", n, err)
		}
	}
	pendingCount(t, s.db, 0, "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='egress-other-maintenance'")
}
